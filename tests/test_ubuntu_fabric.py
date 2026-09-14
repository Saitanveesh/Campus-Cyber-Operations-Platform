import asyncio
import json
import time
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from campus_ops.agent_plane import AgentRegistry
from campus_ops.event_bus import EventBus
from campus_ops.fabric.records import normalize, sensor_event, timestamp
from campus_ops.fabric.risk import RiskPolicy, decisions, managed_subjects
from campus_ops.fabric.runtime import OperationsFabric, ValidationRequest
from campus_ops.fabric.store import EvidenceStore
from campus_ops.fabric.tail import JsonTail
from campus_ops.linux_host import default_routes
from campus_ops.main import build_app
from campus_ops.models import EventKind, WorkerState
from campus_ops.platform_paths import data_root
from campus_ops.response import ResponseEngine
from campus_ops.workers.network_discovery import classify_interface
from campus_ops.workers.suricata_feed import SuricataFeedWorker


def falco(now=None, host="endpoint", rule="Unexpected shell"):
    return {"hostname": host, "rule": rule, "priority": "Error",
            "time": time.time() if now is None else now,
            "output_fields": {"proc.name": "bash"}}


def evidence(now=None):
    return normalize(sensor_event("falco", "test", falco(now), "session"))


def test_tail_skips_history_and_waits_for_complete_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'{"history":true}\n')
    tail = JsonTail(path)
    assert tail.read("a") == []
    with path.open("ab") as handle:
        handle.write(b'{"live":')
    assert tail.read("a") == []
    with path.open("ab") as handle:
        handle.write(b'true}\n')
    assert tail.read("a") == [{"live": True}]
    with path.open("ab") as handle:
        handle.write(b'{"old_session":true}\n')
    assert tail.read("b") == []
    assert tail.read("b") == []


def test_tail_rotation_truncation_and_oversized_recovery(tmp_path):
    path = tmp_path / "events"
    path.write_bytes(b'{}\n')
    tail = JsonTail(path, max_line=32)
    tail.read("a")
    path.rename(tmp_path / "old")
    path.write_bytes(b'{"rotated":true}\n')
    assert tail.read("a") == [{"rotated": True}]
    path.write_bytes(b'{}\n')
    assert tail.read("a") == [{}]
    with path.open("ab") as handle:
        handle.write(b"x" * 90 + b'\nBAD\n{"ok":true}\n')
    assert tail.read("a") == [{"ok": True}]
    assert tail.errors == 2


def test_tail_discards_partial_history(tmp_path):
    path = tmp_path / "events"
    path.write_bytes(b'{"before":')
    tail = JsonTail(path)
    tail.read("a")
    with path.open("ab") as handle:
        handle.write(b'true}\n{"after":true}\n')
    assert tail.read("a") == [{"after": True}]


@pytest.mark.parametrize("tool,row", [
    ("tetragon", {"node_name": "node", "time": 123, "process_exec": {"process": {"binary": "bash"}}}),
    ("hubble", {"flow": {"time": 123, "IP": {"source": "10.0.0.1"}, "verdict": "FORWARDED"}}),
])
def test_ordinary_observations_are_not_alerts(tool, row):
    event = sensor_event(tool, "local", row, "session")
    assert event.kind == EventKind.OBSERVATION
    assert str(event.severity) == "INFO"
    assert decisions([asdict(normalize(event))], [], healthy=True, now=123) == []


@pytest.mark.parametrize("value", [None, "not-time", "2026-01-01T00:00:00", True, float("nan")])
def test_unknown_or_naive_timestamp_rejected(value):
    assert timestamp(value) is None


@pytest.mark.parametrize("missing", ["hostname", "time", "rule"])
def test_falco_requires_subject_time_and_rule(missing):
    row = falco()
    del row[missing]
    assert sensor_event("falco", "test", row, "session") is None


def test_wazuh_forwarding_does_not_create_corroboration():
    now = time.time()
    row = {"agent": {"ip": "10.0.0.2"}, "rule": {"id": "42", "level": 12,
           "groups": ["suricata"]}, "timestamp": now}
    forwarded = normalize(sensor_event("wazuh", "local", row, "session"))
    native = normalize(SuricataFeedWorker._event_for(
        {"event_type": "alert", "timestamp": now, "src_ip": "10.0.0.2",
         "alert": {"signature_id": 9, "severity": 1}}, "session"))
    decision = decisions([asdict(forwarded), asdict(native)], [], healthy=True)[0]
    assert forwarded.origin == "suricata"
    assert decision["independent_sources"] == 1
    assert decision["risk_score"] == 80


def test_opencanary_utc_export():
    event = sensor_event("opencanary", "local", {
        "src_host": "10.0.0.9", "logtype": 4001, "utc_time": "2026-09-14 12:00:00.123456"
    }, "session")
    assert event.kind == EventKind.ALERT
    assert event.payload["observed_at"] == timestamp("2026-09-14T12:00:00.123456+00:00")


def test_sqlite_dedup_survives_restart_and_filters_time_session(tmp_path):
    path = tmp_path / "evidence.db"
    now = time.time()
    record = evidence(now)
    store = EvidenceStore(path)
    assert store.add(record, now)
    assert not store.add(record, now)
    assert not store.add(replace(record, record_id="stale", observed_at=now - 301), now)
    assert not store.add(replace(record, record_id="future", observed_at=now + 31), now)
    assert store.recent("other", now) == []
    assert len(store.graph("session")["edges"]) == 2
    store.close()
    reopened = EvidenceStore(path)
    assert not reopened.add(record, now)
    assert len(reopened.recent("session", now)) == 1
    reopened.close()


def test_repeat_alerts_do_not_inflate_risk_or_authorize_containment():
    row = asdict(evidence())
    agent = {"endpoint_id": "id", "host": "endpoint", "status": "ONLINE"}
    once = decisions([row], [agent], healthy=True)[0]
    repeated = decisions([row] * 100, [agent], healthy=True)[0]
    assert once["risk_score"] == repeated["risk_score"] == 65
    assert repeated["independent_sources"] == 1
    assert repeated["automatic_containment_enabled"] is False
    assert "NO_VALIDATED_LINUX_CONTAINMENT_BACKEND" in repeated["containment_blockers"]
    assert repeated["automation_gate"] == "INVESTIGATE_ELIGIBLE"
    assert decisions([row], [agent], healthy=False)[0]["automation_gate"] == "OBSERVE"
    row["source_time_known"] = False
    assert decisions([row], [agent], healthy=True)[0]["automation_gate"] == "OBSERVE"


def test_ambiguous_and_offline_agents_are_not_control_targets():
    agents = [
        {"endpoint_id": "a", "host": "shared", "status": "ONLINE",
         "telemetry": {"network_addresses": ["10.0.0.1"]}},
        {"endpoint_id": "b", "host": "shared", "status": "OFFLINE"},
    ]
    aliases = managed_subjects(agents)
    assert "shared" not in aliases
    assert "b" not in aliases
    assert aliases["10.0.0.1"] == "a"


def test_linux_ipv4_and_ipv6_routes(monkeypatch):
    def run(command, **kwargs):
        rows = ([{"dev": "enp1s0", "gateway": "10.0.0.1", "metric": 100},
                 {"dev": "enp1s0", "gateway": "10.0.0.2", "metric": 50}]
                if "-4" in command else
                [{"dev": "enp1s0", "gateway": "fe80::1", "metric": 1},
                 {"dev": "wlp2s0", "gateway": "fe80::2", "metric": 10}])
        return SimpleNamespace(returncode=0, stdout=json.dumps(rows))
    monkeypatch.setattr("campus_ops.linux_host.subprocess.run", run)
    routes = default_routes()
    assert routes["enp1s0"] == (True, 50, "10.0.0.2")
    assert routes["wlp2s0"] == (True, 10, "fe80::2")
    assert classify_interface("enp1s0") == "ethernet"
    assert classify_interface("wlp2s0") == "wireless"
    assert classify_interface("cilium_host") == "virtual"


def test_xdg_and_explicit_state_paths(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("CAMPUS_OPS_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert data_root() == tmp_path / "campus-ops"
    monkeypatch.setenv("CAMPUS_OPS_DATA_DIR", str(tmp_path / "explicit"))
    assert data_root() == tmp_path / "explicit"


async def test_export_bus_evidence_and_real_snapshot_queue(tmp_path, monkeypatch):
    path = tmp_path / "falco.jsonl"
    path.write_text("")
    monkeypatch.setenv("CAMPUS_OPS_FALCO_LOG", str(path))
    monkeypatch.setenv("CAMPUS_OPS_AUTONOMY_MODE", "investigate")
    bus = EventBus()
    agents = AgentRegistry(tmp_path / "agents.json")
    enrolled = agents.enroll("id", "endpoint", "linux", host="endpoint")
    agents.heartbeat("id", enrolled["enrollment_token"], host="endpoint", version="test", telemetry={})
    orch = SimpleNamespace(bus=bus, session_id="session", agents=agents)
    orch.response = ResponseEngine(bus, agents, lambda: orch.session_id)
    fabric = OperationsFabric(orch, tmp_path / "fabric.db")
    fabric.subscription = await bus.subscribe(fabric.name)
    fabric.health.state = WorkerState.HEALTHY
    await fabric.poll_exports()
    with path.open("a") as handle:
        handle.write(json.dumps(falco()) + "\n")
    await fabric.poll_exports()
    fabric.drain()
    assert len(fabric.store.recent("session")) == 1
    await fabric.investigate()
    await fabric.investigate()
    assert len(agents.jobs()) == 1
    assert agents.jobs()[0]["action"] == "COLLECT_SNAPSHOT"
    await fabric.stop()
    # New runtime and same durable evidence must not enqueue the same bucket again.
    restarted = OperationsFabric(orch, tmp_path / "fabric.db")
    restarted.health.state = WorkerState.HEALTHY
    await restarted.investigate()
    assert len(agents.jobs()) == 1
    await restarted.stop()


async def test_runtime_start_stop_and_failed_pipeline_blocks_jobs(tmp_path, monkeypatch):
    monkeypatch.setenv("CAMPUS_OPS_AUTONOMY_MODE", "investigate")
    orch = SimpleNamespace(bus=EventBus(queue_size=1), session_id="session",
                           agents=SimpleNamespace(list=list))
    fabric = OperationsFabric(orch, tmp_path / "fabric.db")
    await fabric.start()
    await asyncio.sleep(0)
    await orch.bus.publish(sensor_event("falco", "x", falco(), "session"))
    await orch.bus.publish(sensor_event("falco", "x", falco(), "session"))
    assert not fabric.pipeline_healthy()
    await fabric.stop()
    assert fabric.closed
    assert fabric.name not in orch.bus.stats()
    await fabric.start()
    await asyncio.sleep(0)
    await fabric.stop()


def test_validation_matches_only_exact_current_session_alert(tmp_path):
    orch = SimpleNamespace(bus=EventBus(), session_id="session",
                           agents=SimpleNamespace(list=list))
    fabric = OperationsFabric(orch, tmp_path / "fabric.db")
    run = fabric.start_validation(ValidationRequest(subject="endpoint", origin="falco",
                                                    rule="Unexpected shell"))
    record = evidence()
    fabric.store.add(replace(record, record_id="different", rule="Different rule"))
    assert fabric.validation(run["run_id"])["state"] == "WAITING"
    fabric.store.add(record)
    result = fabric.validation(run["run_id"])
    assert result["state"] == "MATCHED_ALERT"
    assert result["coverage_measured"] is False
    orch.session_id = "new-session"
    assert fabric.validation(run["run_id"])["state"] == "SESSION_ENDED"
    fabric.store.close()


@pytest.mark.parametrize("args", [{"investigate_threshold": 101}, {"minimum_origins": 0},
                                 {"window_seconds": 301}, {"minimum_confidence": True}])
def test_invalid_policy_fails_closed(args):
    with pytest.raises(ValueError):
        RiskPolicy(**args)


def test_one_zeek_and_syslog_owner_and_admin_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    orch = app.state.orchestrator
    assert sum(worker.name == "zeek-feed" for worker in orch.workers) == 1
    assert app.state.passive_syslog is orch.syslog
    assert app.state.zeek_adapter._task is None
    client = TestClient(app)
    assert client.get("/api/v1/system/evidence-graph").status_code == 401
    assert client.post("/api/v1/admin/validation-runs", json={
        "subject": "endpoint", "origin": "falco", "rule": "test"
    }).status_code == 401
    assert client.get("/api/v1/system/operations-fabric").json()["automatic_containment_enabled"] is False
    app.state.operations_fabric.store.close()
