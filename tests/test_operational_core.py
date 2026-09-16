from __future__ import annotations

from campus_ops.operational_core import (
    build_investigation_report,
    build_system_diagnostics,
    isolation_capability,
)
from campus_ops.truth import assess_target_truth


def _snapshot() -> dict:
    return {
        "session_id": "session-1",
        "network": {
            "interface": "eth0",
            "ipv4": ["172.18.3.126"],
            "ipv6": [],
            "prefixes": ["172.18.0.0/20"],
            "gateway": "172.18.0.1",
        },
        "workers": {
            "capture": {
                "state": "HEALTHY",
                "detail": "capture active",
                "last_heartbeat": "2099-01-01T00:00:00+00:00",
                "last_error": None,
            }
        },
        "event_bus": {},
        "managed_agents": [],
        "enrolled_endpoints": [],
        "tools": [],
        "live": {
            "capture": {
                "state": "ACTIVE",
                "backend": "tshark",
                "detail": "capturing on eth0 via tshark",
            },
            "metrics": {},
            "assets": [
                {
                    "ip": "172.18.3.126",
                    "mac": "00:15:5d:cc:f5:7e",
                    "confidence": "HIGH",
                    "evidence": "CONFIRMED_LOCAL_SOURCE_FRAMES",
                },
                {
                    "ip": "172.18.0.1",
                    "mac": "00:15:5d:d7:14:45",
                    "confidence": "HIGH",
                    "evidence": "CONFIRMED_LOCAL_SOURCE_FRAMES",
                },
            ],
            "flows": [
                {
                    "src": "172.18.3.126",
                    "dst": "8.8.8.8",
                    "packets": 8,
                    "bytes": 800,
                    "protocol": "UDP",
                    "dst_port": "53",
                }
            ],
            "topology_edges": [
                {"source": "172.18.3.126", "target": "8.8.8.8", "packets": 8}
            ],
            "packet_feed": [],
            "alerts": [],
            "incidents": [],
        },
    }


def _add_confirmed_endpoint(snapshot: dict, *, status: str = "ONLINE", platform: str = "windows") -> None:
    snapshot["live"]["assets"].append(
        {
            "ip": "172.18.3.55",
            "mac": "00:11:22:33:44:55",
            "confidence": "HIGH",
            "evidence": "CONFIRMED_LOCAL_SOURCE_FRAMES",
        }
    )
    snapshot["live"]["flows"].append(
        {"src": "172.18.3.55", "dst": "172.18.0.1", "packets": 4, "bytes": 400}
    )
    snapshot["managed_agents"] = [
        {
            "endpoint_id": "lab-55",
            "status": status,
            "platform": platform,
            "telemetry": {"network_addresses": [{"address": "172.18.3.55"}]},
        }
    ]


def test_fake_ip_is_not_observed_and_never_gets_green_assessment():
    snapshot = _snapshot()
    truth = assess_target_truth(snapshot, "172.18.9.99")
    assert truth["status"] == "NOT_OBSERVED"
    assert truth["observed"] is False

    report = build_investigation_report(snapshot, "172.18.9.99")
    assert report["assessment"] == "NOT_OBSERVED"
    assert report["risk"]["score"] is None
    assert report["risk"]["claim"] == "NO_SECURITY_VERDICT_WITHOUT_EVIDENCE"


def test_confirmed_asset_is_not_automatically_manageable():
    truth = assess_target_truth(_snapshot(), "172.18.0.1")
    assert truth["status"] == "CONFIRMED_LOCAL_ASSET"
    assert truth["confirmed_local_asset"] is True
    assert truth["manageable"] is False
    assert truth["is_gateway"] is True


def test_online_windows_agent_backed_confirmed_endpoint_becomes_manageable():
    snapshot = _snapshot()
    _add_confirmed_endpoint(snapshot)

    truth = assess_target_truth(snapshot, "172.18.3.55")
    assert truth["status"] == "MANAGEABLE_ASSET"
    assert truth["manageable"] is True

    capability = isolation_capability(snapshot, "172.18.3.55")
    assert capability["available"] is True
    assert capability["control_method"] == "WINDOWS_FIREWALL_ENDPOINT_AGENT"


def test_isolation_fails_closed_for_offline_agent():
    snapshot = _snapshot()
    _add_confirmed_endpoint(snapshot, status="OFFLINE")
    capability = isolation_capability(snapshot, "172.18.3.55")
    assert capability["available"] is False
    assert any("offline" in reason for reason in capability["reasons"])


def test_isolation_fails_closed_for_unsupported_linux_agent_backend():
    snapshot = _snapshot()
    _add_confirmed_endpoint(snapshot, platform="linux")
    capability = isolation_capability(snapshot, "172.18.3.55")
    assert capability["available"] is False
    assert any("Windows agents only" in reason for reason in capability["reasons"])


def test_isolation_refuses_monitor_and_gateway():
    host = isolation_capability(_snapshot(), "172.18.3.126")
    gateway = isolation_capability(_snapshot(), "172.18.0.1")
    assert host["available"] is False
    assert any("own monitoring address" in reason for reason in host["reasons"])
    assert gateway["available"] is False
    assert any("default gateway" in reason for reason in gateway["reasons"])


def test_diagnostics_explain_capture_permission_failure():
    snapshot = _snapshot()
    snapshot["live"]["capture"] = {
        "state": "ERROR",
        "detail": "tshark: dumpcap: Operation not permitted",
    }
    result = build_system_diagnostics(snapshot)
    problem = next(item for item in result["problems"] if item["id"] == "capture-failure")
    assert result["state"] == "ATTENTION"
    assert "capabilities" in problem["probable_cause"].lower()
    assert any("setcap" in command for command in problem["fix"])
