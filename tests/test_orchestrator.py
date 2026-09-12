from campus_ops.config import Settings
from campus_ops.orchestrator import Orchestrator


def test_snapshot_has_full_worker_fabric_before_start(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    orch = Orchestrator(Settings())
    snapshot = orch.snapshot()
    assert snapshot["session_id"] is None
    assert snapshot["version"] == "0.3.0"

    workers = set(snapshot["workers"])
    expected = {
        "state-sink",
        "history-storage",
        "protocol-engine",
        "asset-engine",
        "flow-engine",
        "topology-engine",
        "identity-engine",
        "endpoint-identity",
        "endpoint-deep-monitor",
        "application-intelligence",
        "dns-intelligence",
        "service-intelligence",
        "infrastructure-intelligence",
        "tcp-intelligence",
        "arp-guard",
        "behaviour-detection",
        "lateral-movement-watch",
        "beaconing-watch",
        "dos-early-warning",
        "threat-engine",
        "traffic-baseline",
        "performance-engine",
        "incident-correlation",
        "risk-graph",
        "attack-timeline",
        "suricata-feed",
        "malware-analysis",
        "telemetry",
        "local-host-telemetry",
        "windows-security-telemetry",
        "wifi-telemetry",
        "syslog-receiver",
        "flow-telemetry-receiver",
        "snmp-poller",
        "stale-cleanup",
        "capture-health",
        "pipeline-health",
        "job-scheduler",
        "voice-alert",
        "operations-watchdog",
        "tool-probe",
        "network-discovery",
        "capture",
        "forensic-pcap",
    }
    assert workers == expected
    assert snapshot["managed_agents"] == []
    assert snapshot["response_jobs"] == []
    assert snapshot["watchdog"]["state"] == "STOPPED"
