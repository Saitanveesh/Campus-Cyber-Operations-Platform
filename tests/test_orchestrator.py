from campus_ops.config import Settings
from campus_ops.orchestrator import Orchestrator


def test_snapshot_has_live_contract_before_start():
    orch = Orchestrator(Settings())
    snapshot = orch.snapshot()
    assert snapshot["live_contract"] == "CURRENT_SESSION_ONLY"
    assert snapshot["session_id"] is None

    workers = set(snapshot["workers"])
    expected = {
        "state-sink",
        "history-storage",
        "network-intelligence",
        "application-intelligence",
        "tcp-intelligence",
        "arp-guard",
        "behaviour-detection",
        "dos-early-warning",
        "incident-correlation",
        "suricata-feed",
        "malware-analysis",
        "telemetry",
        "local-host-telemetry",
        "voice-alert",
        "tool-probe",
        "network-discovery",
        "capture",
        "forensic-pcap",
    }
    assert workers == expected
