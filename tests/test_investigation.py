import pytest

from campus_ops.investigation import build_investigation


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "live": {
            "assets": [
                {
                    "ip": "10.20.80.22",
                    "classification": "LOCAL_SUBNET_ENDPOINT",
                    "hostname": "PC22",
                    "mac": "00:11:22:33:44:55",
                }
            ],
            "flows": [
                {
                    "src": "10.20.80.22",
                    "dst": "10.20.80.31",
                    "protocol": "TCP",
                    "dst_port": "445",
                    "packets": 30,
                    "bytes": 3000,
                    "bps_ewma": 24000,
                }
            ],
            "topology_edges": [
                {"source": "10.20.80.22", "target": "10.20.80.31", "packets": 30}
            ],
            "alerts": [
                {
                    "severity": "HIGH",
                    "payload": {
                        "title": "Suspicious fan-out",
                        "evidence": {"source": "10.20.80.22"},
                    },
                }
            ],
            "incidents": [
                {
                    "id": "inc-1",
                    "title": "Suspicious fan-out",
                    "source": "10.20.80.22",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "latest_evidence": {"source": "10.20.80.22"},
                }
            ],
            "packet_feed": [],
        },
    }


def test_investigation_correlates_current_session_evidence_only():
    result = build_investigation(_snapshot(), "10.20.80.22")
    assert result["target"] == "10.20.80.22"
    assert result["observed"] is True
    assert result["asset"]["hostname"] == "PC22"
    assert result["summary"]["flow_count"] == 1
    assert result["summary"]["open_incident_count"] == 1
    assert result["risk"]["score"] >= 70
    assert result["operator_mode"] == "PASSIVE_ONLY"
    assert "managed_agent" not in result
    assert "remote_access" not in result
    assert "forensic_tools" not in result


def test_investigation_rejects_unspecified_address():
    with pytest.raises(ValueError):
        build_investigation(_snapshot(), "0.0.0.0")


def test_unobserved_public_peer_is_reported_without_active_lookup():
    result = build_investigation(_snapshot(), "8.8.8.8")
    assert result["scope"] == "PUBLIC"
    assert result["observed"] is False
    assert result["summary"]["flow_count"] == 0
