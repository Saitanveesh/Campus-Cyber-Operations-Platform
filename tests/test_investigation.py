import pytest

from campus_ops.investigation import build_investigation, deep_probe


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "tools": [{"key": "tshark", "available": True}, {"key": "nmap", "available": False}],
        "managed_agents": [
            {
                "endpoint_id": "lab-pc-22",
                "name": "PC22",
                "status": "ONLINE",
                "telemetry": {
                    "network_addresses": [{"interface": "Ethernet", "address": "10.20.80.22"}],
                    "isolation_state": "NORMAL",
                },
            }
        ],
        "live": {
            "assets": [
                {
                    "ip": "10.20.80.22",
                    "role": "LOCAL_SUBNET_ENDPOINT",
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
                    "alert_count": 2,
                    "confidence": 82,
                    "latest_evidence": {"source": "10.20.80.22", "unique_destinations": 17},
                }
            ],
            "packet_feed": [],
            "metrics": {"risk_graph": {"nodes": [{"id": "10.20.80.22", "risk": 76, "reasons": ["fan-out"]}]}},
        },
    }


def test_investigation_correlates_target_evidence_and_agent():
    result = build_investigation(_snapshot(), "10.20.80.22")
    assert result["target"] == "10.20.80.22"
    assert result["manageable"] is True
    assert result["managed_agent"]["endpoint_id"] == "lab-pc-22"
    assert result["summary"]["flow_count"] == 1
    assert result["summary"]["open_incident_count"] == 1
    assert result["risk"]["score"] >= 70
    assert result["risk"]["claim"] == "EVIDENCE_BASED_PRIORITY_NOT_MALICIOUS_VERDICT"


def test_investigation_rejects_unspecified_address():
    with pytest.raises(ValueError):
        build_investigation(_snapshot(), "0.0.0.0")


def test_deep_probe_refuses_public_target_before_tool_execution():
    with pytest.raises(PermissionError):
        deep_probe("8.8.8.8", include_services=True)
