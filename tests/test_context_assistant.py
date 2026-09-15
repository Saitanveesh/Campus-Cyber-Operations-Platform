from campus_ops.context_assistant import page_briefing


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "network": {"interface": "Wi-Fi"},
        "workers": {},
        "voice": {"engine": "System.Speech"},
        "managed_agents": [],
        "enrolled_endpoints": [],
        "response_jobs": [],
        "tools": [],
        "live": {
            "capture": {"state": "ACTIVE", "packets": 1200},
            "assets": [{"ip": "10.20.87.22", "classification": "LOCAL_SUBNET_ENDPOINT"}],
            "flows": [
                {
                    "src": "10.20.87.22",
                    "dst": "10.20.87.50",
                    "protocol": "TCP",
                    "packets": 90,
                    "bps_ewma": 24000,
                    "pps_ewma": 12,
                }
            ],
            "topology_edges": [
                {
                    "source": "10.20.87.22",
                    "target": "10.20.87.50",
                    "packets": 90,
                    "bps_ewma": 24000,
                    "last_protocol": "TCP",
                }
            ],
            "alerts": [{"severity": "MEDIUM"}],
            "incidents": [
                {
                    "id": "incident-1",
                    "title": "Suspicious fan-out",
                    "source": "10.20.87.22",
                    "severity": "MEDIUM",
                    "confidence": 82,
                    "alert_count": 4,
                    "alert_types": ["Suspicious fan-out"],
                    "status": "OPEN",
                    "last_seen": "2026-09-12T01:00:00+00:00",
                    "latest_evidence": {"unique_destinations": 17},
                }
            ],
            "events": [],
            "metrics": {"rx_bps": 1000, "tx_bps": 500},
        },
    }


def test_overview_brief_names_current_incident():
    text = page_briefing(_snapshot(), "overview")
    assert "Suspicious fan-out" in text
    assert "10.20.87.22" in text
    assert "17 destinations" in text


def test_security_brief_identifies_incident_and_confidence():
    text = page_briefing(_snapshot(), "security")
    assert "Suspicious fan-out" in text
    assert "confidence 82 percent" in text
    assert "1 correlated signal type" in text


def test_topology_brief_identifies_busiest_relationship():
    text = page_briefing(_snapshot(), "topology")
    assert "10.20.87.22 to 10.20.87.50" in text
    assert "24.0 kilobits per second" in text
