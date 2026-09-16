from pathlib import Path

from campus_ops.investigation import build_investigation


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "network": {
            "interface": "eth0",
            "ipv4": ("10.20.80.10",),
            "ipv6": (),
            "prefixes": ("10.20.80.0/24",),
            "gateway": "10.20.80.1",
        },
        "live": {
            "assets": [],
            "flows": [],
            "topology_edges": [],
            "alerts": [],
            "incidents": [],
            "packet_feed": [],
        },
    }


def test_unseen_target_never_receives_green_or_numeric_security_verdict():
    result = build_investigation(_snapshot(), "10.20.80.99")
    assert result["observed"] is False
    assert result["risk"]["assessment"] == "NOT_OBSERVED"
    assert result["risk"]["score"] is None
    assert result["risk"]["claim"] == "NO_SECURITY_VERDICT_WITHOUT_EVIDENCE"


def test_operator_workspaces_have_no_admin_login_gate_and_topology_can_open_investigation():
    routes = Path("src/campus_ops/stable_operator.py").read_text()
    ui = Path("src/campus_ops/stable_operator_ui.py").read_text()
    topology = Path("src/campus_ops/topology_ui.py").read_text()

    assert "/api/v1/operator/targets" in routes
    assert "/api/v1/operator/investigate/{target}" in routes
    assert "/api/v1/operator/forensics/{target}" in routes
    assert "/api/v1/admin" not in routes
    assert "OperatorLoginRequest" not in routes
    assert "OperatorSessionStore" not in routes
    assert "window.openInvestigation" in ui
    assert "operatorGate" not in ui
    assert "topologyInvestigate" in topology
