from campus_ops.red_panel import _purple_team_model


def test_purple_model_maps_remote_services():
    model = _purple_team_model(
        [
            {"port": 3389, "service_hint": "RDP"},
            {"port": 445, "service_hint": "SMB"},
            {"port": 22, "service_hint": "SSH"},
        ],
        peer_count=18,
        signals=2,
        managed=True,
    )
    techniques = {row["technique"] for row in model["techniques"]}
    assert "T1021.001" in techniques
    assert "T1021.002" in techniques
    assert "T1021.004" in techniques
    assert "T1018" in techniques
    assert model["coverage_score"] is None
    assert model["detection_gap_score"] is None


def test_purple_model_does_not_invent_techniques_without_evidence():
    model = _purple_team_model([], peer_count=1, signals=0, managed=False)
    assert model["techniques"][0]["technique"] == "BASELINE"
    assert model["coverage_score"] is None
    assert model["detection_gap_score"] is None
