from campus_ops.enterprise_depth_v3 import RollingBaseline


def test_rolling_baseline_initial_state():
    baseline = RollingBaseline()
    assert baseline.session_id is None
    assert baseline.observations == 0
    assert baseline.peers == set()
    assert baseline.services == set()
    assert baseline.assets == set()
