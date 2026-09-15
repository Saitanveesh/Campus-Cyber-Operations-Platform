from campus_ops.enterprise_detection import _entropy, segmentation_policy_report, sigma_status
from campus_ops.main import build_app


def test_enterprise_detection_routes_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/segmentation-policy" in paths
    assert "/api/v1/system/dns-tls-anomalies" in paths
    assert "/api/v1/system/sigma" in paths
    assert "/api/v1/admin/command-center/{target}" in paths
    assert app.state.enterprise_detection_installed is True


def test_segmentation_policy_fails_closed_without_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("CAMPUS_OPS_SEGMENT_POLICY", raising=False)
    monkeypatch.delenv("CAMPUS_OPS_SEGMENT_POLICY_FILE", raising=False)
    report = segmentation_policy_report(build_app())
    assert report["state"] == "NOT_CONFIGURED"
    assert report["violations"] == []


def test_entropy_distinguishes_repetitive_from_varied_text():
    assert _entropy("aaaaaaaaaaaaaaaa") < _entropy("a1b2c3d4e5f6g7h8")


def test_sigma_status_is_truthful_when_unconfigured(monkeypatch):
    monkeypatch.delenv("CAMPUS_OPS_SIGMA_RULE_DIR", raising=False)
    status = sigma_status()
    assert status["rule_dir"] is None
    assert status["state"] == "NOT_CONFIGURED"
