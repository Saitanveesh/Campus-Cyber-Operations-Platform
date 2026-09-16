from campus_ops.main import build_app
from campus_ops.runtime_ui import _clean_console_copy


def test_stable_runtime_mounts_operational_backends_without_legacy_runtime_stack(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/watchdog" in paths
    assert "/api/v1/system/diagnostics" in paths
    assert "/api/v1/anomalies" in paths
    assert "/api/v1/investigate/{target}" in paths
    assert "/api/v1/pathspace/{target}" in paths
    assert "/api/v1/isolation/{target}" in paths
    assert "/api/v1/isolation/{target}/restore" in paths
    assert app.state.operational_core_installed is True
    assert app.state.path_analysis_installed is True
    assert app.state.watchdog_api_installed is True
    assert getattr(app.state, "runtime_extensions_installed", False) is False


def test_stable_runtime_mounts_only_passive_protected_operator_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}

    for expected in (
        "/api/v1/admin/login",
        "/api/v1/admin/status",
        "/api/v1/admin/logout",
        "/api/v1/admin/targets",
        "/api/v1/admin/forensics/{target}",
    ):
        assert expected in paths

    for forbidden in (
        "/api/v1/admin/remote/enroll",
        "/api/v1/admin/forensics/{target}/probe",
        "/api/v1/admin/targets/{target}/snapshot",
        "/api/v1/admin/targets/{target}/isolate",
        "/api/v1/admin/targets/{target}/restore",
        "/api/v1/admin/targets/{target}/connect",
    ):
        assert forbidden not in paths

    assert app.state.stable_operator_routes_installed is True
    assert getattr(app.state, "admin_routes_installed", False) is False


def test_console_copy_removes_old_taglines():
    html = (
        "Evidence-first network defence console | "
        "Black / white / grey operator interface · authorized cyber-range and "
        "campus-lab environments only · live contract: CURRENT_SESSION_ONLY"
    )
    cleaned = _clean_console_copy(html)
    assert "Evidence-first" not in cleaned
    assert "CURRENT_SESSION_ONLY" not in cleaned
