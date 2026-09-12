from campus_ops.main import build_app
from campus_ops.runtime_ui import _clean_console_copy


def test_runtime_app_installs_watchdog_assistant_investigation_and_admin_routes(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/watchdog" in paths
    assert "/api/v1/system/assistant/brief" in paths
    assert "/api/v1/system/assistant/context/{view}" in paths
    assert "/api/v1/system/assistant/stop" in paths
    assert "/api/v1/system/voice/stop" in paths
    assert "/api/v1/system/capabilities" in paths
    assert "/api/v1/system/diagnostics/{check}" in paths
    assert "/api/v1/investigate/{target}" in paths
    assert "/api/v1/investigate/{target}/deep-probe" in paths
    assert "/api/v1/investigate/{target}/snapshot" in paths
    assert "/api/v1/investigate/{target}/isolate" in paths
    assert "/api/v1/investigate/{target}/restore" in paths
    assert "/api/v1/admin/login" in paths
    assert "/api/v1/admin/status" in paths
    assert "/api/v1/admin/targets" in paths
    assert "/api/v1/admin/forensics/{target}" in paths
    assert "/api/v1/admin/forensics/{target}/probe" in paths
    assert "/api/v1/admin/targets/{target}/snapshot" in paths
    assert "/api/v1/admin/targets/{target}/isolate" in paths
    assert "/api/v1/admin/targets/{target}/restore" in paths
    assert "/api/v1/admin/targets/{target}/connect" in paths
    assert app.state.runtime_extensions_installed is True
    assert app.state.context_assistant_installed is True
    assert app.state.capability_routes_installed is True
    assert app.state.investigation_routes_installed is True
    assert app.state.admin_routes_installed is True


def test_console_copy_removes_old_taglines():
    html = (
        "Evidence-first network defence console | "
        "Black / white / grey operator interface · authorized cyber-range and "
        "campus-lab environments only · live contract: CURRENT_SESSION_ONLY"
    )
    cleaned = _clean_console_copy(html)
    assert "Evidence-first" not in cleaned
    assert "CURRENT_SESSION_ONLY" not in cleaned
