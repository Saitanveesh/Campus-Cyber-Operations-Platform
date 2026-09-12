from campus_ops.main import build_app
from campus_ops.runtime_ui import _clean_console_copy


def test_runtime_app_installs_watchdog_and_assistant_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/watchdog" in paths
    assert "/api/v1/system/assistant/brief" in paths
    assert app.state.runtime_extensions_installed is True


def test_console_copy_removes_old_taglines():
    html = (
        "Evidence-first network defence console | "
        "Black / white / grey operator interface · authorized cyber-range and "
        "campus-lab environments only · live contract: CURRENT_SESSION_ONLY"
    )
    cleaned = _clean_console_copy(html)
    assert "Evidence-first" not in cleaned
    assert "CURRENT_SESSION_ONLY" not in cleaned
