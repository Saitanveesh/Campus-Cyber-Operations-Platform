from campus_ops.main import build_app


def test_runtime_app_installs_watchdog_and_assistant_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/watchdog" in paths
    assert "/api/v1/system/assistant/brief" in paths
    assert app.state.runtime_extensions_installed is True
