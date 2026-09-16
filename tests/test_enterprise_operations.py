from campus_ops.enterprise_operations import SoarExecuteRequest, soar_plan
from campus_ops.main import build_app


def test_stable_runtime_excludes_enterprise_operations_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/identity-context" not in paths
    assert "/api/v1/admin/soar/{target}" not in paths
    assert "/api/v1/isolation/{target}" in paths
    assert "/api/v1/system/diagnostics" in paths
    assert getattr(app.state, "enterprise_operations_installed", False) is False


def test_soar_plan_is_guarded_without_managed_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    plan = soar_plan(app, "10.10.10.10", "CONTAIN")
    assert plan["playbook"] == "CONTAIN"
    assert plan["executable"] is False
    assert plan["steps"][0]["action"] == "COLLECT_SNAPSHOT"
    assert any(step["action"] == "ISOLATE_HOST" for step in plan["steps"])
    restore = next(step for step in plan["steps"] if step["action"] == "RESTORE_NETWORK")
    assert restore["automatic"] is False


def test_soar_execute_request_defaults_to_unconfirmed():
    request = SoarExecuteRequest(reason="manual triage")
    assert request.playbook == "TRIAGE"
    assert request.confirm is False
