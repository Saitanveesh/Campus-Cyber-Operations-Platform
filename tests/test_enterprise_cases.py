from campus_ops.enterprise_cases import CaseCreateRequest, CaseStore
from campus_ops.main import build_app


def test_stable_runtime_does_not_mount_enterprise_case_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/admin/cases" not in paths
    assert "/api/v1/system/syslog" not in paths
    assert "/api/v1/investigate/{target}" in paths
    assert "/api/v1/isolation/{target}" in paths


def test_case_audit_chain_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    store = CaseStore()
    created = store.create(
        CaseCreateRequest(title="Investigate endpoint", target="10.10.10.10", severity="HIGH"),
        "session-1",
    )
    store.attach_evidence(created["case_id"], {"sha256": "a" * 64, "type": "snapshot"})
    result = store.verify_audit_chain()
    assert result["valid"] is True
    assert result["entries"] == 2
