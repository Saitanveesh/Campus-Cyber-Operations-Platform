from campus_ops.enterprise_cases import CaseCreateRequest, CaseStore
from campus_ops.main import build_app


def test_enterprise_case_routes_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/syslog" in paths
    assert "/api/v1/admin/cases" in paths
    assert "/api/v1/admin/cases/{case_id}" in paths
    assert "/api/v1/admin/cases/{case_id}/evidence" in paths
    assert "/api/v1/admin/case-audit/verify" in paths
    assert app.state.enterprise_cases_installed is True


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
