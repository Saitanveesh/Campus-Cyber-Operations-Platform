from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Request

from campus_ops.admin import (
    AdminLoginRequest,
    AdminSessionStore,
    _admin_targets,
    _local_request,
    _require_admin,
)
from campus_ops.investigation import build_investigation


def install_stable_operator_routes(app: FastAPI) -> FastAPI:
    """Install only the authenticated passive operator routes used by stable mode.

    Stable MON is a passive single-source monitor. Remote access, active probing,
    endpoint snapshotting, isolation and restoration remain available to the broader
    development codebase but are deliberately not mounted into the stable runtime.
    """
    if getattr(app.state, "stable_operator_routes_installed", False):
        return app
    app.state.stable_operator_routes_installed = True

    store = AdminSessionStore()
    app.state.admin_sessions = store

    @app.post("/api/v1/admin/login")
    async def operator_login(request: Request, body: AdminLoginRequest) -> dict[str, object]:
        if not _local_request(request):
            raise HTTPException(status_code=403, detail="operator console is local-only")
        token = store.login(body.username, body.password)
        if token is None:
            raise HTTPException(status_code=401, detail="invalid operator credentials")
        return {
            "authenticated": True,
            "role": "OPERATOR",
            "token": token,
            "expires_seconds": store.ttl_seconds,
            "default_password": store.default_password,
            "capabilities": ["PASSIVE_INVESTIGATION", "PASSIVE_FORENSICS"],
        }

    @app.get("/api/v1/admin/status")
    async def operator_status(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        if not _local_request(request):
            return {"authenticated": False, "local": False}
        return {
            "authenticated": store.validate(x_campus_admin),
            "local": True,
            "default_password": store.default_password,
            "mode": "PASSIVE_ONLY",
        }

    @app.post("/api/v1/admin/logout")
    async def operator_logout(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        store.logout(x_campus_admin)
        return {"authenticated": False}

    @app.get("/api/v1/admin/targets")
    async def operator_targets(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        snapshot = app.state.orchestrator.snapshot()
        return {"targets": _admin_targets(snapshot), "mode": "PASSIVE_ONLY"}

    @app.get("/api/v1/admin/forensics/{target}")
    async def operator_forensics(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        try:
            report = build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if isinstance(report, dict):
            report = dict(report)
            report["operator_mode"] = "PASSIVE_ONLY"
        return report

    return app
