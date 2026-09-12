from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


class IocCreateRequest(BaseModel):
    kind: str = Field(min_length=2, max_length=16)
    value: str = Field(min_length=1, max_length=256)
    severity: str = Field(default="HIGH", min_length=3, max_length=16)
    label: str = Field(default="", max_length=160)
    notes: str = Field(default="", max_length=1000)


def _local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _require_admin(app: FastAPI, request: Request, token: str | None) -> None:
    store = getattr(app.state, "admin_sessions", None)
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="administrator console is local-only")
    if store is None or not store.validate(token):
        raise HTTPException(status_code=401, detail="administrator authentication required")


def install_ioc_routes(app: FastAPI) -> FastAPI:
    if getattr(app.state, "ioc_routes_installed", False):
        return app
    app.state.ioc_routes_installed = True

    @app.get("/api/v1/admin/iocs")
    async def list_iocs(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        return {"indicators": app.state.orchestrator.iocs.list()}

    @app.post("/api/v1/admin/iocs")
    async def add_ioc(
        body: IocCreateRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        try:
            item = app.state.orchestrator.iocs.add(**body.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"indicator": item}

    @app.delete("/api/v1/admin/iocs/{indicator_id}")
    async def delete_ioc(
        indicator_id: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        if not app.state.orchestrator.iocs.remove(indicator_id):
            raise HTTPException(status_code=404, detail="indicator not found")
        return {"removed": indicator_id}

    @app.get("/api/v1/admin/iocs/matches/live")
    async def live_ioc_matches(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        live = app.state.orchestrator.state.snapshot()
        matches = [
            item
            for item in live.get("alerts", [])
            if isinstance(item, dict) and item.get("evidence_class") == "OPERATOR_IOC_MATCH"
        ]
        return {"session_id": live.get("session_id"), "matches": matches[:200]}

    return app
