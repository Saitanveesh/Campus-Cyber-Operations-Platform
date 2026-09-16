from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.investigation import build_investigation


class OperatorLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@dataclass(slots=True)
class OperatorSession:
    token: str
    expires_at: float


class OperatorSessionStore:
    def __init__(self, ttl_seconds: int = 8 * 60 * 60) -> None:
        self.username = os.environ.get("CAMPUS_OPS_OPERATOR_USER", "admin")
        self.password = os.environ.get(
            "CAMPUS_OPS_OPERATOR_PASSWORD",
            os.environ.get("CAMPUS_OPS_ADMIN_PASSWORD", "123"),
        )
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, OperatorSession] = {}

    @property
    def default_password(self) -> bool:
        return self.username == "admin" and self.password == "123"

    def login(self, username: str, password: str) -> str | None:
        if not secrets.compare_digest(username, self.username):
            return None
        if not secrets.compare_digest(password, self.password):
            return None
        token = secrets.token_urlsafe(32)
        self._sessions[token] = OperatorSession(token, time.monotonic() + self.ttl_seconds)
        return token

    def validate(self, token: str | None) -> bool:
        if not token:
            return False
        session = self._sessions.get(token)
        if session is None:
            return False
        if session.expires_at <= time.monotonic():
            self._sessions.pop(token, None)
            return False
        return True

    def logout(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)


def _local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _require_operator(
    request: Request,
    token: str | None,
    store: OperatorSessionStore,
) -> None:
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="operator console is local-only")
    if not store.validate(token):
        raise HTTPException(status_code=401, detail="operator authentication required")


def _observed_targets(snapshot: dict[str, object]) -> list[dict[str, object]]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    flows = [item for item in live.get("flows", []) if isinstance(item, dict)]

    rows: dict[str, dict[str, object]] = {}
    for asset in assets:
        ip = str(asset.get("ip") or "").strip()
        if not ip:
            continue
        rows[ip] = {
            "ip": ip,
            "name": asset.get("hostname") or asset.get("dhcp_hostname") or "",
            "classification": asset.get("classification") or asset.get("role") or "LOCAL_ASSET",
            "last_seen": asset.get("last_seen"),
            "packets": int(asset.get("packets_as_source") or 0),
            "managed": False,
        }

    for flow in flows:
        count = int(flow.get("packets") or 0)
        last_seen = flow.get("last_seen")
        for key in ("src", "dst"):
            ip = str(flow.get(key) or "").strip()
            if not ip:
                continue
            row = rows.setdefault(
                ip,
                {
                    "ip": ip,
                    "name": "",
                    "classification": "OBSERVED_PEER",
                    "last_seen": last_seen,
                    "packets": 0,
                    "managed": False,
                },
            )
            row["packets"] = int(row.get("packets") or 0) + count
            if last_seen and str(last_seen) > str(row.get("last_seen") or ""):
                row["last_seen"] = last_seen

    return sorted(
        rows.values(),
        key=lambda item: (int(item.get("packets") or 0), str(item.get("last_seen") or "")),
        reverse=True,
    )[:500]


def install_stable_operator_routes(app: FastAPI) -> FastAPI:
    """Install local authenticated passive Investigation and Forensics routes."""
    if getattr(app.state, "stable_operator_routes_installed", False):
        return app
    app.state.stable_operator_routes_installed = True

    store = OperatorSessionStore()
    app.state.operator_sessions = store

    # The /admin prefix is retained only as a compatibility URI for the existing
    # stable operator UI. There is no Admin panel or active-control API behind it.
    @app.post("/api/v1/admin/login")
    async def operator_login(
        request: Request,
        body: OperatorLoginRequest,
    ) -> dict[str, object]:
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
        _require_operator(request, x_campus_admin, store)
        store.logout(x_campus_admin)
        return {"authenticated": False}

    @app.get("/api/v1/admin/targets")
    async def operator_targets(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_operator(request, x_campus_admin, store)
        return {
            "targets": _observed_targets(app.state.orchestrator.snapshot()),
            "mode": "PASSIVE_ONLY",
        }

    @app.get("/api/v1/admin/forensics/{target}")
    async def operator_forensics(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_operator(request, x_campus_admin, store)
        try:
            return build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app
