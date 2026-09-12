from __future__ import annotations

import asyncio
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.investigation import build_investigation, deep_probe
from campus_ops.policy import Role


class AdminLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AdminProbeRequest(BaseModel):
    authorized: bool = False
    include_services: bool = True


class AdminConnectRequest(BaseModel):
    protocol: str


@dataclass(slots=True)
class AdminSession:
    token: str
    expires_at: float


class AdminSessionStore:
    """Local-console administrator sessions.

    The requested bootstrap credential is admin / 123. The password can be
    overridden with CAMPUS_OPS_ADMIN_PASSWORD and should be changed before any
    non-lab deployment.
    """

    def __init__(self, ttl_seconds: int = 8 * 60 * 60) -> None:
        self.username = os.environ.get("CAMPUS_OPS_ADMIN_USER", "admin")
        self.password = os.environ.get("CAMPUS_OPS_ADMIN_PASSWORD", "123")
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, AdminSession] = {}

    @property
    def default_password(self) -> bool:
        return self.username == "admin" and self.password == "123"

    def login(self, username: str, password: str) -> str | None:
        if not secrets.compare_digest(username, self.username):
            return None
        if not secrets.compare_digest(password, self.password):
            return None
        token = secrets.token_urlsafe(32)
        self._sessions[token] = AdminSession(token, time.monotonic() + self.ttl_seconds)
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


def _require_admin(request: Request, token: str | None, store: AdminSessionStore) -> None:
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="administrator console is local-only")
    if not store.validate(token):
        raise HTTPException(status_code=401, detail="administrator authentication required")


def _management_ip(snapshot: dict[str, Any]) -> str | None:
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    raw = network.get("ipv4")
    values = raw if isinstance(raw, list) else [raw] if raw else []
    for value in values:
        candidate = str(value or "").strip()
        if candidate and candidate != "127.0.0.1":
            return candidate
    return None


def _target_agent(snapshot: dict[str, Any], target: str) -> dict[str, Any] | None:
    investigation = build_investigation(snapshot, target)
    agent = investigation.get("managed_agent")
    return agent if isinstance(agent, dict) else None


def _remote_endpoint(snapshot: dict[str, Any], target: str) -> dict[str, Any] | None:
    for item in snapshot.get("enrolled_endpoints", []):
        if isinstance(item, dict) and str(item.get("host") or "").strip() == target:
            return item
    return None


def _admin_targets(snapshot: dict[str, Any]) -> list[dict[str, object]]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    agents = [item for item in snapshot.get("managed_agents", []) if isinstance(item, dict)]
    endpoints = [item for item in snapshot.get("enrolled_endpoints", []) if isinstance(item, dict)]

    agent_by_ip: dict[str, dict[str, Any]] = {}
    for agent in agents:
        telemetry = agent.get("telemetry") if isinstance(agent.get("telemetry"), dict) else {}
        for address in telemetry.get("network_addresses", []) if isinstance(telemetry.get("network_addresses"), list) else []:
            if isinstance(address, dict) and address.get("address"):
                agent_by_ip[str(address["address"])] = agent
    endpoint_by_host = {str(item.get("host") or ""): item for item in endpoints}

    rows: list[dict[str, object]] = []
    for asset in assets:
        ip = str(asset.get("ip") or "")
        if not ip:
            continue
        agent = agent_by_ip.get(ip)
        endpoint = endpoint_by_host.get(ip)
        rows.append(
            {
                "ip": ip,
                "name": asset.get("hostname") or asset.get("dhcp_hostname") or (agent or {}).get("name") or "",
                "classification": asset.get("classification") or asset.get("role") or "OBSERVED_PEER",
                "last_seen": asset.get("last_seen"),
                "packets": asset.get("packets_as_source") or 0,
                "managed": bool(agent),
                "agent_id": (agent or {}).get("endpoint_id"),
                "agent_status": (agent or {}).get("status"),
                "isolation_state": ((agent or {}).get("telemetry") or {}).get("isolation_state") if agent else None,
                "remote_enrolled": bool(endpoint),
                "allow_ssh": bool((endpoint or {}).get("allow_ssh")),
                "allow_rdp": bool((endpoint or {}).get("allow_rdp")),
                "remote_endpoint_id": (endpoint or {}).get("endpoint_id"),
            }
        )
    rows.sort(key=lambda item: (not bool(item["managed"]), not bool(item["remote_enrolled"]), str(item["ip"])))
    return rows


def install_admin_routes(app: FastAPI) -> FastAPI:
    if getattr(app.state, "admin_routes_installed", False):
        return app
    app.state.admin_routes_installed = True
    store = AdminSessionStore()
    app.state.admin_sessions = store

    @app.post("/api/v1/admin/login")
    async def admin_login(request: Request, body: AdminLoginRequest) -> dict[str, object]:
        if not _local_request(request):
            raise HTTPException(status_code=403, detail="administrator console is local-only")
        token = store.login(body.username, body.password)
        if token is None:
            raise HTTPException(status_code=401, detail="invalid administrator credentials")
        return {
            "authenticated": True,
            "role": "ADMINISTRATOR",
            "token": token,
            "expires_seconds": store.ttl_seconds,
            "default_password": store.default_password,
        }

    @app.get("/api/v1/admin/status")
    async def admin_status(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        if not _local_request(request):
            return {"authenticated": False, "local": False}
        return {
            "authenticated": store.validate(x_campus_admin),
            "local": True,
            "default_password": store.default_password,
        }

    @app.post("/api/v1/admin/logout")
    async def admin_logout(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        store.logout(x_campus_admin)
        return {"authenticated": False}

    @app.get("/api/v1/admin/targets")
    async def admin_targets(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        snapshot = app.state.orchestrator.snapshot()
        return {"targets": _admin_targets(snapshot)}

    @app.get("/api/v1/admin/forensics/{target}")
    async def admin_forensics(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        try:
            return build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/admin/forensics/{target}/probe")
    async def admin_forensics_probe(
        target: str,
        body: AdminProbeRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        if not body.authorized:
            raise HTTPException(status_code=403, detail="explicit private-lab authorization is required")
        try:
            return await asyncio.to_thread(deep_probe, target, body.include_services)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/admin/targets/{target}/snapshot")
    async def admin_snapshot(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        orch = app.state.orchestrator
        snapshot = orch.snapshot()
        try:
            agent = _target_agent(snapshot, target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not agent or not agent.get("endpoint_id"):
            raise HTTPException(status_code=409, detail="target is not backed by an enrolled endpoint agent")
        job = await orch.response.queue(
            endpoint_id=str(agent["endpoint_id"]),
            action="COLLECT_SNAPSHOT",
            role=Role.PLATFORM_ADMINISTRATOR,
            operator="admin-console",
        )
        return {"target": target, "job": job}

    @app.post("/api/v1/admin/targets/{target}/isolate")
    async def admin_isolate(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        orch = app.state.orchestrator
        snapshot = orch.snapshot()
        try:
            agent = _target_agent(snapshot, target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not agent or not agent.get("endpoint_id"):
            raise HTTPException(status_code=409, detail="target is not backed by an enrolled endpoint agent")
        management_ip = _management_ip(snapshot)
        if not management_ip:
            raise HTTPException(status_code=409, detail="management interface address is unavailable; isolation refused")
        job = await orch.response.queue(
            endpoint_id=str(agent["endpoint_id"]),
            action="ISOLATE_HOST",
            arguments={"management_ip": management_ip},
            role=Role.PLATFORM_ADMINISTRATOR,
            operator="admin-console",
        )
        return {"target": target, "management_ip": management_ip, "job": job}

    @app.post("/api/v1/admin/targets/{target}/restore")
    async def admin_restore(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        orch = app.state.orchestrator
        snapshot = orch.snapshot()
        try:
            agent = _target_agent(snapshot, target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not agent or not agent.get("endpoint_id"):
            raise HTTPException(status_code=409, detail="target is not backed by an enrolled endpoint agent")
        job = await orch.response.queue(
            endpoint_id=str(agent["endpoint_id"]),
            action="RESTORE_NETWORK",
            role=Role.PLATFORM_ADMINISTRATOR,
            operator="admin-console",
        )
        return {"target": target, "job": job}

    @app.post("/api/v1/admin/targets/{target}/connect")
    async def admin_connect(
        target: str,
        body: AdminConnectRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(request, x_campus_admin, store)
        protocol = body.protocol.lower().strip()
        if protocol not in {"ssh", "rdp"}:
            raise HTTPException(status_code=400, detail="protocol must be ssh or rdp")
        orch = app.state.orchestrator
        snapshot = orch.snapshot()
        endpoint = _remote_endpoint(snapshot, target)
        if not endpoint or not endpoint.get("endpoint_id"):
            raise HTTPException(
                status_code=409,
                detail="target is not an explicitly enrolled remote-console endpoint",
            )
        try:
            return await orch.control.connect(str(endpoint["endpoint_id"]), protocol)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return app
