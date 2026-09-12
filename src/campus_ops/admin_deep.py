from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.investigation import build_investigation
from campus_ops.policy import Role
from campus_ops.workers.endpoint_deep_monitor import analyze_agent


class AdminTerminateRequest(BaseModel):
    pid: int = Field(gt=4)


class AdminBlockPeerRequest(BaseModel):
    remote_ip: str = Field(min_length=3, max_length=64)


class AdminQuarantineRequest(BaseModel):
    path: str = Field(min_length=1, max_length=2048)


def _local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _require_admin(app: FastAPI, request: Request, token: str | None) -> None:
    store = getattr(app.state, "admin_sessions", None)
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="administrator console is local-only")
    if store is None or not store.validate(token):
        raise HTTPException(status_code=401, detail="administrator authentication required")


def _target_agent(orchestrator: Any, target: str) -> tuple[str, dict[str, Any]]:
    investigation = build_investigation(orchestrator.snapshot(), target)
    agent = investigation.get("managed_agent")
    if not isinstance(agent, dict) or not agent.get("endpoint_id"):
        raise LookupError("target is not backed by an enrolled endpoint agent")
    return str(agent["endpoint_id"]), investigation


def _parse_remote_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("[") and "]:" in raw:
        host = raw[1:].split("]:", 1)[0]
    else:
        host, sep, _ = raw.rpartition(":")
        if not sep:
            host = raw
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return None
    return str(ip)


def build_deep_dossier(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    investigation = build_investigation(snapshot, target)
    agent = investigation.get("managed_agent")
    endpoint = analyze_agent(agent) if isinstance(agent, dict) else None

    network_processes: list[dict[str, Any]] = []
    if endpoint:
        connection_counts: dict[int, int] = {}
        peer_counts: dict[int, set[str]] = {}
        for connection in endpoint.get("connections", []):
            if not isinstance(connection, dict):
                continue
            try:
                pid = int(connection.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            if not pid:
                continue
            connection_counts[pid] = connection_counts.get(pid, 0) + 1
            remote_ip = _parse_remote_ip(connection.get("remote"))
            if remote_ip:
                peer_counts.setdefault(pid, set()).add(remote_ip)

        for process in endpoint.get("processes", []):
            if not isinstance(process, dict):
                continue
            try:
                pid = int(process.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            row = dict(process)
            row["active_connections"] = connection_counts.get(pid, 0)
            row["unique_remote_peers"] = len(peer_counts.get(pid, set()))
            network_processes.append(row)
        network_processes.sort(
            key=lambda item: (
                int(item.get("admin_peer_count") or 0),
                int(item.get("unique_remote_peers") or 0),
                int(item.get("active_connections") or 0),
                float(item.get("memory_percent") or 0),
            ),
            reverse=True,
        )

    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    metrics = live.get("metrics") if isinstance(live.get("metrics"), dict) else {}
    endpoint_metrics = metrics.get("endpoint_deep") if isinstance(metrics.get("endpoint_deep"), dict) else {}
    endpoint_metric_rows = endpoint_metrics.get("endpoints") if isinstance(endpoint_metrics.get("endpoints"), dict) else {}
    metric_report = None
    if isinstance(agent, dict) and agent.get("endpoint_id"):
        candidate = endpoint_metric_rows.get(str(agent["endpoint_id"]))
        if isinstance(candidate, dict):
            metric_report = candidate

    return {
        "target": investigation["target"],
        "session_id": investigation.get("session_id"),
        "risk": investigation.get("risk"),
        "summary": investigation.get("summary"),
        "asset": investigation.get("asset"),
        "managed": bool(endpoint),
        "agent": agent,
        "endpoint": endpoint,
        "processes": network_processes[:200],
        "connections": (endpoint or {}).get("connections", [])[:300],
        "listeners": (endpoint or {}).get("listeners", [])[:200],
        "services": (endpoint or {}).get("services", [])[:300],
        "users": (endpoint or {}).get("users", []),
        "findings": (metric_report or endpoint or {}).get("findings", []),
        "network": {
            "flows": investigation.get("flows", [])[:100],
            "alerts": investigation.get("alerts", [])[:100],
            "incidents": investigation.get("incidents", [])[:50],
            "topology_edges": investigation.get("topology_edges", [])[:100],
            "recent_packets": investigation.get("recent_packets", [])[:50],
        },
        "controls": {
            "can_collect_snapshot": bool(endpoint),
            "can_stop_process": bool(endpoint),
            "can_quarantine_file": bool(endpoint),
            "can_block_peer": bool(endpoint),
            "can_isolate": bool(endpoint),
        },
    }


def install_admin_deep_routes(app: FastAPI) -> FastAPI:
    if getattr(app.state, "admin_deep_routes_installed", False):
        return app
    app.state.admin_deep_routes_installed = True

    @app.get("/api/v1/admin/deep/{target}")
    async def admin_deep_dossier(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        try:
            return build_deep_dossier(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/admin/deep/{target}/snapshot")
    async def admin_deep_snapshot(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        orch = app.state.orchestrator
        try:
            endpoint_id, _ = _target_agent(orch, target)
            job = await orch.response.queue(
                endpoint_id=endpoint_id,
                action="COLLECT_SNAPSHOT",
                role=Role.PLATFORM_ADMINISTRATOR,
                operator="admin-deep-console",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"target": target, "job": job}

    @app.post("/api/v1/admin/deep/{target}/terminate")
    async def admin_deep_terminate(
        target: str,
        body: AdminTerminateRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        orch = app.state.orchestrator
        try:
            endpoint_id, _ = _target_agent(orch, target)
            job = await orch.response.queue(
                endpoint_id=endpoint_id,
                action="STOP_PROCESS",
                arguments={"pid": body.pid},
                role=Role.PLATFORM_ADMINISTRATOR,
                operator="admin-deep-console",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"target": target, "job": job}

    @app.post("/api/v1/admin/deep/{target}/block-peer")
    async def admin_deep_block_peer(
        target: str,
        body: AdminBlockPeerRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        try:
            remote_ip = str(ipaddress.ip_address(body.remote_ip.strip()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid remote IP address") from exc
        orch = app.state.orchestrator
        try:
            endpoint_id, _ = _target_agent(orch, target)
            job = await orch.response.queue(
                endpoint_id=endpoint_id,
                action="BLOCK_REMOTE_IP",
                arguments={"remote_ip": remote_ip},
                role=Role.PLATFORM_ADMINISTRATOR,
                operator="admin-deep-console",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"target": target, "remote_ip": remote_ip, "job": job}

    @app.post("/api/v1/admin/deep/{target}/quarantine")
    async def admin_deep_quarantine(
        target: str,
        body: AdminQuarantineRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(app, request, x_campus_admin)
        orch = app.state.orchestrator
        try:
            endpoint_id, _ = _target_agent(orch, target)
            job = await orch.response.queue(
                endpoint_id=endpoint_id,
                action="QUARANTINE_FILE",
                arguments={"path": body.path},
                role=Role.PLATFORM_ADMINISTRATOR,
                operator="admin-deep-console",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"target": target, "job": job}

    return app
