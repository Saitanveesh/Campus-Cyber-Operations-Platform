from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request

from campus_ops.investigation import build_investigation


def _local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _require_local(request: Request) -> None:
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="MON operator workspaces are local-console only")


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
            "asset": True,
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
                    "asset": False,
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
    """Install local passive Investigation and Forensics routes.

    The stable console is already bound to localhost.  These workspaces therefore do
    not add a second Admin/login surface; they are direct local-console functions.
    """
    if getattr(app.state, "stable_operator_routes_installed", False):
        return app
    app.state.stable_operator_routes_installed = True

    @app.get("/api/v1/operator/targets")
    async def operator_targets(request: Request) -> dict[str, object]:
        _require_local(request)
        return {
            "targets": _observed_targets(app.state.orchestrator.snapshot()),
            "mode": "PASSIVE_ONLY",
        }

    @app.get("/api/v1/operator/investigate/{target}")
    async def operator_investigate(target: str, request: Request) -> dict[str, object]:
        _require_local(request)
        try:
            return build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/operator/forensics/{target}")
    async def operator_forensics(target: str, request: Request) -> dict[str, object]:
        _require_local(request)
        try:
            report = build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            **report,
            "forensics_claim": "CURRENT_SESSION_PASSIVE_EVIDENCE_ONLY",
        }

    return app
