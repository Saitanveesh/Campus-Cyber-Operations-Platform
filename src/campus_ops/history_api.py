from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import FastAPI, HTTPException, Query

from campus_ops.workers.evidence_store import EvidenceStoreWorker


def _target(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid IP address") from exc
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise HTTPException(status_code=400, detail="special-purpose IP is not a history target")
    return str(ip)


def install_history_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "history_api_installed", False):
        return app
    app.state.history_api_installed = True

    @app.get("/api/v1/history/ip/{target}")
    async def history_ip(
        target: str,
        limit: int = Query(default=250, ge=1, le=1000),
    ) -> dict[str, Any]:
        target = _target(target)
        return EvidenceStoreWorker.query_ip(target, limit=limit)

    return app
