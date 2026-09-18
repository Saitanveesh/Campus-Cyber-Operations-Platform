from __future__ import annotations

import ipaddress

from fastapi import FastAPI, HTTPException, Request

from campus_ops.investigation import build_investigation
from campus_ops.workers.evidence_store import EvidenceStoreWorker


def _local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _require_local(request: Request) -> None:
    if not _local_request(request):
        raise HTTPException(status_code=403, detail="MON Windows console is local-only")


def _real_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return None
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return str(ip)


def _observed_targets(snapshot: dict[str, object]) -> list[dict[str, object]]:
    """Return only IPs proven by current-session TShark-derived state."""
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    flows = [item for item in live.get("flows", []) if isinstance(item, dict)]
    edges = [item for item in live.get("topology_edges", []) if isinstance(item, dict)]

    rows: dict[str, dict[str, object]] = {}
    for asset in assets:
        ip = _real_ip(asset.get("ip"))
        if not ip:
            continue
        rows[ip] = {
            "ip": ip,
            "name": asset.get("hostname") or asset.get("dhcp_hostname") or "",
            "vendor": asset.get("vendor") or "",
            "mac": asset.get("mac") or "",
            "classification": asset.get("classification") or asset.get("role") or "LOCAL_ASSET",
            "last_seen": asset.get("last_seen"),
            "packets": int(asset.get("packets_as_source") or 0),
            "asset": True,
            "evidence": asset.get("evidence") or "CONFIRMED_LOCAL_SOURCE_FRAMES",
        }

    for flow in flows:
        if str(flow.get("source") or "") not in {"PACKET_CAPTURE", ""}:
            continue
        count = int(flow.get("packets") or 0)
        last_seen = flow.get("last_seen")
        for key in ("src", "dst"):
            ip = _real_ip(flow.get(key))
            if not ip:
                continue
            row = rows.setdefault(
                ip,
                {
                    "ip": ip,
                    "name": "",
                    "vendor": "",
                    "mac": "",
                    "classification": "OBSERVED_PACKET_PEER",
                    "last_seen": last_seen,
                    "packets": 0,
                    "asset": False,
                    "evidence": "OBSERVED_PACKET_CONVERSATION",
                },
            )
            row["packets"] = int(row.get("packets") or 0) + count
            if last_seen and str(last_seen) > str(row.get("last_seen") or ""):
                row["last_seen"] = last_seen

    for edge in edges:
        if str(edge.get("evidence") or "") != "TSHARK_PACKET_OBSERVED":
            continue
        count = int(edge.get("packets") or 0)
        last_seen = edge.get("last_seen")
        for key in ("source", "target"):
            ip = _real_ip(edge.get(key))
            if not ip:
                continue
            row = rows.setdefault(
                ip,
                {
                    "ip": ip,
                    "name": "",
                    "vendor": "",
                    "mac": "",
                    "classification": "OBSERVED_PACKET_PEER",
                    "last_seen": last_seen,
                    "packets": 0,
                    "asset": False,
                    "evidence": "TSHARK_PACKET_OBSERVED",
                },
            )
            row["packets"] = max(int(row.get("packets") or 0), count)
            if last_seen and str(last_seen) > str(row.get("last_seen") or ""):
                row["last_seen"] = last_seen

    return sorted(
        rows.values(),
        key=lambda item: (int(item.get("packets") or 0), str(item.get("last_seen") or "")),
        reverse=True,
    )[:500]


def install_stable_operator_routes(app: FastAPI) -> FastAPI:
    """Install direct passive investigation routes; there is no Admin panel."""
    if getattr(app.state, "stable_operator_routes_installed", False):
        return app
    app.state.stable_operator_routes_installed = True

    @app.get("/api/v1/operator/targets")
    async def operator_targets(request: Request) -> dict[str, object]:
        _require_local(request)
        snapshot = app.state.orchestrator.snapshot()
        return {
            "targets": _observed_targets(snapshot),
            "session_id": snapshot.get("session_id"),
            "source_contract": "CURRENT_SESSION_TSHARK_EVIDENCE_ONLY",
        }

    @app.get("/api/v1/operator/investigate/{target}")
    async def operator_investigate(target: str, request: Request) -> dict[str, object]:
        _require_local(request)
        try:
            report = build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not report.get("observed"):
            raise HTTPException(
                status_code=404,
                detail=(
                    "Target was not observed in the current TShark capture. "
                    "MON will not fabricate an investigation for an unseen IP."
                ),
            )
        history = EvidenceStoreWorker.query_ip(str(report["target"]), limit=100)
        report["history"] = {
            "event_count": len(history.get("events", [])),
            "snapshot_count": len(history.get("snapshots", [])),
            "recent_events": history.get("events", [])[:25],
            "retention_days": history.get("retention_days"),
            "claim": history.get("claim"),
        }
        return report

    return app
