from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin

_ADMIN_PORTS = {
    22: "SSH",
    23: "TELNET",
    3389: "RDP",
    445: "SMB",
    5985: "WINRM",
    5986: "WINRM_TLS",
    5900: "VNC",
}


def _target_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def _flow_port(flow: dict[str, Any], target: str) -> tuple[int | None, str | None]:
    src = str(flow.get("src") or flow.get("src_ip") or "")
    dst = str(flow.get("dst") or flow.get("dst_ip") or "")
    if dst == target:
        port = flow.get("dst_port") or flow.get("dport")
        return (int(port) if str(port).isdigit() else None, src or None)
    if src == target:
        port = flow.get("src_port") or flow.get("sport")
        return (int(port) if str(port).isdigit() else None, dst or None)
    return None, None


def build_red_panel(app: FastAPI, target: str) -> dict[str, Any]:
    target = _target_ip(target)
    live = app.state.orchestrator.state.snapshot()
    assets = [row for row in live.get("assets", []) if isinstance(row, dict)]
    flows = [row for row in live.get("flows", []) if isinstance(row, dict)]
    alerts = [row for row in live.get("alerts", []) if isinstance(row, dict)]
    incidents = [row for row in live.get("incidents", []) if isinstance(row, dict)]

    asset = next((row for row in assets if str(row.get("ip") or row.get("id") or "") == target), None)
    target_flows = [row for row in flows if target in {str(row.get("src") or row.get("src_ip") or ""), str(row.get("dst") or row.get("dst_ip") or "")}]
    ports: Counter[int] = Counter()
    peers: Counter[str] = Counter()
    for flow in target_flows:
        port, peer = _flow_port(flow, target)
        if port is not None:
            ports[port] += 1
        if peer:
            peers[peer] += 1

    signal_rows: list[dict[str, Any]] = []
    for row in [*alerts, *incidents]:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        text = " ".join(str(value) for value in [row.get("title"), row.get("summary"), row.get("source"), *payload.values()])
        if target in text:
            signal_rows.append(row)

    exposures = []
    for port, count in ports.most_common(20):
        exposures.append(
            {
                "port": port,
                "service_hint": _ADMIN_PORTS.get(port, "OBSERVED_SERVICE"),
                "flow_count": count,
                "administrative": port in _ADMIN_PORTS,
            }
        )

    hypotheses: list[dict[str, str]] = []
    if any(item["administrative"] for item in exposures):
        hypotheses.append({"area": "REMOTE_ACCESS", "finding": "Administrative service traffic is observed; validate exposure and authentication policy."})
    if len(peers) >= 12:
        hypotheses.append({"area": "LATERAL_MOVEMENT", "finding": f"Target communicates with {len(peers)} peers; validate whether this fan-out matches its role."})
    if signal_rows:
        hypotheses.append({"area": "DETECTION", "finding": f"{len(signal_rows)} current-session security signal(s) reference this target."})
    if not hypotheses:
        hypotheses.append({"area": "BASELINE", "finding": "No strong adversary-emulation hypothesis is supported by current evidence. Start with passive validation."})

    managed = False
    try:
        managed = any(str(row.get("host") or row.get("endpoint_id") or "") == target for row in app.state.orchestrator.agents.list())
    except Exception:
        managed = False

    return {
        "target": target,
        "asset": asset,
        "observed_flows": len(target_flows),
        "peer_count": len(peers),
        "top_peers": peers.most_common(20),
        "exposures": exposures,
        "security_signals": len(signal_rows),
        "hypotheses": hypotheses,
        "managed_endpoint": managed,
        "allowed_validation": [
            "Passive evidence pivot",
            "Authorized service verification",
            "Forensic snapshot on managed endpoints",
            "Containment on managed endpoints after operator confirmation",
        ],
        "guardrails": [
            "RED-PANEL is for authorized validation and adversary-emulation planning.",
            "It does not auto-exploit, brute-force credentials, or run destructive actions.",
            "Active probes require explicit operator confirmation and private/authorized scope.",
        ],
    }


def install_red_panel(app: FastAPI) -> FastAPI:
    if getattr(app.state, "red_panel_installed", False):
        return app
    app.state.red_panel_installed = True

    @app.get("/api/v1/admin/red-panel/{target}")
    async def red_panel(target: str, request: Request, x_campus_admin: str | None = Header(default=None)) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return build_red_panel(app, target)

    return app
