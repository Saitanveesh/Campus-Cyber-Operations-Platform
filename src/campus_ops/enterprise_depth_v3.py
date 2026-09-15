from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.enterprise_telemetry import telemetry_fabric_status


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    live = snap.get("live")
    return live if isinstance(live, dict) else {}


def _events(app: FastAPI) -> list[dict[str, Any]]:
    live = _live(app)
    rows: list[dict[str, Any]] = []
    for key in ("events", "alerts", "packet_feed"):
        value = live.get(key)
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, dict))
    return rows


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [row for row in _live(app).get("flows", []) if isinstance(row, dict)]


def _ends(flow: dict[str, Any]) -> tuple[str, str]:
    return (
        str(flow.get("src_ip") or flow.get("source") or flow.get("src") or "").strip(),
        str(flow.get("dst_ip") or flow.get("destination") or flow.get("dst") or "").strip(),
    )


def _dst_port(flow: dict[str, Any]) -> int | None:
    raw = flow.get("dst_port") or flow.get("dport") or flow.get("port")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("payload")
    return value if isinstance(value, dict) else {}


@dataclass
class RollingBaseline:
    session_id: str | None = None
    observations: int = 0
    peers: set[tuple[str, str]] = field(default_factory=set)
    services: set[tuple[str, int]] = field(default_factory=set)
    assets: set[str] = field(default_factory=set)

    def update(self, app: FastAPI) -> dict[str, Any]:
        session = str(app.state.orchestrator.session_id)
        if session != self.session_id:
            self.session_id = session
            self.observations = 0
            self.peers.clear()
            self.services.clear()
            self.assets.clear()

        current_peers: set[tuple[str, str]] = set()
        current_services: set[tuple[str, int]] = set()
        current_assets: set[str] = set()
        for asset in _live(app).get("assets", []):
            if isinstance(asset, dict):
                identity = str(asset.get("ip") or asset.get("id") or "").strip()
                if identity:
                    current_assets.add(identity)
        for flow in _flows(app):
            src, dst = _ends(flow)
            if src and dst:
                current_peers.add((src, dst))
            port = _dst_port(flow)
            if dst and port is not None:
                current_services.add((dst, port))

        new_peers = sorted(current_peers - self.peers)[:100]
        new_services = sorted(current_services - self.services)[:100]
        new_assets = sorted(current_assets - self.assets)[:100]
        self.peers.update(current_peers)
        self.services.update(current_services)
        self.assets.update(current_assets)
        self.observations += 1
        learning = self.observations <= 2
        return {
            "engine": "ROLLING_SESSION_BASELINE",
            "state": "LEARNING" if learning else "ACTIVE",
            "session_id": self.session_id,
            "observations": self.observations,
            "new_assets": [] if learning else new_assets,
            "new_relationships": [] if learning else [{"src": s, "dst": d} for s, d in new_peers],
            "new_services": [] if learning else [{"host": h, "port": p} for h, p in new_services],
            "truth_note": "Baseline is scoped to the current live session and never substitutes for live telemetry.",
        }


def infrastructure_integrity(app: FastAPI) -> dict[str, Any]:
    dhcp_servers: Counter[str] = Counter()
    dns_servers: Counter[str] = Counter()
    gateways: Counter[str] = Counter()
    conflicts: list[dict[str, Any]] = []

    for row in _events(app):
        payload = _payload(row)
        text = " ".join(str(payload.get(k) or "") for k in ("type", "protocol", "message", "summary")).upper()
        if "DHCP" in text:
            server = str(payload.get("server_ip") or payload.get("dhcp_server") or payload.get("src_ip") or "").strip()
            if server and server != "0.0.0.0":
                dhcp_servers[server] += 1
        if "DNS" in text:
            server = str(payload.get("server_ip") or payload.get("dns_server") or payload.get("dst_ip") or "").strip()
            if server and server != "0.0.0.0":
                dns_servers[server] += 1
        if "GATEWAY" in text or "ROUTER ADVERT" in text:
            gw = str(payload.get("gateway") or payload.get("router") or payload.get("src_ip") or "").strip()
            if gw:
                gateways[gw] += 1
        if any(token in text for token in ("ARP CONFLICT", "DUPLICATE IP", "ADDRESS CONFLICT")):
            conflicts.append({"source": row.get("source"), "payload": payload})

    findings: list[dict[str, Any]] = []
    if len(dhcp_servers) > 1:
        findings.append({"type": "MULTIPLE_DHCP_SERVERS", "severity": "MEDIUM", "servers": dhcp_servers.most_common()})
    if len(gateways) > 1:
        findings.append({"type": "MULTIPLE_GATEWAYS_OBSERVED", "severity": "INFO", "gateways": gateways.most_common()})
    if conflicts:
        findings.append({"type": "ADDRESS_OWNERSHIP_CONFLICT", "severity": "MEDIUM", "count": len(conflicts)})

    return {
        "engine": "INFRASTRUCTURE_INTEGRITY",
        "state": "ATTENTION" if findings else "OBSERVED",
        "dhcp_servers": dhcp_servers.most_common(20),
        "dns_servers": dns_servers.most_common(20),
        "gateways": gateways.most_common(20),
        "findings": findings,
        "truth_note": "Only observed infrastructure identities are reported; multiple servers may be legitimate in redundant designs.",
    }


def protocol_depth(app: FastAPI) -> dict[str, Any]:
    nxdomain = 0
    legacy_tls = 0
    plaintext = Counter()
    smb_sources: dict[str, set[str]] = defaultdict(set)
    rdp_sources: dict[str, set[str]] = defaultdict(set)

    for row in _events(app):
        p = _payload(row)
        rcode = str(p.get("rcode_name") or p.get("rcode") or "").upper()
        if "NXDOMAIN" in rcode or rcode == "3":
            nxdomain += 1
        tls = str(p.get("tls_version") or "").upper()
        if tls in {"SSLV2", "SSLV3", "TLS1.0", "TLSV1", "TLSV1.0"}:
            legacy_tls += 1

    for flow in _flows(app):
        src, dst = _ends(flow)
        port = _dst_port(flow)
        if port in {21, 23, 69, 110, 143}:
            plaintext[str(port)] += 1
        if port == 445 and src and dst:
            smb_sources[src].add(dst)
        if port == 3389 and src and dst:
            rdp_sources[src].add(dst)

    findings: list[dict[str, Any]] = []
    if nxdomain >= 25:
        findings.append({"type": "DNS_NXDOMAIN_VOLUME", "severity": "LOW", "count": nxdomain})
    if legacy_tls:
        findings.append({"type": "LEGACY_TLS", "severity": "MEDIUM", "count": legacy_tls})
    if plaintext:
        findings.append({"type": "PLAINTEXT_PROTOCOL_USE", "severity": "MEDIUM", "ports": dict(plaintext)})
    for src, dsts in smb_sources.items():
        if len(dsts) >= 8:
            findings.append({"type": "SMB_FANOUT", "severity": "MEDIUM", "source": src, "destinations": len(dsts)})
    for src, dsts in rdp_sources.items():
        if len(dsts) >= 5:
            findings.append({"type": "RDP_FANOUT", "severity": "MEDIUM", "source": src, "destinations": len(dsts)})

    return {"engine": "PROTOCOL_DEPTH", "state": "ATTENTION" if findings else "OBSERVED", "findings": findings}


def crown_jewel_risk(app: FastAPI) -> dict[str, Any]:
    configured = [x.strip() for x in os.environ.get("CAMPUS_OPS_CROWN_JEWELS", "").split(",") if x.strip()]
    if not configured:
        return {"engine": "CROWN_JEWEL_RISK", "state": "NOT_CONFIGURED", "assets": [], "paths": []}
    jewel_set = set(configured)
    inbound: dict[str, Counter[str]] = defaultdict(Counter)
    for flow in _flows(app):
        src, dst = _ends(flow)
        if src and dst in jewel_set:
            inbound[dst][src] += 1
    paths = []
    for jewel in configured:
        for src, count in inbound[jewel].most_common(100):
            paths.append({"source": src, "crown_jewel": jewel, "observations": count, "risk": min(100, 25 + count * 3)})
    paths.sort(key=lambda x: x["risk"], reverse=True)
    return {
        "engine": "CROWN_JEWEL_RISK",
        "state": "OBSERVED" if paths else "NO_CURRENT_REACHABILITY_EVIDENCE",
        "assets": configured,
        "paths": paths,
        "truth_note": "Reachability is based on observed current-session communication, not assumed exploitability.",
    }


def visibility_score(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    fabric = telemetry_fabric_status()
    score = 0
    evidence: list[str] = []
    if str(capture.get("state") or "").upper() in {"ACTIVE", "RUNNING", "READY"}:
        score += 35; evidence.append("packet-capture")
    if live.get("flows"):
        score += 20; evidence.append("flow-visibility")
    if live.get("assets"):
        score += 15; evidence.append("asset-visibility")
    ready_planes = sum(1 for value in fabric.get("planes", {}).values() if int(value.get("ready", 0)) > 0)
    score += min(20, ready_planes * 4)
    if any(v.get("state") == "CONFIGURED" for v in fabric.get("streaming_telemetry", {}).values()):
        score += 10; evidence.append("infrastructure-telemetry")
    score = min(100, score)
    return {
        "engine": "VISIBILITY_CONFIDENCE",
        "score": score,
        "state": "STRONG" if score >= 75 else ("PARTIAL" if score >= 40 else "LIMITED"),
        "evidence": evidence,
        "ready_tool_count": fabric.get("ready_tools", 0),
        "truth_note": "Visibility score measures sensor coverage, not network security posture.",
    }


def enterprise_depth_v3(app: FastAPI) -> dict[str, Any]:
    baseline = app.state.enterprise_baseline.update(app)
    engines = [baseline, infrastructure_integrity(app), protocol_depth(app), crown_jewel_risk(app), visibility_score(app)]
    return {"state": "ACTIVE", "session_id": app.state.orchestrator.session_id, "engine_count": len(engines), "engines": engines}


def install_enterprise_depth_v3(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_depth_v3_installed", False):
        return app
    app.state.enterprise_depth_v3_installed = True
    app.state.enterprise_baseline = RollingBaseline()

    @app.get("/api/v1/system/depth-engines-v3")
    async def system_depth_v3() -> dict[str, Any]:
        return enterprise_depth_v3(app)

    @app.get("/api/v1/admin/depth-engines-v3")
    async def admin_depth_v3(request: Request, x_campus_admin: str | None = Header(default=None)) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return enterprise_depth_v3(app)

    return app
