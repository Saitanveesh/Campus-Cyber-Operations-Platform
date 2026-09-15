from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    live = snap.get("live")
    return live if isinstance(live, dict) else {}


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [row for row in _live(app).get("flows", []) if isinstance(row, dict)]


def _events(app: FastAPI) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    live = _live(app)
    for key in ("events", "alerts", "incidents", "packet_feed"):
        value = live.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    return rows


def _ends(flow: dict[str, Any]) -> tuple[str, str]:
    src = str(flow.get("src_ip") or flow.get("source") or flow.get("src") or "").strip()
    dst = str(flow.get("dst_ip") or flow.get("destination") or flow.get("dst") or "").strip()
    return src, dst


def _dst_port(flow: dict[str, Any]) -> int | None:
    value = flow.get("dst_port") or flow.get("dport") or flow.get("port")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _valid_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_multicast)


def asset_identity_fusion(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    assets = [row for row in live.get("assets", []) if isinstance(row, dict)]
    by_ip: dict[str, dict[str, Any]] = {}
    for asset in assets:
        ip = str(asset.get("ip") or asset.get("address") or asset.get("id") or "").strip()
        if not _valid_ip(ip):
            continue
        row = by_ip.setdefault(ip, {"ip": ip, "hostnames": set(), "macs": set(), "roles": set(), "sources": set()})
        for key in ("hostname", "dhcp_hostname", "dns_name"):
            if asset.get(key): row["hostnames"].add(str(asset[key]))
        if asset.get("mac"): row["macs"].add(str(asset["mac"]).lower())
        for key in ("role", "classification"):
            if asset.get(key): row["roles"].add(str(asset[key]))
        row["sources"].add("ASSET_ENGINE")
    for event in _events(app):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        ip = str(payload.get("ip") or payload.get("src_ip") or payload.get("address") or "").strip()
        if not _valid_ip(ip): continue
        row = by_ip.setdefault(ip, {"ip": ip, "hostnames": set(), "macs": set(), "roles": set(), "sources": set()})
        if payload.get("hostname"): row["hostnames"].add(str(payload["hostname"]))
        if payload.get("mac"): row["macs"].add(str(payload["mac"]).lower())
        row["sources"].add(str(event.get("source") or "EVENT"))
    fused=[]
    for row in by_ip.values():
        conflicts=[]
        if len(row["macs"])>1: conflicts.append("multiple-mac-identities")
        if len(row["hostnames"])>1: conflicts.append("multiple-hostnames")
        confidence=min(100, 35 + len(row["sources"])*15 + (10 if row["macs"] else 0) + (10 if row["hostnames"] else 0))
        fused.append({"ip":row["ip"],"hostnames":sorted(row["hostnames"]),"macs":sorted(row["macs"]),"roles":sorted(row["roles"]),"sources":sorted(row["sources"]),"confidence":confidence,"conflicts":conflicts})
    fused.sort(key=lambda x:(len(x["conflicts"]),x["confidence"]), reverse=True)
    return {"engine":"ASSET_IDENTITY_FUSION","state":"OBSERVED" if fused else "NO_IDENTITY_EVIDENCE","assets":fused[:500],"truth_note":"Identity is fused from observed evidence; conflicts are surfaced, not silently resolved."}


def recon_engine(app: FastAPI) -> dict[str, Any]:
    ports: dict[str, set[int]] = defaultdict(set); peers: dict[str, set[str]] = defaultdict(set); flows=Counter()
    for flow in _flows(app):
        src,dst=_ends(flow); port=_dst_port(flow)
        if not src or not dst: continue
        flows[src]+=1; peers[src].add(dst)
        if port is not None: ports[src].add(port)
    findings=[]
    for src in flows:
        score=min(100, len(ports[src])*5 + len(peers[src])*3)
        reasons=[]
        if len(ports[src])>=15: reasons.append("many-destination-ports")
        if len(peers[src])>=20: reasons.append("many-destination-hosts")
        if score>=45: findings.append({"source":src,"score":score,"distinct_ports":len(ports[src]),"distinct_hosts":len(peers[src]),"flow_count":flows[src],"reasons":reasons})
    findings.sort(key=lambda x:x["score"], reverse=True)
    return {"engine":"RECON_DISCOVERY_ANALYTICS","state":"OBSERVED" if findings else "NO_STRONG_PATTERN","findings":findings[:100],"truth_note":"Broad connection diversity is a recon indicator, not proof of scanning."}


def topology_drift_engine(app: FastAPI) -> dict[str, Any]:
    live=_live(app); edges=[e for e in live.get("topology_edges",[]) if isinstance(e,dict)]
    newish=[]
    for e in edges:
        if e.get("first_seen") and e.get("last_seen") and str(e.get("first_seen"))==str(e.get("last_seen")):
            newish.append({"source":e.get("source"),"target":e.get("target"),"protocol":e.get("protocol") or e.get("last_protocol"),"evidence":"CURRENT_SESSION_NEW_EDGE"})
    return {"engine":"TOPOLOGY_DRIFT","state":"OBSERVED" if newish else "NO_DRIFT_EVIDENCE","new_relationships":newish[:200],"truth_note":"Without historical baseline, only newly created current-session relationships are reported."}


def confidence_fusion(app: FastAPI) -> dict[str, Any]:
    grouped: dict[str, list[dict[str,Any]]] = defaultdict(list)
    for event in _events(app):
        payload=event.get("payload") if isinstance(event.get("payload"),dict) else {}
        target=str(payload.get("ip") or payload.get("host") or payload.get("src_ip") or payload.get("dst_ip") or "").strip()
        if not target: continue
        grouped[target].append(event)
    out=[]
    weights={"CRITICAL":35,"HIGH":25,"MEDIUM":15,"LOW":7,"INFO":2}
    for target,rows in grouped.items():
        sources={str(r.get("source") or "unknown") for r in rows}
        score=sum(weights.get(str(r.get("severity") or "INFO").upper(),2) for r in rows)
        score=min(100, score + max(0,len(sources)-1)*8)
        out.append({"target":target,"confidence":score,"signal_count":len(rows),"independent_sources":len(sources),"sources":sorted(sources)})
    out.sort(key=lambda x:x["confidence"], reverse=True)
    return {"engine":"DETECTION_CONFIDENCE_FUSION","state":"OBSERVED" if out else "NO_CORRELATED_SIGNALS","targets":out[:200],"truth_note":"Confidence rises with severity and independent evidence sources; it is not compromise probability."}


def correlation_fabric(app: FastAPI) -> dict[str, Any]:
    engines=[asset_identity_fusion(app),recon_engine(app),topology_drift_engine(app),confidence_fusion(app)]
    return {"state":"ACTIVE","engine_count":len(engines),"engines":engines,"session_id":app.state.orchestrator.session_id,"contract":"CURRENT_SESSION_EVIDENCE_FUSION"}


def install_correlation_fabric(app: FastAPI) -> FastAPI:
    if getattr(app.state,"correlation_fabric_installed",False): return app
    app.state.correlation_fabric_installed=True
    @app.get("/api/v1/system/correlation-fabric")
    async def system_correlation_fabric()->dict[str,Any]: return correlation_fabric(app)
    @app.get("/api/v1/admin/correlation-fabric")
    async def admin_correlation_fabric(request:Request,x_campus_admin:str|None=Header(default=None))->dict[str,Any]:
        _require_admin(app,request,x_campus_admin); return correlation_fabric(app)
    return app
