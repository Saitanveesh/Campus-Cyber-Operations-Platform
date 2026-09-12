from __future__ import annotations

import ipaddress
import os
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.depth_engines import engine_suite
from campus_ops.depth_engines_v2 import depth_engines_v2
from campus_ops.enterprise_depth_v3 import enterprise_depth_v3


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    live = snap.get("live")
    return live if isinstance(live, dict) else {}


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [row for row in _live(app).get("flows", []) if isinstance(row, dict)]


def _events(app: FastAPI) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("events", "alerts", "incidents", "packet_feed"):
        rows = _live(app).get(key)
        if isinstance(rows, list):
            out.extend(row for row in rows if isinstance(row, dict))
    return out


def _ends(flow: dict[str, Any]) -> tuple[str, str]:
    return (
        str(flow.get("src_ip") or flow.get("source") or flow.get("src") or "").strip(),
        str(flow.get("dst_ip") or flow.get("destination") or flow.get("dst") or "").strip(),
    )


def _valid_host(value: object) -> str | None:
    text = str(value or "").strip().split("%", 1)[0]
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text if len(text) <= 255 else None
    if addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr)


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    val = row.get("payload")
    return val if isinstance(val, dict) else {}


def _severity_weight(value: object) -> int:
    return {"INFO": 3, "LOW": 8, "MEDIUM": 18, "HIGH": 32, "CRITICAL": 45}.get(str(value or "INFO").upper(), 3)


@dataclass
class InfrastructureMemory:
    session_id: str | None = None
    observations: int = 0
    gateways: Counter[str] = field(default_factory=Counter)
    dns: Counter[str] = field(default_factory=Counter)
    dhcp: Counter[str] = field(default_factory=Counter)

    def update(self, app: FastAPI) -> dict[str, Any]:
        session = str(app.state.orchestrator.session_id)
        if session != self.session_id:
            self.session_id = session
            self.observations = 0
            self.gateways.clear(); self.dns.clear(); self.dhcp.clear()
        current_gateway = Counter(); current_dns = Counter(); current_dhcp = Counter()
        for row in _events(app):
            p = _payload(row)
            text = " ".join(str(p.get(k) or "") for k in ("type", "protocol", "message", "summary")).upper()
            if "DHCP" in text:
                value = _valid_host(p.get("server_ip") or p.get("dhcp_server") or p.get("src_ip"))
                if value: current_dhcp[value] += 1
            if "DNS" in text:
                value = _valid_host(p.get("dns_server") or p.get("server_ip") or p.get("dst_ip"))
                if value: current_dns[value] += 1
            if "GATEWAY" in text or "ROUTER ADVERT" in text:
                value = _valid_host(p.get("gateway") or p.get("router") or p.get("src_ip"))
                if value: current_gateway[value] += 1
        old_gw=set(self.gateways); old_dns=set(self.dns); old_dhcp=set(self.dhcp)
        self.gateways.update(current_gateway); self.dns.update(current_dns); self.dhcp.update(current_dhcp)
        self.observations += 1
        learning=self.observations <= 2
        return {
            "engine":"INFRASTRUCTURE_BASELINE_MEMORY",
            "state":"LEARNING" if learning else "ACTIVE",
            "gateway_changes":[] if learning else sorted(set(current_gateway)-old_gw),
            "new_dns_servers":[] if learning else sorted(set(current_dns)-old_dns),
            "new_dhcp_servers":[] if learning else sorted(set(current_dhcp)-old_dhcp),
            "known_gateways":self.gateways.most_common(20),
            "known_dns":self.dns.most_common(20),
            "known_dhcp":self.dhcp.most_common(20),
            "truth_note":"Changes are session-baseline deviations and require infrastructure validation before escalation.",
        }


def sensor_trust(app: FastAPI) -> dict[str, Any]:
    live=_live(app); capture=live.get("capture") if isinstance(live.get("capture"),dict) else {}
    workers=live.get("workers") if isinstance(live.get("workers"),list) else []
    score=100; reasons=[]
    state=str(capture.get("state") or "UNKNOWN").upper()
    if state not in {"ACTIVE","RUNNING","READY"}: score-=45; reasons.append("packet-capture-not-active")
    if not live.get("flows"): score-=20; reasons.append("no-flow-evidence")
    if not live.get("assets"): score-=10; reasons.append("no-asset-evidence")
    failed=0; degraded=0
    for row in workers:
        if not isinstance(row,dict): continue
        s=str(row.get("state") or row.get("status") or "").upper()
        failed += s in {"FAILED","ERROR","STOPPED"}; degraded += s=="DEGRADED"
    score-=min(30,failed*15+degraded*5); score=max(0,score)
    return {"engine":"SENSOR_TRUST","score":score,"state":"TRUSTED" if score>=80 else ("DEGRADED" if score>=45 else "LOW_VISIBILITY"),"failed_workers":failed,"degraded_workers":degraded,"reasons":reasons,"truth_note":"Sensor trust measures telemetry reliability, not security posture."}


def risk_propagation(app: FastAPI) -> dict[str, Any]:
    crown={x.strip() for x in os.environ.get("CAMPUS_OPS_CROWN_JEWELS","").split(",") if x.strip()}
    adjacency:dict[str,set[str]]=defaultdict(set)
    for f in _flows(app):
        s,d=_ends(f)
        if s and d: adjacency[s].add(d); adjacency[d].add(s)
    base=Counter()
    for row in _events(app):
        p=_payload(row); sev=_severity_weight(row.get("severity") or p.get("severity"))
        for key in ("src_ip","dst_ip","ip","target","host"):
            value=_valid_host(p.get(key) or row.get(key))
            if value: base[value]+=sev
    results=[]
    for host,score in base.items():
        visited={host}; q=deque([(host,0)]); crown_reach=[]; exposure=score
        while q:
            node,depth=q.popleft()
            if depth>=3: continue
            for peer in adjacency.get(node,set()):
                if peer in visited: continue
                visited.add(peer); nd=depth+1; q.append((peer,nd))
                exposure += max(1,int(score*(0.35**nd)))
                if peer in crown: crown_reach.append({"asset":peer,"hops":nd})
        if score or crown_reach:
            results.append({"target":host,"direct_risk":min(100,score),"propagated_risk":min(100,exposure),"reachable_nodes":len(visited)-1,"crown_jewel_paths":crown_reach[:20]})
    results.sort(key=lambda x:(x["propagated_risk"],len(x["crown_jewel_paths"])),reverse=True)
    return {"engine":"RISK_PROPAGATION","state":"OBSERVED" if results else "NO_RISK_SIGNALS","findings":results[:100],"truth_note":"Propagation reflects observed communication reach, not exploitability."}


def attack_chain(app: FastAPI) -> dict[str, Any]:
    techniques:dict[str,set[str]]=defaultdict(set)
    for row in _events(app):
        p=_payload(row); text=" ".join(str(x) for x in [row.get("title"),row.get("summary"),row.get("source"),*p.values()]).upper()
        target=_valid_host(p.get("src_ip") or p.get("host") or p.get("target") or p.get("dst_ip"))
        if not target: continue
        if "SCAN" in text or "RECON" in text: techniques[target].add("TA0043 Reconnaissance")
        if any(x in text for x in ("RDP","SMB","WINRM","SSH FANOUT","LATERAL")): techniques[target].add("TA0008 Lateral Movement")
        if any(x in text for x in ("POWERSHELL","SCRIPT","COMMAND")): techniques[target].add("TA0002 Execution")
        if any(x in text for x in ("PERSIST","RUNONCE","SCHEDULED TASK")): techniques[target].add("TA0003 Persistence")
        if any(x in text for x in ("IOC","MALWARE","YARA")): techniques[target].add("TA0005 Defense Evasion / Malicious Artifact Signal")
        if any(x in text for x in ("EXFIL","EGRESS","BEACON")): techniques[target].add("TA0010 Exfiltration / C2 Signal")
    chains=[]
    order=["TA0043 Reconnaissance","TA0002 Execution","TA0003 Persistence","TA0008 Lateral Movement","TA0005 Defense Evasion / Malicious Artifact Signal","TA0010 Exfiltration / C2 Signal"]
    for target,seen in techniques.items():
        seq=[x for x in order if x in seen]
        if seq: chains.append({"target":target,"technique_count":len(seq),"chain":seq,"confidence":min(95,25+len(seq)*12)})
    chains.sort(key=lambda x:(x["technique_count"],x["confidence"]),reverse=True)
    return {"engine":"ATTACK_CHAIN_CORRELATION","state":"OBSERVED" if chains else "NO_CHAIN_EVIDENCE","chains":chains[:100],"truth_note":"ATT&CK labels are behavior mappings, not attribution or compromise proof."}


def incident_promotion(app: FastAPI) -> dict[str, Any]:
    v1=engine_suite(app); v2=depth_engines_v2(app); rp=risk_propagation(app); chain=attack_chain(app); trust=sensor_trust(app)
    evidence:dict[str,dict[str,Any]]=defaultdict(lambda:{"engines":set(),"score":0,"reasons":[]})
    for engine in v1.get("engines",[]):
        for item in engine.get("findings",[]) if isinstance(engine,dict) else []:
            target=_valid_host(item.get("host") or item.get("source") or item.get("src"))
            if target: evidence[target]["engines"].add(engine.get("engine","V1")); evidence[target]["score"]+=min(30,int(item.get("score") or 12)); evidence[target]["reasons"].append(engine.get("engine","V1"))
    for engine in v2.get("engines",[]):
        for item in engine.get("findings",[]) if isinstance(engine,dict) else []:
            target=_valid_host(item.get("host") or item.get("source") or item.get("target") or item.get("src"))
            if target: evidence[target]["engines"].add(engine.get("engine","V2")); evidence[target]["score"]+=min(30,int(item.get("score") or 12)); evidence[target]["reasons"].append(engine.get("engine","V2"))
    for item in rp.get("findings",[]):
        target=item.get("target");
        if target: evidence[target]["engines"].add("RISK_PROPAGATION"); evidence[target]["score"]+=min(30,int(item.get("propagated_risk") or 0)//3)
    for item in chain.get("chains",[]):
        target=item.get("target");
        if target: evidence[target]["engines"].add("ATTACK_CHAIN_CORRELATION"); evidence[target]["score"]+=item.get("technique_count",0)*8
    candidates=[]
    trust_factor=max(0.35,trust["score"]/100)
    for target,row in evidence.items():
        independent=len(row["engines"]); raw=min(100,row["score"]+independent*8); confidence=int(min(100,(25+independent*15)*trust_factor));
        if independent>=2 and raw>=45:
            severity="CRITICAL" if raw>=85 and independent>=4 else ("HIGH" if raw>=65 else "MEDIUM")
            candidates.append({"target":target,"severity":severity,"risk":raw,"confidence":confidence,"independent_engines":independent,"evidence_sources":sorted(row["engines"]),"recommended_action":"CREATE_CASE_AND_TRIAGE" if severity in {"HIGH","CRITICAL"} else "ANALYST_REVIEW"})
    candidates.sort(key=lambda x:(x["risk"],x["confidence"],x["independent_engines"]),reverse=True)
    return {"engine":"INCIDENT_PROMOTION","state":"CANDIDATES" if candidates else "NO_PROMOTION_CANDIDATES","candidates":candidates[:100],"sensor_trust":trust,"truth_note":"Promotion candidates require multiple independent engines; no disruptive response is automatic."}


def depth_v4(app: FastAPI) -> dict[str, Any]:
    infra=app.state.infrastructure_memory.update(app)
    engines=[infra,sensor_trust(app),risk_propagation(app),attack_chain(app),incident_promotion(app)]
    return {"state":"ACTIVE","session_id":app.state.orchestrator.session_id,"engine_count":len(engines),"engines":engines,"contract":"MULTI_SIGNAL_DEFENSIVE_CORRELATION"}


def install_enterprise_depth_v4(app: FastAPI) -> FastAPI:
    if getattr(app.state,"enterprise_depth_v4_installed",False): return app
    app.state.enterprise_depth_v4_installed=True; app.state.infrastructure_memory=InfrastructureMemory()
    @app.get("/api/v1/system/depth-engines-v4")
    async def system_depth_v4()->dict[str,Any]: return depth_v4(app)
    @app.get("/api/v1/system/incidents/promotion-candidates")
    async def promotion_candidates()->dict[str,Any]: return incident_promotion(app)
    @app.get("/api/v1/admin/depth-engines-v4")
    async def admin_depth_v4(request:Request,x_campus_admin:str|None=Header(default=None))->dict[str,Any]:
        _require_admin(app,request,x_campus_admin); return depth_v4(app)
    return app
