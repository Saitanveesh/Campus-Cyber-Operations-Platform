from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.correlation_fabric import correlation_fabric
from campus_ops.depth_engines import engine_suite


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    value = snap.get("live")
    return value if isinstance(value, dict) else {}


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [x for x in _live(app).get("flows", []) if isinstance(x, dict)]


def _events(app: FastAPI) -> list[dict[str, Any]]:
    live = _live(app); out=[]
    for key in ("events","alerts","incidents","packet_feed"):
        rows=live.get(key)
        if isinstance(rows,list): out.extend(x for x in rows if isinstance(x,dict))
    return out


def _ends(flow: dict[str, Any]) -> tuple[str, str]:
    return (str(flow.get("src_ip") or flow.get("src") or flow.get("source") or "").strip(), str(flow.get("dst_ip") or flow.get("dst") or flow.get("destination") or "").strip())


def _port(flow: dict[str, Any]) -> int | None:
    value=flow.get("dst_port") or flow.get("dport") or flow.get("port")
    try: return int(value)
    except (TypeError,ValueError): return None


def _private(value: str) -> bool:
    try: return ipaddress.ip_address(value.split("%",1)[0]).is_private
    except ValueError: return False


def _ts(value: object) -> float | None:
    if isinstance(value,(int,float)): return float(value)
    text=str(value or "").strip()
    if not text: return None
    try: return datetime.fromisoformat(text.replace("Z","+00:00")).timestamp()
    except ValueError: return None


def beacon_engine(app: FastAPI) -> dict[str, Any]:
    groups: dict[tuple[str,str,int|None], list[dict[str,Any]]] = defaultdict(list)
    for flow in _flows(app):
        s,d=_ends(flow); p=_port(flow)
        if s and d and _private(s) and not _private(d): groups[(s,d,p)].append(flow)
    findings=[]
    for (src,dst,port),rows in groups.items():
        intervals=[]
        times=sorted(t for row in rows for t in [_ts(row.get("last_seen") or row.get("timestamp") or row.get("ts"))] if t is not None)
        for a,b in zip(times,times[1:]):
            if b>a: intervals.append(b-a)
        count=sum(int(row.get("packets") or row.get("flow_count") or 1) for row in rows)
        duration=max(0.0,(max(times)-min(times))) if len(times)>=2 else 0.0
        periodicity=None
        if len(intervals)>=3:
            avg=sum(intervals)/len(intervals); var=sum((x-avg)**2 for x in intervals)/len(intervals); cv=(math.sqrt(var)/avg) if avg else 99.0
            periodicity=max(0,min(100,round((1-min(cv,1))*100)))
        score=min(100,(25 if len(rows)>=4 else 0)+(25 if count>=20 else 0)+(25 if duration>=60 else 0)+(periodicity or 0)//4)
        if score>=45:
            findings.append({"src":src,"dst":dst,"port":port,"score":score,"observations":len(rows),"packets":count,"duration_seconds":round(duration,1),"periodicity":periodicity,"evidence":"CURRENT_SESSION_FLOW"})
    findings.sort(key=lambda x:x["score"],reverse=True)
    return {"engine":"BEACON_PERIODICITY","state":"OBSERVED" if findings else "NO_STRONG_PATTERN","findings":findings[:100],"truth_note":"Periodicity is a behavioral lead, not a command-and-control verdict."}


def identity_integrity_engine(app: FastAPI) -> dict[str, Any]:
    ip_to_macs:dict[str,set[str]]=defaultdict(set); mac_to_ips:dict[str,set[str]]=defaultdict(set); findings=[]
    for asset in _live(app).get("assets",[]):
        if not isinstance(asset,dict): continue
        ip=str(asset.get("ip") or asset.get("address") or "").strip(); mac=str(asset.get("mac") or asset.get("mac_address") or "").lower().strip()
        if ip and mac:
            ip_to_macs[ip].add(mac); mac_to_ips[mac].add(ip)
    for ip,macs in ip_to_macs.items():
        if len(macs)>1: findings.append({"type":"IP_MULTI_MAC","ip":ip,"macs":sorted(macs),"severity":"MEDIUM","confidence":"MEDIUM"})
    for mac,ips in mac_to_ips.items():
        if len(ips)>3: findings.append({"type":"MAC_MULTI_IP","mac":mac,"ips":sorted(ips),"severity":"LOW","confidence":"LOW"})
    for event in _events(app):
        payload=event.get("payload") if isinstance(event.get("payload"),dict) else {}
        text=" ".join(str(x) for x in [event.get("title"),event.get("summary"),payload.get("type"),payload.get("message")]).upper()
        if "ARP" in text and any(k in text for k in ("CHANGE","CONFLICT","DUPLICATE","SPOOF")):
            src=str(payload.get("src_ip") or payload.get("ip") or "").strip()
            if src not in {"","0.0.0.0"}: findings.append({"type":"ARP_IDENTITY_CHANGE","ip":src,"severity":str(event.get("severity") or "MEDIUM"),"confidence":"EVIDENCE_BACKED","source":event.get("source")})
    return {"engine":"IDENTITY_INTEGRITY","state":"OBSERVED" if findings else "STABLE_OR_NO_EVIDENCE","findings":findings[:100],"truth_note":"DHCP churn, HA, virtualization and legitimate address movement can produce identity changes."}


def protocol_misuse_engine(app: FastAPI) -> dict[str, Any]:
    risky={21:"FTP",23:"TELNET",69:"TFTP",111:"RPCBIND",137:"NETBIOS_NS",139:"NETBIOS",161:"SNMP",389:"LDAP",445:"SMB",5900:"VNC"}; counts=Counter(); examples=defaultdict(list)
    for f in _flows(app):
        s,d=_ends(f); p=_port(f)
        if p in risky:
            key=(s,d,p); counts[key]+=1
            if len(examples[p])<20: examples[p].append({"src":s,"dst":d})
    findings=[]
    byport=Counter()
    for (_s,_d,p),c in counts.items(): byport[p]+=c
    for p,c in byport.most_common():
        severity="MEDIUM" if p in {21,23,69,5900} else "LOW"
        findings.append({"port":p,"protocol":risky[p],"observations":c,"severity":severity,"examples":examples[p],"interpretation":"Observed use requires role/policy validation; protocol presence alone is not malicious."})
    return {"engine":"PROTOCOL_POLICY_ANALYTICS","state":"OBSERVED" if findings else "NO_RISKY_PROTOCOL_EVIDENCE","findings":findings}


def tcp_health_engine(app: FastAPI) -> dict[str, Any]:
    totals=Counter(); bad=Counter(); examples=[]
    for f in _flows(app):
        proto=str(f.get("transport") or f.get("protocol") or "").upper()
        if "TCP" not in proto: continue
        totals["flows"]+=1
        metrics={
            "retransmissions":f.get("retransmissions") or f.get("tcp_retransmissions") or 0,
            "resets":f.get("resets") or f.get("tcp_resets") or 0,
            "zero_windows":f.get("zero_windows") or f.get("tcp_zero_windows") or 0,
            "syn_failures":f.get("syn_failures") or f.get("tcp_syn_failures") or 0,
        }
        row_bad=0
        for k,v in metrics.items():
            try: n=int(v or 0)
            except (TypeError,ValueError): n=0
            bad[k]+=n; row_bad+=n
        if row_bad and len(examples)<50:
            s,d=_ends(f); examples.append({"src":s,"dst":d,"port":_port(f),**metrics})
    state="OBSERVED" if sum(bad.values()) else ("NO_DEEP_TCP_METRICS" if totals["flows"] else "NO_TCP_EVIDENCE")
    return {"engine":"TCP_HEALTH","state":state,"tcp_flows":totals["flows"],"metrics":dict(bad),"examples":examples,"truth_note":"Detailed retransmission/reset visibility depends on capture/backend fields."}


def role_inference_engine(app: FastAPI) -> dict[str, Any]:
    inbound=Counter(); outbound=Counter(); services=defaultdict(Counter); peers=defaultdict(set)
    for f in _flows(app):
        s,d=_ends(f); p=_port(f)
        if not s or not d: continue
        outbound[s]+=1; inbound[d]+=1; peers[s].add(d); peers[d].add(s)
        if p is not None: services[d][p]+=1
    roles=[]
    for host in set(inbound)|set(outbound):
        svc=services[host]; labels=[]; confidence=20
        if svc[53]>=5: labels.append("DNS_SERVER_CANDIDATE"); confidence+=20
        if svc[67]>=3 or svc[68]>=3: labels.append("DHCP_SERVICE_CANDIDATE"); confidence+=15
        if svc[445]>=5: labels.append("FILE_SERVICE_CANDIDATE"); confidence+=15
        if svc[80]+svc[443]+svc[8080]+svc[8443]>=10: labels.append("WEB_SERVICE_CANDIDATE"); confidence+=20
        if inbound[host]>=20 and len(peers[host])>=10: labels.append("SHARED_SERVICE_CANDIDATE"); confidence+=15
        if not labels and outbound[host]>inbound[host]*2: labels.append("CLIENT_CANDIDATE"); confidence+=10
        roles.append({"host":host,"roles":labels or ["UNKNOWN"],"confidence":min(85,confidence),"inbound_flows":inbound[host],"outbound_flows":outbound[host],"peer_count":len(peers[host])})
    roles.sort(key=lambda x:x["confidence"],reverse=True)
    return {"engine":"ROLE_INFERENCE","state":"OBSERVED" if roles else "NO_FLOW_EVIDENCE","assets":roles[:250],"truth_note":"Roles are hypotheses from observed communication, not authoritative CMDB labels."}


def attack_mapping_engine(app: FastAPI) -> dict[str, Any]:
    techniques=[]; lateral=engine_suite(app)["engines"][1]; beacon=beacon_engine(app); recon=correlation_fabric(app).get("recon") or {}
    if lateral.get("findings"):
        techniques.append({"technique":"Remote Services / Lateral Movement Pattern","framework_hint":"ATT&CK T1021 family","evidence_count":len(lateral["findings"]),"confidence":"MEDIUM"})
    if beacon.get("findings"):
        techniques.append({"technique":"Periodic External Communication","framework_hint":"Command-and-Control behavioral indicator","evidence_count":len(beacon["findings"]),"confidence":"LOW_TO_MEDIUM"})
    if recon.get("findings"):
        techniques.append({"technique":"Network Service Discovery Pattern","framework_hint":"ATT&CK T1046-like behavior","evidence_count":len(recon["findings"]),"confidence":"MEDIUM"})
    return {"engine":"ATTACK_TECHNIQUE_MAPPING","state":"MAPPED" if techniques else "NO_MAPPING","techniques":techniques,"truth_note":"Mappings describe behavior similarity and are not attribution or compromise proof."}


def incident_fusion_engine(app: FastAPI) -> dict[str, Any]:
    corr=correlation_fabric(app); depth=engine_suite(app); beacon=beacon_engine(app); integrity=identity_integrity_engine(app); proto=protocol_misuse_engine(app)
    per_target=defaultdict(lambda:{"score":0,"sources":set(),"reasons":[]})
    for e in depth.get("engines",[]):
        for f in e.get("findings",[]):
            target=str(f.get("host") or f.get("source") or f.get("src") or "")
            if not target: continue
            score=int(f.get("score") or 25); per_target[target]["score"]+=min(35,score//2); per_target[target]["sources"].add(e.get("engine")); per_target[target]["reasons"].append(e.get("engine"))
    for f in beacon.get("findings",[]):
        t=str(f.get("src") or "")
        if t: per_target[t]["score"]+=20; per_target[t]["sources"].add("BEACON_PERIODICITY"); per_target[t]["reasons"].append("periodic-external-communication")
    for f in integrity.get("findings",[]):
        t=str(f.get("ip") or "")
        if t: per_target[t]["score"]+=20; per_target[t]["sources"].add("IDENTITY_INTEGRITY"); per_target[t]["reasons"].append(f.get("type"))
    incidents=[]
    for target,row in per_target.items():
        independent=len(row["sources"]); score=min(100,row["score"]+max(0,independent-1)*8)
        if score<40: continue
        severity="CRITICAL" if score>=85 else "HIGH" if score>=70 else "MEDIUM"
        confidence="HIGH" if independent>=4 else "MEDIUM" if independent>=2 else "LOW"
        incidents.append({"target":target,"risk_score":score,"severity":severity,"confidence":confidence,"independent_engines":independent,"evidence_sources":sorted(row["sources"]),"reasons":row["reasons"][:20],"status":"FUSED_CANDIDATE"})
    incidents.sort(key=lambda x:x["risk_score"],reverse=True)
    return {"engine":"INCIDENT_FUSION","state":"OBSERVED" if incidents else "NO_FUSED_INCIDENTS","incidents":incidents[:100],"protocol_context":proto.get("findings",[])[:20],"truth_note":"Fusion raises priority only when multiple defensive analytics align; operator validation remains required."}


def full_depth_v2(app: FastAPI) -> dict[str, Any]:
    engines=[beacon_engine(app),identity_integrity_engine(app),protocol_misuse_engine(app),tcp_health_engine(app),role_inference_engine(app),attack_mapping_engine(app),incident_fusion_engine(app)]
    return {"state":"ACTIVE","session_id":app.state.orchestrator.session_id,"engine_count":len(engines),"engines":engines,"contract":"DEFENSIVE_EVIDENCE_FUSION"}


def install_depth_engines_v2(app: FastAPI) -> FastAPI:
    if getattr(app.state,"depth_engines_v2_installed",False): return app
    app.state.depth_engines_v2_installed=True
    @app.get("/api/v1/system/depth-engines-v2")
    async def system_depth_engines_v2()->dict[str,Any]: return full_depth_v2(app)
    @app.get("/api/v1/system/incidents/fused")
    async def system_fused_incidents()->dict[str,Any]: return incident_fusion_engine(app)
    @app.get("/api/v1/admin/depth-engines-v2")
    async def admin_depth_engines_v2(request:Request,x_campus_admin:str|None=Header(default=None))->dict[str,Any]:
        _require_admin(app,request,x_campus_admin); return full_depth_v2(app)
    return app
