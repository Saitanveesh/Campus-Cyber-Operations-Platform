from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    live = snap.get("live")
    return live if isinstance(live, dict) else {}


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [x for x in _live(app).get("flows", []) if isinstance(x, dict)]


def _ends(f: dict[str, Any]) -> tuple[str, str]:
    return (str(f.get("src_ip") or f.get("source") or f.get("src") or ""), str(f.get("dst_ip") or f.get("destination") or f.get("dst") or ""))


def _port(f: dict[str, Any]) -> int | None:
    v = f.get("dst_port") or f.get("dport") or f.get("port")
    try: return int(v)
    except (TypeError, ValueError): return None


def _bytes(f: dict[str, Any]) -> int:
    for k in ("bytes", "byte_count", "bytes_total"):
        try: return max(0, int(f.get(k) or 0))
        except (TypeError, ValueError): pass
    return 0


def _private(v: str) -> bool:
    try: return ipaddress.ip_address(v.split("%",1)[0]).is_private
    except ValueError: return False


def behavior_engine(app: FastAPI) -> dict[str, Any]:
    peers: dict[str, set[str]] = defaultdict(set); ports: dict[str, set[int]] = defaultdict(set); counts=Counter(); volumes=Counter()
    for f in _flows(app):
        s,d=_ends(f)
        if not s or not d: continue
        peers[s].add(d); counts[s]+=1; volumes[s]+=_bytes(f)
        p=_port(f)
        if p is not None: ports[s].add(p)
    rows=[]
    for host,n in counts.items():
        fan=len(peers[host]); diversity=len(ports[host]); score=min(100, fan*3 + diversity*4 + int(math.log2(max(1,n)))*3)
        reasons=[]
        if fan>=20: reasons.append("high-peer-fanout")
        if diversity>=12: reasons.append("high-service-diversity")
        if n>=100: reasons.append("high-flow-volume")
        if score>=35: rows.append({"host":host,"score":score,"flows":n,"peers":fan,"ports":diversity,"bytes":volumes[host],"reasons":reasons})
    rows.sort(key=lambda x:x["score"], reverse=True)
    return {"engine":"BEHAVIOR_ANALYTICS","state":"OBSERVED" if rows else "BASELINE","findings":rows[:100],"truth_note":"Session-relative behavioral heuristics; findings are investigation candidates."}


def lateral_engine(app: FastAPI) -> dict[str, Any]:
    admin={22:"SSH",23:"TELNET",135:"RPC",139:"NETBIOS",445:"SMB",3389:"RDP",5985:"WINRM",5986:"WINRM_TLS",5900:"VNC"}; bysrc:dict[str,list[dict[str,Any]]]=defaultdict(list)
    for f in _flows(app):
        s,d=_ends(f); p=_port(f)
        if s and d and p in admin and _private(s) and _private(d): bysrc[s].append({"dst":d,"port":p,"service":admin[p]})
    findings=[]
    for src,rels in bysrc.items():
        hosts={r["dst"] for r in rels}; services={r["service"] for r in rels}; score=min(100,len(hosts)*8+len(services)*7)
        if len(hosts)>=3: findings.append({"source":src,"score":score,"destination_count":len(hosts),"services":sorted(services),"relationships":rels[:50]})
    findings.sort(key=lambda x:x["score"], reverse=True)
    return {"engine":"LATERAL_MOVEMENT_ANALYTICS","state":"OBSERVED" if findings else "NO_STRONG_PATTERN","findings":findings[:100],"truth_note":"Administrative east-west fan-out is not itself proof of malicious lateral movement."}


def exfil_engine(app: FastAPI) -> dict[str, Any]:
    agg:dict[tuple[str,str],dict[str,Any]]={}
    for f in _flows(app):
        s,d=_ends(f)
        if not s or not d or not _private(s) or _private(d): continue
        k=(s,d); row=agg.setdefault(k,{"src":s,"dst":d,"bytes":0,"flows":0,"ports":Counter()}); row["bytes"]+=_bytes(f); row["flows"]+=1
        p=_port(f)
        if p is not None: row["ports"][p]+=1
    out=[]
    for row in agg.values():
        score=min(100,int(math.log2(max(1,row["bytes"]+1))*4)+min(25,row["flows"]//5));
        if row["bytes"]>=1_000_000 or row["flows"]>=50: out.append({**{k:v for k,v in row.items() if k!="ports"},"score":score,"ports":[p for p,_ in row["ports"].most_common(8)]})
    out.sort(key=lambda x:(x["score"],x["bytes"]),reverse=True)
    return {"engine":"EGRESS_EXFIL_ANALYTICS","state":"OBSERVED" if out else "NO_STRONG_PATTERN","findings":out[:100],"truth_note":"Outbound volume is a triage signal, not an exfiltration verdict."}


def service_graph_engine(app: FastAPI) -> dict[str, Any]:
    edges=Counter(); nodes=Counter()
    for f in _flows(app):
        s,d=_ends(f); p=_port(f)
        if not s or not d: continue
        service=str(f.get("service") or f.get("application") or (f"tcp/{p}" if p else "unknown")); edges[(s,d,service)]+=1; nodes[s]+=1; nodes[d]+=1
    return {"engine":"SERVICE_DEPENDENCY_GRAPH","state":"OBSERVED" if edges else "NO_FLOW_EVIDENCE","critical_nodes":[{"node":n,"degree":c} for n,c in nodes.most_common(50)],"edges":[{"source":s,"target":d,"service":svc,"observations":c} for (s,d,svc),c in edges.most_common(250)]}


def engine_suite(app: FastAPI) -> dict[str, Any]:
    engines=[behavior_engine(app),lateral_engine(app),exfil_engine(app),service_graph_engine(app)]
    return {"state":"ACTIVE","engine_count":len(engines),"engines":engines,"contract":"EVIDENCE_DRIVEN_DEFENSIVE_ANALYTICS","session_id":app.state.orchestrator.session_id}


def install_depth_engines(app: FastAPI) -> FastAPI:
    if getattr(app.state,"depth_engines_installed",False): return app
    app.state.depth_engines_installed=True
    @app.get("/api/v1/system/depth-engines")
    async def depth_engines() -> dict[str,Any]: return engine_suite(app)
    @app.get("/api/v1/admin/depth-engines")
    async def admin_depth_engines(request:Request,x_campus_admin:str|None=Header(default=None))->dict[str,Any]:
        _require_admin(app,request,x_campus_admin); return engine_suite(app)
    return app
