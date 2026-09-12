from __future__ import annotations

import asyncio
import ipaddress
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from campus_ops.policy import Role
from campus_ops.tooling.registry import resolve_executable


class DeepProbeRequest(BaseModel):
    authorized: bool = False
    include_services: bool = True


def _valid_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ValueError("special-purpose IP addresses are not investigation targets")
    return ip


def _contains_ip(value: object, target: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_ip(item, target) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_ip(item, target) for item in value)
    return str(value or "").strip() == target


def _number(value: object) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _agent_for_ip(agents: list[dict[str, Any]], target: str) -> dict[str, Any] | None:
    for agent in agents:
        telemetry = agent.get("telemetry") if isinstance(agent.get("telemetry"), dict) else {}
        addresses = telemetry.get("network_addresses")
        if not isinstance(addresses, list):
            continue
        for item in addresses:
            if isinstance(item, dict) and str(item.get("address") or "") == target:
                return agent
    return None


def _risk_node(metrics: dict[str, Any], target: str) -> dict[str, Any] | None:
    graph = metrics.get("risk_graph") if isinstance(metrics.get("risk_graph"), dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    for item in nodes:
        if isinstance(item, dict) and str(item.get("id") or "") == target:
            return item
    return None


def build_investigation(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    ip = _valid_target(target)
    target = str(ip)
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    metrics = live.get("metrics") if isinstance(live.get("metrics"), dict) else {}

    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    asset = next((item for item in assets if str(item.get("ip") or "") == target), None)

    flows = [
        item
        for item in live.get("flows", [])
        if isinstance(item, dict)
        and (str(item.get("src") or "") == target or str(item.get("dst") or "") == target)
    ]
    flows.sort(key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))), reverse=True)

    edges = [
        item
        for item in live.get("topology_edges", [])
        if isinstance(item, dict)
        and (str(item.get("source") or "") == target or str(item.get("target") or "") == target)
    ]
    edges.sort(key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))), reverse=True)

    alerts = [
        item
        for item in live.get("alerts", [])
        if isinstance(item, dict) and _contains_ip(item, target)
    ]
    incidents = [
        item
        for item in live.get("incidents", [])
        if isinstance(item, dict)
        and (
            str(item.get("source") or "") == target
            or _contains_ip(item.get("latest_evidence"), target)
            or _contains_ip(item.get("timeline"), target)
        )
    ]
    incidents.sort(
        key=lambda item: (
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(
                str(item.get("severity") or "INFO").upper(), 0
            ),
            str(item.get("last_seen") or ""),
        ),
        reverse=True,
    )

    packets = [
        item
        for item in live.get("packet_feed", [])
        if isinstance(item, dict) and _contains_ip(item.get("payload"), target)
    ][:50]

    agents = [item for item in snapshot.get("managed_agents", []) if isinstance(item, dict)]
    agent = _agent_for_ip(agents, target)
    risk = _risk_node(metrics, target)

    services: dict[str, int] = {}
    applications: dict[str, int] = {}
    peers: dict[str, int] = {}
    total_packets = 0
    total_bytes = 0
    observed_bps = 0.0
    for flow in flows:
        total_packets += int(_number(flow.get("packets")))
        total_bytes += int(_number(flow.get("bytes")))
        observed_bps += _number(flow.get("bps_ewma"))
        peer = str(
            flow.get("dst") if str(flow.get("src") or "") == target else flow.get("src") or ""
        )
        if peer:
            peers[peer] = peers.get(peer, 0) + int(_number(flow.get("packets")))
        port = str(flow.get("dst_port") or "")
        protocol = str(flow.get("protocol") or flow.get("transport") or "").upper()
        if port:
            key = f"{protocol}/{port}" if protocol else port
            services[key] = services.get(key, 0) + 1
        app = str(flow.get("tls_sni") or flow.get("dns_query") or flow.get("http_host") or "")
        if app:
            applications[app] = applications.get(app, 0) + 1

    risk_score = int(_number((risk or {}).get("risk")))
    reasons: list[str] = [str(item) for item in (risk or {}).get("reasons", []) if item]
    open_incidents = [
        item for item in incidents if str(item.get("status") or "OPEN").upper() != "CLOSED"
    ]
    critical = sum(
        1 for item in open_incidents if str(item.get("severity") or "").upper() == "CRITICAL"
    )
    high = sum(1 for item in open_incidents if str(item.get("severity") or "").upper() == "HIGH")
    if critical:
        risk_score = max(risk_score, 90)
        reasons.append(f"{critical} open critical incident(s)")
    if high:
        risk_score = max(risk_score, 70)
        reasons.append(f"{high} open high-severity incident(s)")
    if alerts and risk_score < 40:
        risk_score = 40
        reasons.append(f"{len(alerts)} current alert record(s)")

    if risk_score >= 80:
        assessment = "HIGH ATTENTION"
    elif risk_score >= 50:
        assessment = "REVIEW"
    elif risk_score >= 20:
        assessment = "WATCH"
    else:
        assessment = "NO STRONG CURRENT INDICATORS"

    tools = [item for item in snapshot.get("tools", []) if isinstance(item, dict)]
    tool_map = {str(item.get("key")): bool(item.get("available")) for item in tools}

    return {
        "target": target,
        "scope": "PRIVATE_OR_LOCAL" if ip.is_private else "PUBLIC",
        "session_id": snapshot.get("session_id"),
        "asset": asset,
        "managed_agent": agent,
        "manageable": bool(agent),
        "flows": flows[:100],
        "topology_edges": edges[:100],
        "alerts": alerts[:100],
        "incidents": incidents[:50],
        "recent_packets": packets,
        "risk": {
            "score": min(100, risk_score),
            "assessment": assessment,
            "reasons": list(dict.fromkeys(reasons))[:12],
            "claim": "EVIDENCE_BASED_PRIORITY_NOT_MALICIOUS_VERDICT",
        },
        "summary": {
            "flow_count": len(flows),
            "peer_count": len(peers),
            "alert_count": len(alerts),
            "incident_count": len(incidents),
            "open_incident_count": len(open_incidents),
            "packets": total_packets,
            "bytes": total_bytes,
            "observed_bps": observed_bps,
            "top_peers": sorted(peers.items(), key=lambda item: item[1], reverse=True)[:12],
            "top_services": sorted(services.items(), key=lambda item: item[1], reverse=True)[:12],
            "top_applications": sorted(applications.items(), key=lambda item: item[1], reverse=True)[:12],
        },
        "forensic_tools": {
            "nmap": tool_map.get("nmap", False),
            "tshark": tool_map.get("tshark", False),
            "dumpcap": tool_map.get("dumpcap", False),
            "suricata": tool_map.get("suricata", False),
            "yara": tool_map.get("yara", False),
            "sysmon": tool_map.get("sysmon", False),
            "osquery": tool_map.get("osquery", False),
            "hayabusa": tool_map.get("hayabusa", False),
            "chainsaw": tool_map.get("chainsaw", False),
        },
    }


def _run_command(command: list[str], timeout: float) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "ERROR", "exit_code": None, "output": str(exc)}
    output = (result.stdout or result.stderr or "No output returned.").strip()
    return {
        "status": "PASS" if result.returncode == 0 else "ERROR",
        "exit_code": result.returncode,
        "output": output[:24000],
    }


def deep_probe(target: str, include_services: bool) -> dict[str, object]:
    ip = _valid_target(target)
    if not ip.is_private:
        raise PermissionError("active deep probe is restricted to private lab IP addresses")
    target = str(ip)
    results: dict[str, object] = {}

    powershell = resolve_executable("powershell") or resolve_executable("pwsh")
    if powershell:
        neighbor_script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"Get-NetNeighbor -IPAddress '{target}' | "
            "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | Format-List"
        )
        results["neighbor"] = _run_command(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", neighbor_script], 8
        )
        dns_script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"Resolve-DnsName -Name '{target}' -Type PTR | "
            "Select-Object NameHost,Name,Type | Format-List"
        )
        results["reverse_dns"] = _run_command(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", dns_script], 8
        )

    ping = resolve_executable("ping")
    if ping:
        results["reachability"] = _run_command([ping, "-n", "2", "-w", "800", target], 5)

    tracert = resolve_executable("tracert")
    if tracert:
        results["route_trace"] = _run_command(
            [tracert, "-d", "-h", "8", "-w", "700", target], 10
        )

    if include_services:
        nmap = resolve_executable("nmap")
        if nmap:
            results["service_probe"] = _run_command(
                [
                    nmap,
                    "-sT",
                    "-sV",
                    "--version-light",
                    "--top-ports",
                    "30",
                    "-T3",
                    "--host-timeout",
                    "35s",
                    "-n",
                    target,
                ],
                45,
            )
        else:
            results["service_probe"] = {
                "status": "UNAVAILABLE",
                "exit_code": None,
                "output": "Nmap is not installed or not discoverable.",
            }

    return {
        "target": target,
        "scope": "AUTHORIZED_PRIVATE_LAB_ONLY",
        "results": results,
    }


def _target_agent(orchestrator: Any, target: str) -> tuple[str, dict[str, Any]]:
    investigation = build_investigation(orchestrator.snapshot(), target)
    agent = investigation.get("managed_agent")
    if not isinstance(agent, dict) or not agent.get("endpoint_id"):
        raise LookupError("this IP is not backed by an enrolled endpoint agent")
    return str(agent["endpoint_id"]), investigation


def install_investigation_routes(app: FastAPI) -> FastAPI:
    if getattr(app.state, "investigation_routes_installed", False):
        return app
    app.state.investigation_routes_installed = True

    @app.get("/api/v1/investigate/{target}")
    async def investigate(target: str) -> dict[str, object]:
        try:
            return build_investigation(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/investigate/{target}/deep-probe")
    async def investigate_deep_probe(target: str, request: DeepProbeRequest) -> dict[str, object]:
        if not request.authorized:
            raise HTTPException(status_code=403, detail="explicit lab authorization is required")
        try:
            return await asyncio.to_thread(deep_probe, target, request.include_services)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/investigate/{target}/snapshot")
    async def investigate_snapshot(target: str) -> dict[str, object]:
        orchestrator = app.state.orchestrator
        try:
            endpoint_id, investigation = _target_agent(orchestrator, target)
            job = await orchestrator.response.queue(
                endpoint_id=endpoint_id,
                action="COLLECT_SNAPSHOT",
                role=Role.INCIDENT_RESPONDER,
                operator="investigation-center",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"job": job, "target": investigation["target"]}

    @app.post("/api/v1/investigate/{target}/isolate")
    async def investigate_isolate(target: str) -> dict[str, object]:
        orchestrator = app.state.orchestrator
        try:
            endpoint_id, investigation = _target_agent(orchestrator, target)
            job = await orchestrator.response.queue(
                endpoint_id=endpoint_id,
                action="ISOLATE_HOST",
                role=Role.LAB_ADMINISTRATOR,
                operator="investigation-center",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"job": job, "target": investigation["target"]}

    @app.post("/api/v1/investigate/{target}/restore")
    async def investigate_restore(target: str) -> dict[str, object]:
        orchestrator = app.state.orchestrator
        try:
            endpoint_id, investigation = _target_agent(orchestrator, target)
            job = await orchestrator.response.queue(
                endpoint_id=endpoint_id,
                action="RESTORE_NETWORK",
                role=Role.LAB_ADMINISTRATOR,
                operator="investigation-center",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"job": job, "target": investigation["target"]}

    return app
