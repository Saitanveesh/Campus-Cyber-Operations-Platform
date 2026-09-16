from __future__ import annotations

import ipaddress
from typing import Any


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


def build_investigation(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    """Build a passive report from current-session MON evidence only."""
    ip = _valid_target(target)
    target = str(ip)
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}

    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    asset = next((item for item in assets if str(item.get("ip") or "") == target), None)
    flows = [
        item
        for item in live.get("flows", [])
        if isinstance(item, dict)
        and (str(item.get("src") or "") == target or str(item.get("dst") or "") == target)
    ]
    flows.sort(
        key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))),
        reverse=True,
    )
    edges = [
        item
        for item in live.get("topology_edges", [])
        if isinstance(item, dict)
        and (str(item.get("source") or "") == target or str(item.get("target") or "") == target)
    ]
    edges.sort(
        key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))),
        reverse=True,
    )
    alerts = [
        item
        for item in live.get("alerts", [])
        if isinstance(item, dict) and _contains_ip(item, target)
    ]
    incidents = [
        item
        for item in live.get("incidents", [])
        if isinstance(item, dict) and _contains_ip(item, target)
    ]
    packets = [
        item
        for item in live.get("packet_feed", [])
        if isinstance(item, dict) and _contains_ip(item.get("payload"), target)
    ][:50]

    peers: dict[str, int] = {}
    services: dict[str, int] = {}
    applications: dict[str, int] = {}
    total_packets = 0
    total_bytes = 0
    observed_bps = 0.0
    for flow in flows:
        count = int(_number(flow.get("packets")))
        total_packets += count
        total_bytes += int(_number(flow.get("bytes")))
        observed_bps += _number(flow.get("bps_ewma"))
        peer = str(
            flow.get("dst") if str(flow.get("src") or "") == target else flow.get("src") or ""
        )
        if peer:
            peers[peer] = peers.get(peer, 0) + count
        port = str(flow.get("dst_port") or "")
        protocol = str(flow.get("protocol") or flow.get("transport") or "").upper()
        if port:
            key = f"{protocol}/{port}" if protocol else port
            services[key] = services.get(key, 0) + 1
        application = str(
            flow.get("tls_sni") or flow.get("dns_query") or flow.get("http_host") or ""
        )
        if application:
            applications[application] = applications.get(application, 0) + 1

    open_incidents = [
        item for item in incidents if str(item.get("status") or "OPEN").upper() != "CLOSED"
    ]
    risk_score = 40 if alerts else 0
    reasons: list[str] = []
    if alerts:
        reasons.append(f"{len(alerts)} current alert record(s)")
    severity_rank = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 20, "INFO": 0}
    for incident in open_incidents:
        risk_score = max(
            risk_score,
            severity_rank.get(str(incident.get("severity") or "INFO").upper(), 0),
        )
    if open_incidents:
        reasons.append(f"{len(open_incidents)} open incident record(s)")

    if risk_score >= 80:
        assessment = "HIGH ATTENTION"
    elif risk_score >= 50:
        assessment = "REVIEW"
    elif risk_score >= 20:
        assessment = "WATCH"
    else:
        assessment = "NO STRONG CURRENT INDICATORS"

    return {
        "target": target,
        "scope": "PRIVATE_OR_LOCAL" if ip.is_private else "PUBLIC",
        "session_id": snapshot.get("session_id"),
        "observed": bool(asset or flows or edges or alerts or incidents or packets),
        "asset": asset,
        "flows": flows[:100],
        "topology_edges": edges[:100],
        "alerts": alerts[:100],
        "incidents": incidents[:50],
        "recent_packets": packets,
        "risk": {
            "score": risk_score,
            "assessment": assessment,
            "reasons": reasons[:12],
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
            "top_applications": sorted(
                applications.items(), key=lambda item: item[1], reverse=True
            )[:12],
        },
        "operator_mode": "PASSIVE_ONLY",
    }
