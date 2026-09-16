from __future__ import annotations

import ipaddress
from typing import Any


def _contains_ip(value: object, target: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_ip(item, target) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_ip(item, target) for item in value)
    return str(value or "").strip() == target


def _network_values(network: dict[str, Any], key: str) -> list[str]:
    raw = network.get(key)
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    if raw:
        return [str(raw).strip()]
    return []


def _is_local_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, network: dict[str, Any]) -> bool:
    for prefix in _network_values(network, "prefixes"):
        try:
            if ip in ipaddress.ip_network(prefix, strict=False):
                return True
        except ValueError:
            continue
    local_addresses = set(_network_values(network, "ipv4") + _network_values(network, "ipv6"))
    return str(ip) in local_addresses


def assess_target_truth(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    """Classify an address using current passive MON evidence only."""
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ValueError("special-purpose IP addresses are not investigation targets")

    target = str(ip)
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    assets = [item for item in live.get("assets", []) if isinstance(item, dict)]
    flows = [item for item in live.get("flows", []) if isinstance(item, dict)]
    edges = [item for item in live.get("topology_edges", []) if isinstance(item, dict)]
    packets = [item for item in live.get("packet_feed", []) if isinstance(item, dict)]
    alerts = [item for item in live.get("alerts", []) if isinstance(item, dict)]
    incidents = [item for item in live.get("incidents", []) if isinstance(item, dict)]

    asset = next((item for item in assets if str(item.get("ip") or "") == target), None)
    flow_count = sum(
        1 for item in flows if target in {str(item.get("src") or ""), str(item.get("dst") or "")}
    )
    edge_count = sum(
        1
        for item in edges
        if target in {str(item.get("source") or ""), str(item.get("target") or "")}
    )
    packet_count = sum(1 for item in packets if _contains_ip(item.get("payload"), target))
    alert_count = sum(1 for item in alerts if _contains_ip(item, target))
    incident_count = sum(1 for item in incidents if _contains_ip(item, target))

    local = _is_local_address(ip, network)
    gateway = str(network.get("gateway") or "").strip() == target
    self_addresses = set(_network_values(network, "ipv4") + _network_values(network, "ipv6"))
    is_self = target in self_addresses
    observed = bool(asset or flow_count or edge_count or packet_count or alert_count or incident_count)
    confirmed_local = bool(
        asset
        and local
        and str(asset.get("confidence") or "").upper() == "HIGH"
        and str(asset.get("evidence") or "") == "CONFIRMED_LOCAL_SOURCE_FRAMES"
    )

    if confirmed_local:
        status = "CONFIRMED_LOCAL_ASSET"
    elif observed:
        status = "OBSERVED_PEER"
    else:
        status = "NOT_OBSERVED"

    evidence = {
        "asset": bool(asset),
        "flows": flow_count,
        "topology_edges": edge_count,
        "recent_packets": packet_count,
        "alerts": alert_count,
        "incidents": incident_count,
    }
    evidence_sources = sum(
        1
        for value in evidence.values()
        if (isinstance(value, bool) and value) or (isinstance(value, int) and value > 0)
    )
    return {
        "target": target,
        "status": status,
        "observed": observed,
        "local_scope": local,
        "confirmed_local_asset": confirmed_local,
        "is_monitor_host": is_self,
        "is_gateway": gateway,
        "asset": asset,
        "evidence": evidence,
        "evidence_sources": evidence_sources,
        "claim": "CURRENT_SESSION_PASSIVE_EVIDENCE_ONLY",
    }
