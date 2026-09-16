from __future__ import annotations

import ipaddress
from typing import Any


def _networks(context: dict[str, Any] | None) -> list[ipaddress._BaseNetwork]:
    if not isinstance(context, dict):
        return []
    result: list[ipaddress._BaseNetwork] = []
    for raw in context.get("prefixes", ()) or ():
        try:
            result.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            continue
    return result


def endpoint_role(value: object, context: dict[str, Any] | None) -> str:
    """Classify one packet-observed IP relative to MON's selected network.

    This function classifies evidence; it never creates an asset. Asset promotion still
    requires repeated source frames and a valid unicast source MAC in AssetEngineWorker.
    """
    raw = str(value or "").strip().split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return "UNKNOWN"

    if ip.is_unspecified or ip.is_loopback:
        return "SPECIAL_ADDRESS"
    if ip.is_multicast:
        return "MULTICAST"
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return "BROADCAST"

    context = context if isinstance(context, dict) else {}
    local_values = {
        str(item).split("%", 1)[0]
        for key in ("ipv4", "ipv6")
        for item in (context.get(key, ()) or ())
        if item
    }
    if str(ip) in local_values:
        return "SENSOR"

    gateway = str(context.get("gateway") or "").strip().split("%", 1)[0]
    if gateway and str(ip) == gateway:
        return "INFRASTRUCTURE"

    for network in _networks(context):
        if network.version != ip.version:
            continue
        if ip in network:
            if isinstance(network, ipaddress.IPv4Network) and ip == network.broadcast_address:
                return "BROADCAST"
            if ip == network.network_address:
                return "SPECIAL_ADDRESS"
            return "LOCAL_SUBNET_ENDPOINT"

    if ip.is_link_local:
        return "SPECIAL_ADDRESS"
    return "EXTERNAL_PEER"
