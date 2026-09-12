from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin

_IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_KV_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]{1,40})=(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))")


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def parse_syslog_message(message: str, source: str | None = None) -> dict[str, Any]:
    """Normalize common firewall/RADIUS/802.1X syslog without vendor-specific claims."""
    text = (message or "").strip()[:8192]
    upper = text.upper()
    kv: dict[str, str] = {}
    for match in _KV_RE.finditer(text):
        kv[match.group(1).lower()] = next((v for v in match.groups()[1:] if v is not None), "")

    ips = [_valid_ip(value) for value in _IP_RE.findall(text)]
    ips = [value for value in ips if value]
    macs = [value.lower().replace("-", ":") for value in _MAC_RE.findall(text)]

    category = "SYSLOG"
    if any(token in upper for token in ("RADIUS", "ACCESS-ACCEPT", "ACCESS-REJECT", "CALLING-STATION-ID")):
        category = "RADIUS"
    elif any(token in upper for token in ("802.1X", "DOT1X", "EAPOL")):
        category = "DOT1X"
    elif any(token in upper for token in ("FIREWALL", "DENY", "DROP", "BLOCK", "ALLOW", "ACCEPT")):
        category = "FIREWALL"

    action = None
    for candidate in ("deny", "drop", "block", "reject", "allow", "accept", "permit"):
        if candidate.upper() in upper:
            action = candidate.upper()
            break

    username = kv.get("username") or kv.get("user") or kv.get("user-name")
    vlan = kv.get("vlan") or kv.get("vlanid") or kv.get("tunnel-private-group-id")
    port = kv.get("port") or kv.get("nas-port-id") or kv.get("dstport") or kv.get("dpt")
    protocol = kv.get("proto") or kv.get("protocol")

    return {
        "category": category,
        "source_sensor": source,
        "action": action,
        "src_ip": _valid_ip(kv.get("src") or kv.get("srcip") or kv.get("source")) or (ips[0] if ips else None),
        "dst_ip": _valid_ip(kv.get("dst") or kv.get("dstip") or kv.get("destination")) or (ips[1] if len(ips) > 1 else None),
        "mac": kv.get("mac") or kv.get("calling-station-id") or (macs[0] if macs else None),
        "username": username,
        "vlan": vlan,
        "port": port,
        "protocol": protocol,
        "raw": text,
    }


def _rows(app: FastAPI) -> list[dict[str, Any]]:
    live = app.state.orchestrator.state.snapshot()
    rows: list[dict[str, Any]] = []
    for key in ("events", "alerts", "incidents"):
        value = live.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    return rows


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("payload")
    return value if isinstance(value, dict) else {}


def soc_overview(app: FastAPI) -> dict[str, Any]:
    rows = _rows(app)
    severity = Counter(str(row.get("severity") or "INFO").upper() for row in rows)
    sources = Counter(str(row.get("source") or "unknown") for row in rows)
    targets: Counter[str] = Counter()
    for row in rows:
        payload = _payload(row)
        for key in ("src_ip", "dst_ip", "ip", "host", "target"):
            value = _valid_ip(str(payload.get(key) or ""))
            if value:
                targets[value] += 1
    return {
        "session_id": app.state.orchestrator.session_id,
        "signals": len(rows),
        "severity": dict(severity),
        "top_sources": sources.most_common(10),
        "top_targets": targets.most_common(10),
        "truth_note": "Counts are current-session observations and detections, not confirmed compromises.",
    }


def target_pivot(app: FastAPI, target: str) -> dict[str, Any]:
    target = target.strip()
    matches: list[dict[str, Any]] = []
    for row in _rows(app):
        payload = _payload(row)
        haystack = " ".join(
            str(value)
            for value in [row.get("source"), row.get("title"), row.get("summary"), *payload.values()]
        )
        if target.lower() in haystack.lower():
            matches.append(row)
    return {
        "target": target,
        "session_id": app.state.orchestrator.session_id,
        "matching_signals": len(matches),
        "recent": matches[-100:],
        "truth_note": "Pivot includes only evidence containing the requested target in the current session.",
    }


def infrastructure_inventory(app: FastAPI) -> dict[str, Any]:
    """Build a read-only inventory from observed SNMP/LLDP/CDP/NAC/syslog evidence."""
    devices: dict[str, dict[str, Any]] = {}
    vlans: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    links: list[dict[str, Any]] = []

    for row in _rows(app):
        payload = _payload(row)
        event_type = str(payload.get("type") or "").upper()
        source = str(row.get("source") or "")
        evidence = str(row.get("evidence_class") or "").upper()
        target = str(payload.get("target") or payload.get("nas_ip") or payload.get("nas") or "").strip()

        if event_type == "SNMP_TELEMETRY" or "SNMP" in evidence:
            key = target or source or "unknown-snmp-device"
            device = devices.setdefault(
                key,
                {
                    "id": key,
                    "name": payload.get("sysName") or payload.get("name"),
                    "description": payload.get("sysDescr") or payload.get("description"),
                    "interfaces": [],
                    "sources": set(),
                },
            )
            device["sources"].add(source or "snmp")
            interfaces = payload.get("interfaces")
            if isinstance(interfaces, list):
                device["interfaces"] = interfaces[:256]
            neighbors = payload.get("lldp_neighbors")
            if isinstance(neighbors, list):
                for neighbor in neighbors[:256]:
                    if not isinstance(neighbor, dict):
                        continue
                    links.append(
                        {
                            "local": key,
                            "local_port": neighbor.get("local_port"),
                            "remote": neighbor.get("remote_system") or neighbor.get("remote_chassis"),
                            "remote_port": neighbor.get("remote_port"),
                            "evidence": "LLDP_OVER_SNMP",
                        }
                    )

        if event_type in {"LLDP_NEIGHBOR", "CDP_NEIGHBOR"}:
            links.append(dict(payload))

        vlan = payload.get("vlan") or payload.get("vlan_id") or payload.get("tunnel_private_group_id")
        if vlan not in {None, ""}:
            vlans[str(vlan)] += 1
        port = payload.get("port") or payload.get("nas_port_id") or payload.get("switch_port")
        if port not in {None, ""}:
            ports[str(port)] += 1

    output_devices = []
    for device in devices.values():
        row = dict(device)
        row["sources"] = sorted(device["sources"])
        output_devices.append(row)

    return {
        "state": "EVIDENCE_PRESENT" if output_devices or links or vlans or ports else "NO_INFRASTRUCTURE_EVIDENCE",
        "devices": output_devices,
        "links": links[:500],
        "vlans": [{"vlan": key, "observations": count} for key, count in vlans.most_common(100)],
        "ports": [{"port": key, "observations": count} for key, count in ports.most_common(100)],
        "truth_note": "Inventory is evidence-backed; no switch, VLAN or physical link is invented from IP traffic alone.",
    }


def install_enterprise_soc(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_soc_installed", False):
        return app
    app.state.enterprise_soc_installed = True

    @app.get("/api/v1/system/soc-overview")
    async def system_soc_overview() -> dict[str, Any]:
        return soc_overview(app)

    @app.get("/api/v1/system/infrastructure-inventory")
    async def system_infrastructure_inventory() -> dict[str, Any]:
        return infrastructure_inventory(app)

    @app.get("/api/v1/admin/soc/pivot/{target}")
    async def admin_soc_pivot(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return target_pivot(app, target)

    return app
