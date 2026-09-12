from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin


def _ip(value: object) -> ipaddress._BaseAddress | None:
    text = str(value or "").strip().split("%", 1)[0]
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _network(value: object) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def _live(app: FastAPI) -> dict[str, Any]:
    snapshot = app.state.orchestrator.snapshot()
    live = snapshot.get("live")
    return live if isinstance(live, dict) else {}


def _network_context(app: FastAPI) -> dict[str, Any]:
    context = app.state.orchestrator.get_network_context()
    return context if isinstance(context, dict) else {}


def _event_payload(row: object) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    payload = row.get("payload")
    return payload if isinstance(payload, dict) else {}


def _all_current_events(live: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("events", "alerts", "packet_feed"):
        values = live.get(key)
        if isinstance(values, list):
            rows.extend(item for item in values if isinstance(item, dict))
    return rows


def build_ipv6_report(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    addresses: set[str] = set()
    peers: Counter[str] = Counter()
    ndp_signals = 0
    router_advertisements = 0

    for asset in live.get("assets", []):
        if not isinstance(asset, dict):
            continue
        for key in ("ip", "address", "ipv6"):
            value = asset.get(key)
            values = value if isinstance(value, list) else [value]
            for item in values:
                parsed = _ip(item)
                if parsed and parsed.version == 6:
                    addresses.add(str(parsed))

    for flow in live.get("flows", []):
        if not isinstance(flow, dict):
            continue
        for key in ("src_ip", "dst_ip", "source", "destination"):
            parsed = _ip(flow.get(key))
            if parsed and parsed.version == 6:
                addresses.add(str(parsed))
                peers[str(parsed)] += 1

    for event in _all_current_events(live):
        payload = _event_payload(event)
        text = " ".join(
            str(payload.get(key) or "")
            for key in ("type", "protocol", "summary", "message", "icmpv6_type")
        ).upper()
        if "NDP" in text or "NEIGHBOR SOLICIT" in text or "NEIGHBOR ADVERT" in text:
            ndp_signals += 1
        if "ROUTER ADVERT" in text or "RA " in f"{text} ":
            router_advertisements += 1

    return {
        "state": "OBSERVED" if addresses else "NO_CURRENT_SESSION_IPV6_EVIDENCE",
        "addresses": sorted(addresses),
        "address_count": len(addresses),
        "top_peers": [{"ip": ip, "observations": count} for ip, count in peers.most_common(25)],
        "ndp_signals": ndp_signals,
        "router_advertisements": router_advertisements,
        "truth_note": "Only evidence observed in the current live session is reported.",
    }


def build_dns_tls_report(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    dns: Counter[str] = Counter()
    sni: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    issuers: Counter[str] = Counter()

    for event in _all_current_events(live):
        payload = _event_payload(event)
        values = {
            "dns": payload.get("dns_query") or payload.get("query"),
            "sni": payload.get("tls_sni") or payload.get("server_name") or payload.get("sni"),
            "http": payload.get("http_host") or payload.get("host_header"),
            "issuer": payload.get("certificate_issuer") or payload.get("tls_issuer"),
        }
        if values["dns"]:
            dns[str(values["dns"]).lower()] += 1
        if values["sni"]:
            sni[str(values["sni"]).lower()] += 1
        if values["http"]:
            http_hosts[str(values["http"]).lower()] += 1
        if values["issuer"]:
            issuers[str(values["issuer"])] += 1

    return {
        "dns": [{"name": name, "observations": count} for name, count in dns.most_common(50)],
        "tls_sni": [{"name": name, "observations": count} for name, count in sni.most_common(50)],
        "http_hosts": [
            {"name": name, "observations": count} for name, count in http_hosts.most_common(50)
        ],
        "certificate_issuers": [
            {"name": name, "observations": count} for name, count in issuers.most_common(25)
        ],
        "state": "OBSERVED" if dns or sni or http_hosts or issuers else "NO_APPLICATION_EVIDENCE",
    }


def build_segmentation_report(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    context = _network_context(app)
    prefixes = [net for raw in context.get("prefixes", []) if (net := _network(raw)) is not None]
    counts: Counter[str] = Counter()
    cross_prefix: list[dict[str, Any]] = []

    def classify(value: object) -> str:
        parsed = _ip(value)
        if parsed is None:
            return "UNKNOWN"
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return "SPECIAL"
        for net in prefixes:
            if parsed.version == net.version and parsed in net:
                return str(net)
        return "EXTERNAL_OR_OTHER_PREFIX"

    for flow in live.get("flows", []):
        if not isinstance(flow, dict):
            continue
        src = flow.get("src_ip") or flow.get("source")
        dst = flow.get("dst_ip") or flow.get("destination")
        src_zone = classify(src)
        dst_zone = classify(dst)
        counts[f"{src_zone} -> {dst_zone}"] += 1
        if src_zone not in {dst_zone, "UNKNOWN", "SPECIAL"} and dst_zone not in {
            "UNKNOWN",
            "SPECIAL",
        }:
            if len(cross_prefix) < 100:
                cross_prefix.append(
                    {
                        "src": src,
                        "dst": dst,
                        "src_zone": src_zone,
                        "dst_zone": dst_zone,
                        "protocol": flow.get("protocol") or flow.get("proto"),
                        "service": flow.get("service") or flow.get("application"),
                    }
                )

    return {
        "configured_prefixes": [str(net) for net in prefixes],
        "flow_classes": [{"class": key, "flows": value} for key, value in counts.most_common()],
        "cross_prefix_examples": cross_prefix,
        "vlan_state": "UNKNOWN_WITHOUT_LLDP_SNMP_CONTROLLER_EVIDENCE",
        "truth_note": "Subnets are derived from the selected interface. VLAN IDs are never inferred from IP alone.",
    }


def build_physical_topology_evidence(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    devices: dict[str, dict[str, Any]] = {}
    links: list[dict[str, Any]] = []

    for event in _all_current_events(live):
        payload = _event_payload(event)
        event_type = str(payload.get("type") or "").upper()
        if event_type == "SNMP_TELEMETRY":
            target = str(payload.get("target") or "").strip()
            if target:
                devices[target] = {
                    "target": target,
                    "name": payload.get("sysName"),
                    "description": payload.get("sysDescr"),
                    "interfaces": payload.get("interfaces") or [],
                    "evidence": "SNMP_READ_ONLY",
                }
            for neighbor in payload.get("lldp_neighbors") or []:
                if not isinstance(neighbor, dict):
                    continue
                links.append(
                    {
                        "local": target,
                        "local_port": neighbor.get("local_port"),
                        "remote": neighbor.get("remote_system") or neighbor.get("remote_chassis"),
                        "remote_port": neighbor.get("remote_port"),
                        "evidence": "LLDP_OVER_SNMP",
                    }
                )
        elif event_type in {"LLDP_NEIGHBOR", "CDP_NEIGHBOR"}:
            links.append(dict(payload))

    return {
        "state": "EVIDENCE_PRESENT" if devices or links else "NO_INFRASTRUCTURE_EVIDENCE",
        "devices": list(devices.values()),
        "links": links,
        "truth_note": "Physical links appear only when LLDP/CDP/SNMP/controller evidence exists.",
    }


def build_target_network_dossier(app: FastAPI, target: str) -> dict[str, Any]:
    live = _live(app)
    flows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    peers: Counter[str] = Counter()

    for flow in live.get("flows", []):
        if not isinstance(flow, dict):
            continue
        src = str(flow.get("src_ip") or flow.get("source") or "")
        dst = str(flow.get("dst_ip") or flow.get("destination") or "")
        if target not in {src, dst}:
            continue
        flows.append(flow)
        peer = dst if src == target else src
        if peer:
            peers[peer] += 1

    for event in _all_current_events(live):
        payload = _event_payload(event)
        text_values = {
            str(payload.get(key) or "")
            for key in ("src_ip", "dst_ip", "source", "target", "ip", "host")
        }
        evidence = payload.get("evidence")
        if isinstance(evidence, dict):
            text_values.update(str(value or "") for value in evidence.values() if isinstance(value, str))
        if target in text_values:
            events.append(event)

    parsed = _ip(target)
    classification = "INVALID"
    if parsed:
        if parsed.is_private:
            classification = "PRIVATE"
        elif parsed.is_global:
            classification = "GLOBAL"
        elif parsed.is_link_local:
            classification = "LINK_LOCAL"
        else:
            classification = "SPECIAL"

    return {
        "target": target,
        "classification": classification,
        "current_session_only": True,
        "flow_count": len(flows),
        "event_count": len(events),
        "top_peers": [{"peer": peer, "flows": count} for peer, count in peers.most_common(30)],
        "flows": flows[:150],
        "events": events[:150],
        "truth_state": "EVIDENCE_PRESENT" if flows or events else "NO_CURRENT_SESSION_EVIDENCE",
    }


def install_network_depth_layer(app: FastAPI) -> FastAPI:
    if getattr(app.state, "network_depth_layer_installed", False):
        return app
    app.state.network_depth_layer_installed = True

    @app.get("/api/v1/system/network-depth")
    async def network_depth() -> dict[str, Any]:
        return {
            "ipv6": build_ipv6_report(app),
            "dns_tls": build_dns_tls_report(app),
            "segmentation": build_segmentation_report(app),
            "physical_topology": build_physical_topology_evidence(app),
        }

    @app.get("/api/v1/system/ipv6")
    async def ipv6_depth() -> dict[str, Any]:
        return build_ipv6_report(app)

    @app.get("/api/v1/system/dns-tls")
    async def dns_tls_depth() -> dict[str, Any]:
        return build_dns_tls_report(app)

    @app.get("/api/v1/system/physical-topology-evidence")
    async def physical_topology_depth() -> dict[str, Any]:
        return build_physical_topology_evidence(app)

    @app.get("/api/v1/admin/network-dossier/{target}")
    async def network_dossier(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return build_target_network_dossier(app, target)

    return app
