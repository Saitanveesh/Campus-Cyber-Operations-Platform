from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role
from campus_ops.workers.service_intelligence import service_name


_LOCAL_ASSET_ROLES = frozenset({"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"})


def _valid_unicast_mac(value: str) -> bool:
    raw = value.strip().lower().replace("-", ":")
    parts = raw.split(":")
    if len(parts) != 6:
        return False
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return False
    if any(part < 0 or part > 255 for part in octets):
        return False
    if all(part == 0 for part in octets) or all(part == 255 for part in octets):
        return False
    return (octets[0] & 1) == 0


def _flag_value(raw: object) -> int:
    text = str(raw or "").strip().lower()
    if not text:
        return 0
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


def _clean_hostname(value: object) -> str:
    name = str(value or "").strip().rstrip(".")
    if not name or len(name) > 253:
        return ""
    if name.startswith("_") or "._tcp." in name.lower() or "._udp." in name.lower():
        return ""
    return name


def _ttl_profile(value: object) -> dict[str, object]:
    try:
        ttl = int(str(value or "").split(",", 1)[0])
    except ValueError:
        return {}
    if not 1 <= ttl <= 255:
        return {}
    if ttl <= 32:
        initial = 32
        family = "TTL≈32"
    elif ttl <= 64:
        initial = 64
        family = "TTL≈64 (common Unix/Linux/macOS/mobile)"
    elif ttl <= 128:
        initial = 128
        family = "TTL≈128 (common Windows)"
    else:
        initial = 255
        family = "TTL≈255 (common network/embedded)"
    return {
        "observed_ttl": ttl,
        "estimated_initial_ttl": initial,
        "estimated_hops": max(0, initial - ttl),
        "ip_stack_hint": family,
        "ip_stack_hint_confidence": "LOW_HEURISTIC",
    }


def _top(counter: Counter[str], limit: int = 12) -> list[list[object]]:
    return [[name, count] for name, count in counter.most_common(limit)]


class AssetEngineWorker(BaseWorker):
    """Build evidence-backed local device identities from passive packet metadata.

    Inventory entries still require repeated local source-frame evidence. Once confirmed,
    MON enriches them only from metadata already present in the same TShark stream:
    DHCP/mDNS/LLMNR/NBNS names, MAC vendor, observed responding services, peers,
    application names and a deliberately low-confidence IP-TTL stack hint.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("asset-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider
        self._candidate_counts: dict[tuple[str, str], int] = {}
        self._candidate_session: str | None = None
        self._peers: dict[str, Counter[str]] = defaultdict(Counter)
        self._applications: dict[str, Counter[str]] = defaultdict(Counter)
        self._protocols: dict[str, Counter[str]] = defaultdict(Counter)
        self._services: dict[str, Counter[str]] = defaultdict(Counter)
        self._hostname_sources: dict[str, dict[str, str]] = defaultdict(dict)

    def _reset(self, session_id: str) -> None:
        self._candidate_session = session_id
        self._candidate_counts.clear()
        self._peers.clear()
        self._applications.clear()
        self._protocols.clear()
        self._services.clear()
        self._hostname_sources.clear()

    @staticmethod
    def _valid_peer(value: object) -> str:
        raw = str(value or "").strip()
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return ""
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            return ""
        return str(ip)

    def _observe_enrichment(self, src_ip: str, payload: dict[str, object]) -> None:
        peer = self._valid_peer(payload.get("dst_ip"))
        if peer and peer != src_ip:
            self._peers[src_ip][peer] += 1

        protocol = str(payload.get("protocol") or payload.get("transport") or "").strip().upper()
        if protocol:
            self._protocols[src_ip][protocol] += 1

        for raw in (
            payload.get("dns_query"),
            payload.get("tls_sni"),
            payload.get("http_host"),
        ):
            name = _clean_hostname(raw)
            if name:
                self._applications[src_ip][name.lower()] += 1

        names = self._hostname_sources[src_ip]
        dhcp = _clean_hostname(payload.get("dhcp_hostname"))
        if dhcp:
            names["DHCP"] = dhcp

        transport = str(payload.get("transport") or "").upper()
        src_port = str(payload.get("src_port") or "")
        dst_port = str(payload.get("dst_port") or "")
        if transport == "UDP" and "5353" in {src_port, dst_port}:
            mdns = _clean_hostname(
                payload.get("dns_response_name")
                or payload.get("dns_query")
                or payload.get("dns_ptr_name")
            )
            if mdns:
                names["mDNS"] = mdns
        if transport == "UDP" and "5355" in {src_port, dst_port}:
            llmnr = _clean_hostname(payload.get("llmnr_name") or payload.get("dns_query"))
            if llmnr:
                names["LLMNR"] = llmnr
        if transport == "UDP" and "137" in {src_port, dst_port}:
            nbns = _clean_hostname(payload.get("nbns_name"))
            if nbns:
                names["NBNS"] = nbns

        flags = _flag_value(payload.get("tcp_flags"))
        if transport == "TCP" and flags & 0x12 == 0x12 and src_port:
            try:
                port = int(src_port)
            except ValueError:
                port = 0
            if 1 <= port <= 65535:
                label = service_name("TCP", port)
                self._services[src_ip][f"TCP/{port} {label}"] += 1

    def _preferred_hostname(self, src_ip: str, previous: dict[str, object]) -> str | None:
        names = self._hostname_sources.get(src_ip, {})
        for source in ("DHCP", "mDNS", "LLMNR", "NBNS"):
            if names.get(source):
                return names[source]
        value = _clean_hostname(previous.get("hostname"))
        return value or None

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                if self._candidate_session != session_id:
                    self._reset(session_id)

                payload = dict(event.payload)
                src_ip = str(payload.get("src_ip") or "").strip()
                src_mac = str(payload.get("eth_src") or "").strip().lower()
                if not src_ip or not _valid_unicast_mac(src_mac):
                    continue

                role = endpoint_role(src_ip, self.network_provider())
                if role not in _LOCAL_ASSET_ROLES:
                    continue

                self._observe_enrichment(src_ip, payload)

                candidate_key = (src_ip, src_mac)
                count = self._candidate_counts.get(candidate_key, 0) + 1
                self._candidate_counts[candidate_key] = count
                if count < 2:
                    self.health.heartbeat("validating local source-frame candidates")
                    continue

                now = datetime.now(UTC).isoformat()
                previous = self.state.get_asset(src_ip)
                previous_mac = str(previous.get("mac") or "").lower()
                identity_changed = bool(previous_mac and previous_mac != src_mac)
                vendor = payload.get("eth_src_vendor") or previous.get("vendor")
                hostname = self._preferred_hostname(src_ip, previous)
                ttl = _ttl_profile(payload.get("ip_ttl") or payload.get("ipv6_hop_limit"))
                hostname_sources = dict(self._hostname_sources.get(src_ip, {}))

                self.state.upsert_asset(
                    src_ip,
                    {
                        **previous,
                        **ttl,
                        "id": src_ip,
                        "ip": src_ip,
                        "mac": src_mac,
                        "vendor": vendor,
                        "role": role,
                        "classification": role,
                        "local_device": True,
                        "hostname": hostname,
                        "dhcp_hostname": hostname_sources.get("DHCP"),
                        "hostname_sources": hostname_sources,
                        "vlan_id": payload.get("vlan_id") or previous.get("vlan_id"),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "packets_as_source": int(previous.get("packets_as_source", 0)) + 1,
                        "confirmation_frames": count,
                        "identity_changed": identity_changed,
                        "observed_services": _top(self._services[src_ip], 16),
                        "top_peers": _top(self._peers[src_ip], 12),
                        "top_application_names": _top(self._applications[src_ip], 16),
                        "top_protocols": _top(self._protocols[src_ip], 12),
                        "evidence": "CONFIRMED_LOCAL_SOURCE_FRAMES",
                        "identity_evidence": (
                            "PASSIVE_DHCP_MDNS_LLMNR_NBNS_MAC_SERVICE_PACKET_METADATA"
                        ),
                        "confidence": "HIGH",
                    },
                )
                self.health.heartbeat(
                    f"confirmed_assets={len(self.state.snapshot()['assets'])}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
