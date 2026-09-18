from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role

_LOCAL_ROLES = frozenset({"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"})
_REJECT_ROLES = frozenset({"SPECIAL_ADDRESS", "MULTICAST", "BROADCAST", "UNKNOWN"})


def _real_unicast_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return None
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return str(ip)


class TopologyEngineWorker(BaseWorker):
    """Maintain packet-proven communication relationships for the active session.

    A topology node is created only when its IP was present in a packet captured by the
    one managed TShark process. MON never creates guessed IP nodes, scan results or
    synthetic physical hops.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("topology-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider
        self._last_event_at: dict[str, float] = {}
        self._rate_session: str | None = None

    @staticmethod
    def _count(previous: object, value: object) -> dict[str, int]:
        counts: dict[str, int] = {}
        if isinstance(previous, dict):
            for key, raw in previous.items():
                try:
                    counts[str(key)] = int(raw)
                except (TypeError, ValueError):
                    continue
        text = str(value or "").strip()
        if text:
            counts[text] = counts.get(text, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True)[:12])

    @staticmethod
    def _remember(previous: object, value: object, limit: int = 12) -> list[str]:
        values = [str(item) for item in previous] if isinstance(previous, list) else []
        text = str(value or "").strip()
        if text and text not in values:
            values.append(text)
        return values[-limit:]

    @staticmethod
    def _application(payload: dict[str, Any]) -> str | None:
        for key in ("dns_query", "tls_sni", "http_host", "dhcp_hostname"):
            value = str(payload.get(key) or "").strip()
            if value:
                return value
        return None

    @staticmethod
    def _ewma(previous: object, current: float, alpha: float = 0.22) -> float:
        try:
            old = float(previous)
        except (TypeError, ValueError):
            old = current
        return round((alpha * current) + ((1.0 - alpha) * old), 2)

    def _rates(self, key: str, octets: int, previous: dict[str, Any]) -> tuple[float, float]:
        now = time.monotonic()
        prior = self._last_event_at.get(key)
        self._last_event_at[key] = now
        if prior is None:
            return float(previous.get("pps_ewma") or 0.0), float(previous.get("bps_ewma") or 0.0)
        elapsed = max(0.001, now - prior)
        return (
            self._ewma(previous.get("pps_ewma"), 1.0 / elapsed),
            self._ewma(previous.get("bps_ewma"), (octets * 8.0) / elapsed),
        )

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id or event.kind != EventKind.OBSERVATION:
                    continue
                if self._rate_session != session_id:
                    self._rate_session = session_id
                    self._last_event_at.clear()

                payload = dict(event.payload)
                if str(payload.get("type") or "") != "PACKET":
                    continue

                src = _real_unicast_ip(payload.get("src_ip"))
                dst = _real_unicast_ip(payload.get("dst_ip"))
                if not src or not dst:
                    continue

                network = self.network_provider()
                src_role = endpoint_role(src, network)
                dst_role = endpoint_role(dst, network)
                if src_role in _REJECT_ROLES or dst_role in _REJECT_ROLES:
                    continue
                if src_role not in _LOCAL_ROLES and dst_role not in _LOCAL_ROLES:
                    continue

                octets = max(0, int(payload.get("length") or 0))
                protocol = str(payload.get("protocol") or "").strip()
                transport = str(payload.get("transport") or protocol or "UNKNOWN").strip()
                src_port = str(payload.get("src_port") or "").strip()
                dst_port = str(payload.get("dst_port") or "").strip()
                vlan_id = str(payload.get("vlan_id") or "").strip()
                now = datetime.now(UTC).isoformat()
                key = f"{src}>{dst}"
                previous = self.state.get_edge(key)
                pps_ewma, bps_ewma = self._rates(key, octets, previous)

                self.state.upsert_edge(
                    key,
                    {
                        **previous,
                        "id": key,
                        "source": src,
                        "target": dst,
                        "source_role": src_role,
                        "target_role": dst_role,
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "observations": int(previous.get("observations", 0)) + 1,
                        "packets": int(previous.get("packets", 0)) + 1,
                        "bytes": int(previous.get("bytes", 0)) + octets,
                        "pps_ewma": pps_ewma,
                        "bps_ewma": bps_ewma,
                        "protocols": self._count(previous.get("protocols"), protocol or transport),
                        "transports": self._count(previous.get("transports"), transport),
                        "source_ports": self._remember(previous.get("source_ports"), src_port),
                        "destination_ports": self._remember(previous.get("destination_ports"), dst_port),
                        "applications": self._remember(previous.get("applications"), self._application(payload), limit=8),
                        "vlans": self._remember(previous.get("vlans"), vlan_id, limit=8),
                        "last_protocol": protocol or transport,
                        "last_transport": transport,
                        "last_src_port": src_port or None,
                        "last_dst_port": dst_port or None,
                        "last_application": self._application(payload),
                        "last_tcp_flags": payload.get("tcp_flags"),
                        "last_dns_query": payload.get("dns_query"),
                        "last_tls_sni": payload.get("tls_sni"),
                        "last_http_host": payload.get("http_host"),
                        "evidence": "TSHARK_PACKET_OBSERVED",
                    },
                )
                self.health.heartbeat(f"packet_edges={len(self.state.snapshot()['topology_edges'])}")
        finally:
            await self.bus.unsubscribe(self.name)
