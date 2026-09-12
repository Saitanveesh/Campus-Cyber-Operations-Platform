from __future__ import annotations

import time
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


class FlowEngineWorker(BaseWorker):
    """Build live conversations with current packet and bit-rate estimates."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("flow-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider
        self._last_event_at: dict[str, float] = {}
        self._rate_session: str | None = None

    @staticmethod
    def _ewma(previous: object, current: float, alpha: float = 0.22) -> float:
        try:
            old = float(previous)
        except (TypeError, ValueError):
            old = current
        return round((alpha * current) + ((1.0 - alpha) * old), 2)

    def _rates(self, key: str, packets: int, octets: int, previous: dict[str, object]) -> tuple[float, float]:
        now = time.monotonic()
        prior = self._last_event_at.get(key)
        self._last_event_at[key] = now
        if prior is None:
            return float(previous.get("pps_ewma") or 0.0), float(previous.get("bps_ewma") or 0.0)
        elapsed = max(0.001, now - prior)
        instant_pps = packets / elapsed
        instant_bps = (octets * 8.0) / elapsed
        return (
            self._ewma(previous.get("pps_ewma"), instant_pps),
            self._ewma(previous.get("bps_ewma"), instant_bps),
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
                kind = str(payload.get("type") or "")
                if kind not in {"PACKET", "FLOW_TELEMETRY"}:
                    continue
                src_ip = str(payload.get("src_ip") or "")
                dst_ip = str(payload.get("dst_ip") or "")
                if not src_ip or not dst_ip:
                    continue
                transport = str(payload.get("transport") or payload.get("protocol") or "UNKNOWN")
                src_port = str(payload.get("src_port") or "")
                dst_port = str(payload.get("dst_port") or "")
                protocol = str(payload.get("protocol") or transport)
                packets = int(payload.get("packets") or 1)
                octets = int(payload.get("bytes") or payload.get("length") or 0)
                now = datetime.now(UTC).isoformat()
                key = f"{src_ip}:{src_port}>{dst_ip}:{dst_port}/{transport}"
                previous = self.state.get_flow(key)
                network = self.network_provider()
                pps_ewma, bps_ewma = self._rates(key, max(1, packets), max(0, octets), previous)
                self.state.upsert_flow(
                    key,
                    {
                        **previous,
                        "id": key,
                        "src": src_ip,
                        "dst": dst_ip,
                        "src_role": endpoint_role(src_ip, network),
                        "dst_role": endpoint_role(dst_ip, network),
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "transport": transport,
                        "protocol": protocol,
                        "protocol_stack": payload.get("protocol_stack") or previous.get("protocol_stack"),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "packets": int(previous.get("packets", 0)) + max(1, packets),
                        "bytes": int(previous.get("bytes", 0)) + max(0, octets),
                        "pps_ewma": pps_ewma,
                        "bps_ewma": bps_ewma,
                        "dns_query": payload.get("dns_query") or previous.get("dns_query"),
                        "tls_sni": payload.get("tls_sni") or previous.get("tls_sni"),
                        "http_host": payload.get("http_host") or previous.get("http_host"),
                        "tcp_flags": payload.get("tcp_flags") or previous.get("tcp_flags"),
                        "tcp_ack_rtt": payload.get("tcp_ack_rtt") or previous.get("tcp_ack_rtt"),
                        "ip_ttl": payload.get("ip_ttl") or previous.get("ip_ttl"),
                        "vlan_id": payload.get("vlan_id") or previous.get("vlan_id"),
                        "source": "FLOW_EXPORT" if kind == "FLOW_TELEMETRY" else "PACKET_CAPTURE",
                        "exporter": payload.get("exporter") or previous.get("exporter"),
                    },
                )
                self.health.heartbeat(f"flows={len(self.state.snapshot()['flows'])}")
        finally:
            await self.bus.unsubscribe(self.name)
