from __future__ import annotations

from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


class FlowEngineWorker(BaseWorker):
    """Builds live conversations from packet metadata and external flow telemetry."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("flow-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id or event.kind != EventKind.OBSERVATION:
                    continue
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
