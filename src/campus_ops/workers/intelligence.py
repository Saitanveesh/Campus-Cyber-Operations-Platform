from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def classify_ip(value: str) -> str:
    if not value:
        return "UNKNOWN"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "INVALID"
    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_multicast:
        return "MULTICAST"
    if ip.is_link_local:
        return "LINK_LOCAL"
    if ip.is_private:
        return "PRIVATE"
    if ip.is_global:
        return "PUBLIC"
    return "SPECIAL"


class IntelligenceWorker(BaseWorker):
    """Turns passive packet observations into assets, flows and communication edges."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("network-intelligence", bus)
        self.state = state
        self.session_provider = session_provider

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
                payload = event.payload
                now = datetime.now(UTC).isoformat()
                src_ip = str(payload.get("src_ip") or "")
                dst_ip = str(payload.get("dst_ip") or "")
                eth_src = str(payload.get("eth_src") or "")
                protocol = str(payload.get("protocol") or "UNKNOWN")
                src_port = str(payload.get("src_port") or "")
                dst_port = str(payload.get("dst_port") or "")
                if src_ip and classify_ip(src_ip) not in {"INVALID", "MULTICAST", "LOOPBACK", "SPECIAL"}:
                    previous = self.state.assets.get(src_ip, {})
                    self.state.assets[src_ip] = {
                        "id": src_ip,
                        "ip": src_ip,
                        "mac": eth_src or previous.get("mac"),
                        "classification": classify_ip(src_ip),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "packets_as_source": int(previous.get("packets_as_source", 0)) + 1,
                        "evidence": "PASSIVE_SOURCE_FRAME",
                    }
                if src_ip and dst_ip:
                    transport = "TCP" if payload.get("tcp_flags") or src_port or dst_port else "UDP" if src_port or dst_port else protocol
                    flow_key = f"{src_ip}:{src_port}>{dst_ip}:{dst_port}/{transport}"
                    previous_flow = self.state.flows.get(flow_key, {})
                    self.state.flows[flow_key] = {
                        "id": flow_key,
                        "src": src_ip,
                        "dst": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "transport": transport,
                        "protocol": protocol,
                        "first_seen": previous_flow.get("first_seen", now),
                        "last_seen": now,
                        "packets": int(previous_flow.get("packets", 0)) + 1,
                        "bytes": int(previous_flow.get("bytes", 0)) + int(payload.get("length") or 0),
                        "dns_query": payload.get("dns_query") or previous_flow.get("dns_query"),
                        "tls_sni": payload.get("tls_sni") or previous_flow.get("tls_sni"),
                    }
                    edge_key = f"{src_ip}>{dst_ip}"
                    previous_edge = self.state.topology_edges.get(edge_key, {})
                    self.state.topology_edges[edge_key] = {
                        "id": edge_key,
                        "source": src_ip,
                        "target": dst_ip,
                        "packets": int(previous_edge.get("packets", 0)) + 1,
                        "bytes": int(previous_edge.get("bytes", 0)) + int(payload.get("length") or 0),
                        "last_seen": now,
                        "evidence": "OBSERVED_COMMUNICATION",
                    }
                self.health.heartbeat(f"assets={len(self.state.assets)} flows={len(self.state.flows)}")
        finally:
            await self.bus.unsubscribe(self.name)
