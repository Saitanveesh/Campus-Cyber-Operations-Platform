from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def endpoint_role(value: str, network: dict[str, Any] | None) -> str:
    if not value:
        return "UNKNOWN"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "SPECIAL_ADDRESS"
    if ip.is_loopback or ip.is_unspecified:
        return "SPECIAL_ADDRESS"
    if ip.is_multicast:
        return "MULTICAST"
    if str(ip) == "255.255.255.255":
        return "BROADCAST"
    if ip.is_link_local:
        return "SPECIAL_ADDRESS"
    if network:
        sensor_addresses = set(network.get("ipv4") or ()) | set(network.get("ipv6") or ())
        if value in sensor_addresses:
            return "SENSOR"
        if value == network.get("gateway"):
            return "INFRASTRUCTURE"
        for raw_prefix in network.get("prefixes") or ():
            try:
                subnet = ipaddress.ip_network(str(raw_prefix), strict=False)
            except ValueError:
                continue
            if ip.version == subnet.version and ip in subnet:
                if ip == subnet.broadcast_address:
                    return "BROADCAST"
                return "LOCAL_SUBNET_ENDPOINT"
    if ip.is_private:
        return "PRIVATE_OFF_SUBNET_PEER"
    if ip.is_global:
        return "PUBLIC_PEER"
    return "SPECIAL_ADDRESS"


class IntelligenceWorker(BaseWorker):
    """Turns passive packet observations into truth-scoped assets, flows and topology."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("network-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider
        self._metric_session: str | None = None
        self._reset_tcp_metrics()

    def _reset_tcp_metrics(self) -> None:
        self._rtt_samples = 0
        self._rtt_sum_ms = 0.0
        self._tcp_packets = 0
        self._retransmissions = 0
        self._duplicate_acks = 0

    def _update_tcp_metrics(self, payload: dict[str, Any]) -> None:
        if payload.get("transport") != "TCP":
            return
        self._tcp_packets += 1
        if payload.get("tcp_retransmission") or payload.get("tcp_fast_retransmission"):
            self._retransmissions += 1
        if payload.get("tcp_duplicate_ack"):
            self._duplicate_acks += 1
        raw_rtt = str(payload.get("tcp_ack_rtt") or "")
        if raw_rtt:
            try:
                self._rtt_sum_ms += float(raw_rtt) * 1000.0
                self._rtt_samples += 1
            except ValueError:
                pass
        self.state.update_metrics(
            tcp_packets=self._tcp_packets,
            tcp_retransmissions=self._retransmissions,
            tcp_duplicate_acks=self._duplicate_acks,
            tcp_retransmission_percent=(self._retransmissions / self._tcp_packets * 100.0)
            if self._tcp_packets
            else 0.0,
            tcp_avg_ack_rtt_ms=(self._rtt_sum_ms / self._rtt_samples) if self._rtt_samples else None,
            tcp_rtt_samples=self._rtt_samples,
        )

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if self._metric_session != session_id:
                    self._metric_session = session_id
                    self._reset_tcp_metrics()
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue

                payload = dict(event.payload)
                self._update_tcp_metrics(payload)
                network = self.network_provider()
                now = datetime.now(UTC).isoformat()
                src_ip = str(payload.get("src_ip") or "")
                dst_ip = str(payload.get("dst_ip") or "")
                eth_src = str(payload.get("eth_src") or "")
                protocol = str(payload.get("protocol") or "UNKNOWN")
                transport = str(payload.get("transport") or protocol)
                src_port = str(payload.get("src_port") or "")
                dst_port = str(payload.get("dst_port") or "")
                src_role = endpoint_role(src_ip, network)
                dst_role = endpoint_role(dst_ip, network)

                if src_ip and src_role not in {"SPECIAL_ADDRESS", "MULTICAST", "BROADCAST", "UNKNOWN"}:
                    previous = self.state.get_asset(src_ip)
                    self.state.upsert_asset(
                        src_ip,
                        {
                            "id": src_ip,
                            "ip": src_ip,
                            "mac": eth_src or previous.get("mac"),
                            "role": src_role,
                            "local_device": src_role in {"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"},
                            "first_seen": previous.get("first_seen", now),
                            "last_seen": now,
                            "packets_as_source": int(previous.get("packets_as_source", 0)) + 1,
                            "dhcp_hostname": payload.get("dhcp_hostname") or previous.get("dhcp_hostname"),
                            "vlan_id": payload.get("vlan_id") or previous.get("vlan_id"),
                            "evidence": "PASSIVE_SOURCE_FRAME",
                        },
                    )

                if src_ip and dst_ip:
                    flow_key = f"{src_ip}:{src_port}>{dst_ip}:{dst_port}/{transport}"
                    previous_flow = self.state.get_flow(flow_key)
                    self.state.upsert_flow(
                        flow_key,
                        {
                            "id": flow_key,
                            "src": src_ip,
                            "dst": dst_ip,
                            "src_role": src_role,
                            "dst_role": dst_role,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "transport": transport,
                            "protocol": protocol,
                            "protocol_stack": payload.get("protocol_stack"),
                            "first_seen": previous_flow.get("first_seen", now),
                            "last_seen": now,
                            "packets": int(previous_flow.get("packets", 0)) + 1,
                            "bytes": int(previous_flow.get("bytes", 0)) + int(payload.get("length") or 0),
                            "dns_query": payload.get("dns_query") or previous_flow.get("dns_query"),
                            "tls_sni": payload.get("tls_sni") or previous_flow.get("tls_sni"),
                            "http_host": payload.get("http_host") or previous_flow.get("http_host"),
                            "tcp_flags": payload.get("tcp_flags") or previous_flow.get("tcp_flags"),
                            "tcp_ack_rtt": payload.get("tcp_ack_rtt") or previous_flow.get("tcp_ack_rtt"),
                            "ip_ttl": payload.get("ip_ttl") or previous_flow.get("ip_ttl"),
                            "ipv6_hop_limit": payload.get("ipv6_hop_limit") or previous_flow.get("ipv6_hop_limit"),
                            "vlan_id": payload.get("vlan_id") or previous_flow.get("vlan_id"),
                        },
                    )
                    edge_key = f"{src_ip}>{dst_ip}"
                    previous_edge = self.state.get_edge(edge_key)
                    self.state.upsert_edge(
                        edge_key,
                        {
                            "id": edge_key,
                            "source": src_ip,
                            "target": dst_ip,
                            "source_role": src_role,
                            "target_role": dst_role,
                            "packets": int(previous_edge.get("packets", 0)) + 1,
                            "bytes": int(previous_edge.get("bytes", 0)) + int(payload.get("length") or 0),
                            "last_seen": now,
                            "evidence": "OBSERVED_COMMUNICATION",
                        },
                    )
                self.health.heartbeat("asset/flow/TCP/topology correlation active")
        finally:
            await self.bus.unsubscribe(self.name)
