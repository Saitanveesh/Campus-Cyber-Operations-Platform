from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


class TopologyEngineWorker(BaseWorker):
    """Maintain evidence-backed live communication relationships for the active session."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("topology-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider

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

                src = str(payload.get("src_ip") or "").strip()
                dst = str(payload.get("dst_ip") or "").strip()
                if not src or not dst:
                    continue

                packets = max(1, int(payload.get("packets") or 1))
                octets = max(0, int(payload.get("bytes") or payload.get("length") or 0))
                protocol = str(payload.get("protocol") or "").strip()
                transport = str(payload.get("transport") or protocol or "UNKNOWN").strip()
                src_port = str(payload.get("src_port") or "").strip()
                dst_port = str(payload.get("dst_port") or "").strip()
                vlan_id = str(payload.get("vlan_id") or "").strip()
                now = datetime.now(UTC).isoformat()
                key = f"{src}>{dst}"
                previous = self.state.get_edge(key)
                network = self.network_provider()

                protocol_counts = self._count(previous.get("protocols"), protocol or transport)
                transport_counts = self._count(previous.get("transports"), transport)
                source_ports = self._remember(previous.get("source_ports"), src_port)
                destination_ports = self._remember(previous.get("destination_ports"), dst_port)
                applications = self._remember(
                    previous.get("applications"),
                    self._application(payload),
                    limit=8,
                )
                vlans = self._remember(previous.get("vlans"), vlan_id, limit=8)

                self.state.upsert_edge(
                    key,
                    {
                        **previous,
                        "id": key,
                        "source": src,
                        "target": dst,
                        "source_role": endpoint_role(src, network),
                        "target_role": endpoint_role(dst, network),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "observations": int(previous.get("observations", 0)) + 1,
                        "packets": int(previous.get("packets", 0)) + packets,
                        "bytes": int(previous.get("bytes", 0)) + octets,
                        "protocols": protocol_counts,
                        "transports": transport_counts,
                        "source_ports": source_ports,
                        "destination_ports": destination_ports,
                        "applications": applications,
                        "vlans": vlans,
                        "last_protocol": protocol or transport,
                        "last_transport": transport,
                        "last_src_port": src_port or None,
                        "last_dst_port": dst_port or None,
                        "last_application": self._application(payload),
                        "last_tcp_flags": payload.get("tcp_flags"),
                        "last_dns_query": payload.get("dns_query"),
                        "last_tls_sni": payload.get("tls_sni"),
                        "last_http_host": payload.get("http_host"),
                        "evidence": (
                            "FLOW_EXPORT" if kind == "FLOW_TELEMETRY" else "OBSERVED_COMMUNICATION"
                        ),
                        "exporter": payload.get("exporter") or previous.get("exporter"),
                    },
                )
                self.health.heartbeat(f"edges={len(self.state.snapshot()['topology_edges'])}")
        finally:
            await self.bus.unsubscribe(self.name)
