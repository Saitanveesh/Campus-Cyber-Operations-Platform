from __future__ import annotations

from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


class TopologyEngineWorker(BaseWorker):
    """Maintains observed communication edges without claiming physical switch paths."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("topology-engine", bus)
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
                src = str(payload.get("src_ip") or "")
                dst = str(payload.get("dst_ip") or "")
                if not src or not dst:
                    continue
                packets = int(payload.get("packets") or 1)
                octets = int(payload.get("bytes") or payload.get("length") or 0)
                key = f"{src}>{dst}"
                previous = self.state.get_edge(key)
                network = self.network_provider()
                self.state.upsert_edge(
                    key,
                    {
                        **previous,
                        "id": key,
                        "source": src,
                        "target": dst,
                        "source_role": endpoint_role(src, network),
                        "target_role": endpoint_role(dst, network),
                        "packets": int(previous.get("packets", 0)) + max(1, packets),
                        "bytes": int(previous.get("bytes", 0)) + max(0, octets),
                        "last_seen": datetime.now(UTC).isoformat(),
                        "evidence": "FLOW_EXPORT" if kind == "FLOW_TELEMETRY" else "OBSERVED_COMMUNICATION",
                        "exporter": payload.get("exporter") or previous.get("exporter"),
                    },
                )
                self.health.heartbeat(f"edges={len(self.state.snapshot()['topology_edges'])}")
        finally:
            await self.bus.unsubscribe(self.name)
