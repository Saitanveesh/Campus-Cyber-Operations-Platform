from __future__ import annotations

from collections import defaultdict

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

SEVERITY_SCORE = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}


class RiskGraphWorker(BaseWorker):
    """Projects alert evidence onto observed network entities and communication edges."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("risk-graph", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._scores: dict[str, int] = defaultdict(int)
        self._reasons: dict[str, list[str]] = defaultdict(list)

    def _publish(self) -> None:
        live = self.state.snapshot()
        nodes = []
        asset_ids = {str(asset.get("ip") or "") for asset in live["assets"]}
        observed_ids = {
            str(edge.get("source") or "") for edge in live["topology_edges"]
        } | {str(edge.get("target") or "") for edge in live["topology_edges"]}
        for node_id in sorted((asset_ids | observed_ids | set(self._scores)) - {""}):
            nodes.append(
                {
                    "id": node_id,
                    "risk": min(100, self._scores.get(node_id, 0)),
                    "reasons": self._reasons.get(node_id, [])[-8:],
                }
            )
        edges = [
            {
                "source": edge.get("source"),
                "target": edge.get("target"),
                "packets": edge.get("packets", 0),
                "bytes": edge.get("bytes", 0),
            }
            for edge in live["topology_edges"][:500]
        ]
        self.state.update_metrics(risk_graph={"nodes": nodes, "edges": edges})

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if self._session != session_id:
                    self._session = session_id
                    self._scores.clear()
                    self._reasons.clear()
                if event.kind == EventKind.ALERT:
                    payload = dict(event.payload)
                    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                    entities = []
                    for key in ("source", "src", "dst", "destination", "endpoint_id"):
                        value = evidence.get(key) or payload.get(key)
                        if value:
                            entities.append(str(value))
                    title = str(payload.get("title") or "Security indicator")
                    score = SEVERITY_SCORE.get(event.severity, 0)
                    for entity in set(entities):
                        self._scores[entity] = max(self._scores[entity], score)
                        if title not in self._reasons[entity]:
                            self._reasons[entity].append(title)
                    self._publish()
                elif event.kind in {EventKind.OBSERVATION, EventKind.ACTION}:
                    if event.payload.get("type") == "PACKET" or event.kind == EventKind.ACTION:
                        self._publish()
                self.health.heartbeat(f"risk entities={len(self._scores)}")
        finally:
            await self.bus.unsubscribe(self.name)
