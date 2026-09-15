from __future__ import annotations

from collections import Counter

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

WEIGHTS = {"INFO": 0, "LOW": 5, "MEDIUM": 20, "HIGH": 45, "CRITICAL": 80}


class ThreatEngineWorker(BaseWorker):
    """Aggregates evidence-backed alert pressure into a live threat posture score."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("threat-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._severity: Counter[str] = Counter()
        self._sources: Counter[str] = Counter()
        self._titles: Counter[str] = Counter()

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
                    self._severity.clear()
                    self._sources.clear()
                    self._titles.clear()
                if event.kind != EventKind.ALERT:
                    continue
                payload = dict(event.payload)
                evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                severity = event.severity.value
                title = str(payload.get("title") or "Security alert")
                source = str(evidence.get("source") or event.source)
                self._severity[severity] += 1
                self._sources[source] += 1
                self._titles[title] += 1
                weighted = sum(WEIGHTS.get(level, 0) * count for level, count in self._severity.items())
                score = min(100, weighted)
                self.state.update_metrics(
                    threat_score=score,
                    threat_alert_counts=dict(self._severity),
                    threat_sources=dict(self._sources.most_common(20)),
                    threat_indicators=dict(self._titles.most_common(20)),
                )
                self.health.heartbeat(f"score={score} alerts={sum(self._severity.values())}")
        finally:
            await self.bus.unsubscribe(self.name)
