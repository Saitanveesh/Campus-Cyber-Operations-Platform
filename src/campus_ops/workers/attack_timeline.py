from __future__ import annotations

from collections import deque

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class AttackTimelineWorker(BaseWorker):
    """Current-session security/action timeline for investigation and after-action review."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("attack-timeline", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._items: deque[dict[str, object]] = deque(maxlen=500)

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
                    self._items.clear()
                if event.kind not in {EventKind.ALERT, EventKind.INCIDENT, EventKind.ACTION}:
                    continue
                payload = dict(event.payload)
                evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                item: dict[str, object] = {
                    "timestamp": event.timestamp.isoformat(),
                    "kind": event.kind.value,
                    "severity": event.severity.value,
                    "source": event.source,
                    "title": payload.get("title") or payload.get("message") or payload.get("action") or event.kind.value,
                    "entity": evidence.get("source") or payload.get("endpoint_id") or payload.get("incident_id"),
                    "event_id": event.event_id,
                }
                self._items.appendleft(item)
                self.state.update_metrics(attack_timeline=list(self._items))
                self.health.heartbeat(f"timeline={len(self._items)}")
        finally:
            await self.bus.unsubscribe(self.name)
