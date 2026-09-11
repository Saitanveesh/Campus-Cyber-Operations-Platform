from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class IncidentCorrelationWorker(BaseWorker):
    """Groups evidence-backed alerts into current-session incident records."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("incident-correlation", bus)
        self.state = state
        self.session_provider = session_provider
        self._keys: dict[str, str] = {}
        self._session: str | None = None

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id or event.kind != EventKind.ALERT:
                    continue
                if self._session != session_id:
                    self._session = session_id
                    self._keys.clear()
                payload = dict(event.payload)
                evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                source = str(evidence.get("source") or "unknown")
                title = str(payload.get("title") or "Security indicator")
                key = f"{source}|{title}"
                incident_id = self._keys.get(key)
                existing = self.state.get_incident(incident_id)
                if not incident_id or not existing:
                    incident_id = str(uuid4())
                    self._keys[key] = incident_id
                    first_seen = event.timestamp.isoformat()
                    count = 0
                else:
                    first_seen = str(existing.get("first_seen") or event.timestamp.isoformat())
                    count = int(existing.get("alert_count") or 0)
                record = {
                    "id": incident_id,
                    "title": title,
                    "source": source,
                    "severity": event.severity.value,
                    "confidence": payload.get("confidence", 0),
                    "first_seen": first_seen,
                    "last_seen": datetime.now(UTC).isoformat(),
                    "alert_count": count + 1,
                    "status": "OPEN",
                    "latest_evidence": evidence,
                    "session_id": session_id,
                }
                self.state.add_incident(incident_id, record)
                self.health.heartbeat(f"open incidents={self.state.incident_count()}")
        finally:
            await self.bus.unsubscribe(self.name)
