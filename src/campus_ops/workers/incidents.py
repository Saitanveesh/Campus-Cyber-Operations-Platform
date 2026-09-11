from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


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
                source = str(evidence.get("source") or evidence.get("src") or "unknown")
                title = str(payload.get("title") or "Security indicator")
                key = f"{source}|{title}"
                incident_id = self._keys.get(key)
                existing = self.state.get_incident(incident_id)
                is_new = not incident_id or not existing
                reopened = False
                escalated = False

                if is_new:
                    incident_id = str(uuid4())
                    self._keys[key] = incident_id
                    first_seen = event.timestamp.isoformat()
                    count = 0
                    status = "OPEN"
                    timeline: list[dict[str, object]] = []
                    severity = event.severity.value
                    confidence = int(payload.get("confidence") or 0)
                else:
                    first_seen = str(existing.get("first_seen") or event.timestamp.isoformat())
                    count = int(existing.get("alert_count") or 0)
                    status = str(existing.get("status") or "OPEN").upper()
                    timeline = list(existing.get("timeline") or [])[-99:]
                    previous_severity = str(existing.get("severity") or Severity.INFO.value).upper()
                    current_severity = event.severity.value
                    escalated = SEVERITY_RANK.get(current_severity, 0) > SEVERITY_RANK.get(
                        previous_severity, 0
                    )
                    severity = (
                        current_severity
                        if SEVERITY_RANK.get(current_severity, 0)
                        >= SEVERITY_RANK.get(previous_severity, 0)
                        else previous_severity
                    )
                    confidence = max(
                        int(existing.get("confidence") or 0),
                        int(payload.get("confidence") or 0),
                    )
                    if status == "CLOSED":
                        status = "OPEN"
                        reopened = True

                timeline.append(
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "alert_event_id": event.event_id,
                        "severity": event.severity.value,
                        "title": title,
                        "evidence": evidence,
                    }
                )
                record = {
                    "id": incident_id,
                    "title": title,
                    "source": source,
                    "severity": severity,
                    "confidence": confidence,
                    "first_seen": first_seen,
                    "last_seen": datetime.now(UTC).isoformat(),
                    "alert_count": count + 1,
                    "status": status,
                    "latest_evidence": evidence,
                    "session_id": session_id,
                    "timeline": timeline,
                    "last_alert_event_id": event.event_id,
                }
                self.state.add_incident(incident_id, record)

                if is_new:
                    incident_type = "INCIDENT_OPENED"
                    voice = f"New {severity.lower()} severity incident. {title}."
                elif reopened:
                    incident_type = "INCIDENT_REOPENED"
                    voice = f"Incident reopened after new evidence. {title}."
                elif escalated:
                    incident_type = "INCIDENT_ESCALATED"
                    voice = f"Incident severity escalated to {severity.lower()}. {title}."
                else:
                    incident_type = "INCIDENT_UPDATED"
                    voice = None

                event_payload: dict[str, object] = {
                    "type": incident_type,
                    "incident_id": incident_id,
                    "title": title,
                    "source": source,
                    "status": status,
                    "severity": severity,
                    "alert_count": count + 1,
                    "confidence": confidence,
                }
                if voice:
                    event_payload["voice"] = voice

                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.INCIDENT,
                        session_id=session_id,
                        severity=Severity(severity),
                        evidence_class="CORRELATED_ALERTS",
                        payload=event_payload,
                    )
                )
                self.health.heartbeat(f"incidents={self.state.incident_count()}")
        finally:
            await self.bus.unsubscribe(self.name)
