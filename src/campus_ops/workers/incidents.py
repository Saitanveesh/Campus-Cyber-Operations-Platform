from __future__ import annotations

import hashlib
import ipaddress
import json
import time
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
    """Correlate validated alerts by source while suppressing repeated identical evidence."""

    DUPLICATE_WINDOW_SECONDS = 120.0
    SIGNATURE_RETENTION_SECONDS = 900.0

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("incident-correlation", bus)
        self.state = state
        self.session_provider = session_provider
        self._keys: dict[str, str] = {}
        self._recent_signatures: dict[str, float] = {}
        self._session: str | None = None

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._keys.clear()
        self._recent_signatures.clear()

    @staticmethod
    def _source(evidence: dict[str, object]) -> str:
        raw = str(evidence.get("source") or evidence.get("src") or "").strip()
        if not raw:
            return "unknown"
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            return "unknown"
        if raw == "255.255.255.255":
            return "unknown"
        return str(ip)

    @staticmethod
    def _fingerprint(
        source: str,
        title: str,
        severity: str,
        evidence_class: str | None,
        evidence: dict[str, object],
    ) -> str:
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
        raw = f"{source}|{title}|{severity}|{evidence_class or ''}|{canonical}".encode()
        return hashlib.sha256(raw).hexdigest()

    def _prune_signatures(self, now: float) -> None:
        for key in [
            key
            for key, seen in self._recent_signatures.items()
            if now - seen > self.SIGNATURE_RETENTION_SECONDS
        ]:
            del self._recent_signatures[key]

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
                    self._reset(session_id)

                payload = dict(event.payload)
                evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                source = self._source(evidence)
                title = str(payload.get("title") or "Security indicator")

                if event.evidence_class == "ARP_OWNERSHIP_CHANGE" and source == "unknown":
                    self.health.heartbeat("ignored invalid ARP ownership alert source")
                    continue

                severity_value = event.severity.value
                signature = self._fingerprint(
                    source,
                    title,
                    severity_value,
                    event.evidence_class,
                    evidence,
                )
                now_mono = time.monotonic()
                self._prune_signatures(now_mono)

                correlation_key = (
                    source
                    if source != "unknown"
                    else f"unknown|{event.evidence_class or 'alert'}|{title}"
                )
                incident_id = self._keys.get(correlation_key)
                existing = self.state.get_incident(incident_id)

                last_duplicate = self._recent_signatures.get(signature)
                if last_duplicate is not None and now_mono - last_duplicate < self.DUPLICATE_WINDOW_SECONDS:
                    if existing and incident_id:
                        self.state.update_incident(
                            incident_id,
                            last_seen=datetime.now(UTC).isoformat(),
                            suppressed_repeats=int(existing.get("suppressed_repeats") or 0) + 1,
                        )
                    self.health.heartbeat("suppressed repeated identical alert evidence")
                    continue
                self._recent_signatures[signature] = now_mono

                is_new = not incident_id or not existing
                reopened = False
                escalated = False

                if is_new:
                    incident_id = str(uuid4())
                    self._keys[correlation_key] = incident_id
                    first_seen = event.timestamp.isoformat()
                    count = 0
                    status = "OPEN"
                    timeline: list[dict[str, object]] = []
                    severity = severity_value
                    confidence = int(payload.get("confidence") or 0)
                    alert_types: list[str] = []
                    suppressed_repeats = 0
                else:
                    first_seen = str(existing.get("first_seen") or event.timestamp.isoformat())
                    count = int(existing.get("alert_count") or 0)
                    status = str(existing.get("status") or "OPEN").upper()
                    timeline = list(existing.get("timeline") or [])[-99:]
                    previous_severity = str(existing.get("severity") or Severity.INFO.value).upper()
                    current_severity = severity_value
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
                    alert_types = [str(item) for item in existing.get("alert_types", []) if item]
                    suppressed_repeats = int(existing.get("suppressed_repeats") or 0)
                    if status == "CLOSED":
                        status = "OPEN"
                        reopened = True

                if title not in alert_types:
                    alert_types.append(title)

                timeline.append(
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "alert_event_id": event.event_id,
                        "severity": severity_value,
                        "title": title,
                        "evidence_class": event.evidence_class,
                        "evidence": evidence,
                    }
                )
                display_title = alert_types[0] if len(alert_types) == 1 else "Multiple security indicators"
                record = {
                    "id": incident_id,
                    "title": display_title,
                    "source": source,
                    "severity": severity,
                    "confidence": confidence,
                    "first_seen": first_seen,
                    "last_seen": datetime.now(UTC).isoformat(),
                    "alert_count": count + 1,
                    "suppressed_repeats": suppressed_repeats,
                    "alert_types": alert_types[-20:],
                    "status": status,
                    "latest_evidence": evidence,
                    "session_id": session_id,
                    "timeline": timeline,
                    "last_alert_event_id": event.event_id,
                }
                self.state.add_incident(incident_id, record)

                if is_new:
                    incident_type = "INCIDENT_OPENED"
                    voice = f"New {severity.lower()} severity incident. {display_title}."
                elif reopened:
                    incident_type = "INCIDENT_REOPENED"
                    voice = f"Incident reopened after new evidence. {display_title}."
                elif escalated:
                    incident_type = "INCIDENT_ESCALATED"
                    voice = f"Incident severity escalated to {severity.lower()}. {display_title}."
                else:
                    incident_type = "INCIDENT_UPDATED"
                    voice = None

                event_payload: dict[str, object] = {
                    "type": incident_type,
                    "incident_id": incident_id,
                    "title": display_title,
                    "source": source,
                    "status": status,
                    "severity": severity,
                    "alert_count": count + 1,
                    "alert_types": alert_types[-20:],
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
