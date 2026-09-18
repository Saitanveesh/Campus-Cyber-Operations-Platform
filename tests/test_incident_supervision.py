import asyncio

import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity
from campus_ops.state import LiveState
from campus_ops.workers.incidents import IncidentCorrelationWorker


async def _wait_for_incident(state: LiveState, count: int, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while state.incident_count() < count:
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("incident was not created in time")
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_incident_keeps_highest_severity_and_reopens_on_new_evidence():
    bus = EventBus()
    state = LiveState()
    session_id = "session-1"
    state.start_session(session_id, "fingerprint")
    worker = IncidentCorrelationWorker(bus, state, lambda: session_id)
    await worker.start()
    await asyncio.sleep(0)

    try:
        await bus.publish(
            Event(
                source="test",
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.HIGH,
                payload={
                    "title": "Suspicious fan-out",
                    "confidence": 80,
                    "evidence": {"source": "10.0.0.22"},
                },
            )
        )
        await _wait_for_incident(state, 1)
        incident = state.snapshot()["incidents"][0]
        incident_id = incident["id"]
        assert incident["severity"] == "HIGH"

        await bus.publish(
            Event(
                source="test",
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.MEDIUM,
                payload={
                    "title": "Suspicious fan-out",
                    "confidence": 60,
                    "evidence": {"source": "10.0.0.22"},
                },
            )
        )
        await asyncio.sleep(0.05)
        incident = state.get_incident(incident_id)
        assert incident["severity"] == "HIGH"
        assert incident["confidence"] == 80

        state.update_incident(incident_id, status="CLOSED")
        await bus.publish(
            Event(
                source="test",
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.CRITICAL,
                payload={
                    "title": "Suspicious fan-out",
                    "confidence": 95,
                    "evidence": {"source": "10.0.0.22"},
                },
            )
        )
        await asyncio.sleep(0.05)
        incident = state.get_incident(incident_id)
        assert incident["status"] == "OPEN"
        assert incident["severity"] == "CRITICAL"
        assert incident["confidence"] == 95
    finally:
        await worker.stop()
