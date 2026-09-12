from campus_ops.models import Event, EventKind, Severity
from campus_ops.state import LiveState


def test_operational_health_event_does_not_enter_security_alerts():
    state = LiveState()
    state.start_session("s1", "fp")
    state.ingest_event(
        Event(
            source="watchdog",
            kind=EventKind.HEALTH,
            session_id="s1",
            severity=Severity.HIGH,
            payload={"type": "WATCHDOG_STATUS", "title": "Capture failed"},
        )
    )
    assert state.snapshot()["alerts"] == []


def test_security_alert_enters_security_alerts():
    state = LiveState()
    state.start_session("s1", "fp")
    state.ingest_event(
        Event(
            source="detection",
            kind=EventKind.ALERT,
            session_id="s1",
            severity=Severity.HIGH,
            payload={"title": "Suspicious fan-out"},
        )
    )
    assert len(state.snapshot()["alerts"]) == 1
