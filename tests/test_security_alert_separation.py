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


def test_invalid_unspecified_arp_source_is_rejected_from_live_security_state():
    state = LiveState()
    state.start_session("s1", "fp")
    accepted = state.ingest_event(
        Event(
            source="arp-guard",
            kind=EventKind.ALERT,
            session_id="s1",
            severity=Severity.MEDIUM,
            evidence_class="ARP_OWNERSHIP_CHANGE",
            payload={
                "title": "Confirmed ARP ownership change",
                "evidence": {
                    "source": "0.0.0.0",
                    "previous_mac": "00:11:22:33:44:55",
                    "observed_mac": "00:11:22:33:44:66",
                },
            },
        )
    )
    assert accepted is False
    assert state.snapshot()["alerts"] == []
    assert state.snapshot()["events"] == []
