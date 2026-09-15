from campus_ops.models import Event, EventKind, Severity
from campus_ops.workers.voice import VoiceAlertWorker


def test_medium_generic_alert_is_silent():
    event = Event(
        source="arp-guard",
        kind=EventKind.ALERT,
        severity=Severity.MEDIUM,
        payload={"title": "ARP ownership change", "voice": "ARP ownership changed."},
    )
    text, _priority, _critical = VoiceAlertWorker._event_speech(event)
    assert text is None


def test_high_incident_open_is_spoken_once_by_policy():
    event = Event(
        source="incident-correlation",
        kind=EventKind.INCIDENT,
        severity=Severity.HIGH,
        payload={
            "type": "INCIDENT_OPENED",
            "title": "Suspicious fan-out",
            "voice": "New high severity incident. Suspicious fan-out.",
        },
    )
    text, priority, critical = VoiceAlertWorker._event_speech(event)
    assert text == "New high severity incident. Suspicious fan-out."
    assert priority == 10
    assert critical is False


def test_incident_update_without_escalation_is_silent():
    event = Event(
        source="incident-correlation",
        kind=EventKind.INCIDENT,
        severity=Severity.HIGH,
        payload={"type": "INCIDENT_UPDATED", "title": "Suspicious fan-out"},
    )
    text, _priority, _critical = VoiceAlertWorker._event_speech(event)
    assert text is None
