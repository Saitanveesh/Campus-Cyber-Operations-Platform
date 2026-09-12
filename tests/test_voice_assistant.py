from campus_ops.models import Event, EventKind, Severity
from campus_ops.workers.voice import VoiceAlertWorker


def test_generic_critical_alert_is_not_spoken_before_correlation():
    event = Event(
        source="test",
        kind=EventKind.ALERT,
        severity=Severity.CRITICAL,
        payload={"title": "Critical indicator"},
    )
    text, _priority, _critical = VoiceAlertWorker._event_speech(event)
    assert text is None


def test_active_high_watchdog_health_event_is_spoken():
    event = Event(
        source="operations-watchdog",
        kind=EventKind.HEALTH,
        severity=Severity.HIGH,
        payload={"state": "ACTIVE", "voice": "Packet capture needs attention."},
    )
    text, priority, critical = VoiceAlertWorker._event_speech(event)
    assert text == "Packet capture needs attention."
    assert priority == 5
    assert critical is False


def test_resolved_watchdog_health_event_is_silent():
    event = Event(
        source="operations-watchdog",
        kind=EventKind.HEALTH,
        severity=Severity.INFO,
        payload={"state": "RESOLVED", "voice": "Resolved."},
    )
    text, _, _ = VoiceAlertWorker._event_speech(event)
    assert text is None


def test_normal_observation_is_not_spoken():
    event = Event(source="capture", kind=EventKind.OBSERVATION, payload={"type": "PACKET"})
    text, _, _ = VoiceAlertWorker._event_speech(event)
    assert text is None
