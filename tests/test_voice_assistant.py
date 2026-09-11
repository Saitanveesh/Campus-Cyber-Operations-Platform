from campus_ops.models import Event, EventKind, Severity
from campus_ops.workers.voice import VoiceAlertWorker


def test_critical_alert_has_top_voice_priority():
    event = Event(
        source="test",
        kind=EventKind.ALERT,
        severity=Severity.CRITICAL,
        payload={"title": "Critical incident"},
    )
    text, priority, critical = VoiceAlertWorker._event_speech(event)
    assert text == "Critical incident"
    assert priority == 0
    assert critical is True


def test_watchdog_health_event_is_spoken():
    event = Event(
        source="operations-watchdog",
        kind=EventKind.HEALTH,
        severity=Severity.HIGH,
        payload={"voice": "Packet capture needs attention."},
    )
    text, priority, critical = VoiceAlertWorker._event_speech(event)
    assert text == "Packet capture needs attention."
    assert priority == 5
    assert critical is False


def test_normal_observation_is_not_spoken():
    event = Event(source="capture", kind=EventKind.OBSERVATION, payload={"type": "PACKET"})
    text, _, _ = VoiceAlertWorker._event_speech(event)
    assert text is None
