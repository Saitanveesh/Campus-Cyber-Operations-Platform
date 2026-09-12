from campus_ops.workers.voice import VoiceAlertWorker


def test_startup_greeting_is_short():
    assert VoiceAlertWorker.STARTUP_GREETING == "Welcome back."


def test_voice_copy_removes_old_personalized_greeting():
    text = VoiceAlertWorker._clean_text(
        "Welcome back, Sai Tanveesh. Live Operations Console is starting."
    )
    assert text == "Welcome back."
    assert "Sai Tanveesh" not in VoiceAlertWorker._clean_text(
        "Sai Tanveesh, packet capture needs attention."
    )
