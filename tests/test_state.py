from campus_ops.models import Event, EventKind
from campus_ops.state import LiveState


def test_live_state_rejects_wrong_session_and_clears() -> None:
    state = LiveState()
    state.start_session("session-a", "fingerprint")
    wrong = Event(source="test", kind=EventKind.OBSERVATION, session_id="session-b", payload={"x": 1})
    right = Event(source="test", kind=EventKind.OBSERVATION, session_id="session-a", payload={"x": 2})
    assert state.ingest_event(wrong) is False
    assert state.ingest_event(right) is True
    state.upsert_asset("10.0.0.1", {"ip": "10.0.0.1"})
    snapshot = state.snapshot()
    assert len(snapshot["events"]) == 1
    assert len(snapshot["assets"]) == 1

    state.close_session()
    cleared = state.snapshot()
    assert cleared["session_id"] is None
    assert cleared["events"] == []
    assert cleared["assets"] == []
    assert cleared["flows"] == []
    assert cleared["alerts"] == []


def test_new_session_never_reuses_old_live_collections() -> None:
    state = LiveState()
    state.start_session("old")
    state.upsert_asset("192.0.2.1", {"ip": "192.0.2.1"})
    state.increment_protocol("DNS", 5)
    state.start_session("new")
    snapshot = state.snapshot()
    assert snapshot["session_id"] == "new"
    assert snapshot["assets"] == []
    assert snapshot["protocols"] == {}
