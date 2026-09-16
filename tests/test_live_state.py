from campus_ops.models import Event, EventKind
from campus_ops.state import LiveState


def test_live_state_rejects_stale_session_events():
    state = LiveState()
    state.start_session("session-new", "fingerprint")

    stale = Event(
        source="test",
        kind=EventKind.OBSERVATION,
        session_id="session-old",
        payload={"type": "TEST"},
    )
    assert state.ingest_event(stale) is False
    assert state.snapshot()["events"] == []


def test_starting_new_session_clears_live_objects():
    state = LiveState()
    state.start_session("session-a", "fp-a")
    state.upsert_asset("10.0.0.2", {"ip": "10.0.0.2"})
    state.upsert_flow("flow", {"id": "flow"})
    state.upsert_edge("edge", {"id": "edge"})
    state.update_metrics(rx_bps=123)

    state.start_session("session-b", "fp-b")
    snapshot = state.snapshot()

    assert snapshot["session_id"] == "session-b"
    assert snapshot["network_fingerprint"] == "fp-b"
    assert snapshot["assets"] == []
    assert snapshot["flows"] == []
    assert snapshot["topology_edges"] == []
    assert snapshot["metrics"] == {}


def test_incident_status_update_is_current_session_only():
    state = LiveState()
    state.start_session("session-a", "fp-a")
    state.add_incident("inc-1", {"id": "inc-1", "status": "OPEN"})

    updated = state.update_incident("inc-1", status="ACKNOWLEDGED")
    assert updated is not None
    assert updated["status"] == "ACKNOWLEDGED"

    state.close_session()
    assert state.get_incident("inc-1") == {}
