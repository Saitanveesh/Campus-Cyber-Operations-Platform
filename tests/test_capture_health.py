from campus_ops.event_bus import EventBus
from campus_ops.state import LiveState
from campus_ops.workers.capture_health import CaptureHealthWorker


def test_capture_health_distinguishes_idle_from_suspect() -> None:
    state = LiveState()
    state.start_session("s1")
    state.set_capture(state="ACTIVE", packets=10, detail="capturing")
    state.update_metrics(rx_pps=0.0)
    worker = CaptureHealthWorker(EventBus(), state, lambda: "s1", suspect_checks=2)

    status, _ = worker._evaluate("s1")
    assert status == "IDLE"

    state.update_metrics(rx_pps=100.0)
    status, _ = worker._evaluate("s1")
    assert status == "OBSERVING"
    status, _ = worker._evaluate("s1")
    assert status == "SUSPECT"

    state.set_capture(packets=11)
    status, _ = worker._evaluate("s1")
    assert status == "OK"


def test_capture_health_reports_backend_error() -> None:
    state = LiveState()
    state.start_session("s1")
    state.set_capture(state="ERROR", packets=0, detail="permission denied")
    worker = CaptureHealthWorker(EventBus(), state, lambda: "s1")

    status, reason = worker._evaluate("s1")
    assert status == "DEGRADED"
    assert "permission denied" in reason
