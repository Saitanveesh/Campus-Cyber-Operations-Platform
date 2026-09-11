from campus_ops.workers.operations_watchdog import OperationsWatchdogWorker


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "workers": {
            "capture": {"state": "HEALTHY", "detail": "ok", "optional": False},
            "operations-watchdog": {"state": "HEALTHY", "detail": "watching", "optional": False},
        },
        "event_bus": {
            "capture": {"queued": 0, "dropped": 0},
            "state-sink": {"queued": 0, "dropped": 0},
        },
        "response_jobs": [],
        "live": {
            "capture": {"state": "ACTIVE", "detail": "capturing"},
            "incidents": [],
        },
    }


def test_watchdog_reports_clean_snapshot():
    assert OperationsWatchdogWorker.evaluate(_snapshot()) == {}


def test_watchdog_detects_capture_failure_worker_failure_and_event_loss():
    snapshot = _snapshot()
    live = snapshot["live"]
    assert isinstance(live, dict)
    live["capture"] = {"state": "ERROR", "detail": "tshark exited"}

    workers = snapshot["workers"]
    assert isinstance(workers, dict)
    workers["flow-engine"] = {"state": "FAILED", "detail": "boom", "optional": False}

    bus = snapshot["event_bus"]
    assert isinstance(bus, dict)
    bus["flow-engine"] = {"queued": 0, "dropped": 3}

    conditions = OperationsWatchdogWorker.evaluate(snapshot)
    assert "capture-unavailable" in conditions
    assert "worker-failed:flow-engine" in conditions
    assert conditions["event-loss"]["count"] == 3


def test_watchdog_tracks_highest_open_incident_class():
    snapshot = _snapshot()
    live = snapshot["live"]
    assert isinstance(live, dict)
    live["incidents"] = [
        {"status": "OPEN", "severity": "HIGH"},
        {"status": "OPEN", "severity": "CRITICAL"},
        {"status": "CLOSED", "severity": "CRITICAL"},
    ]

    conditions = OperationsWatchdogWorker.evaluate(snapshot)
    assert "critical-incidents" in conditions
    assert conditions["critical-incidents"]["count"] == 1
    assert "high-incidents" not in conditions
