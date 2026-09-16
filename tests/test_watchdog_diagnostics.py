from campus_ops.watchdog_api import _diagnostics


def _snapshot(capture_state: str = "ACTIVE", pid: int = 4321) -> dict[str, object]:
    return {
        "session_id": "session-1",
        "network": {"interface": "eth0"},
        "workers": {
            "network-discovery": {"state": "HEALTHY", "detail": "selected eth0"},
            "capture": {"state": "HEALTHY", "detail": "capture active"},
        },
        "event_bus": {
            "session-manager": {"queued": 0, "dropped": 0, "capacity": 2048},
        },
        "live": {
            "capture": {
                "state": capture_state,
                "backend": "tshark",
                "interface": "eth0",
                "process_pid": pid,
                "detail": "capture active on eth0 via tshark",
            }
        },
    }


def test_watchdog_healthy_snapshot_has_no_problem():
    # Use current process PID so the POSIX liveness check is valid in CI.
    import os

    report = _diagnostics(_snapshot(pid=os.getpid()))
    assert report["state"] == "HEALTHY"
    assert report["problem_count"] == 0


def test_watchdog_failure_contains_evidence_cause_fix_and_verification():
    report = _diagnostics(_snapshot(capture_state="ERROR", pid=0))
    assert report["state"] == "ATTENTION"
    assert report["problem_count"] >= 1
    for problem in report["problems"]:
        assert problem["problem"]
        assert problem["evidence"]
        assert problem["cause"]
        assert problem["fix"]
        assert problem["verify"]
