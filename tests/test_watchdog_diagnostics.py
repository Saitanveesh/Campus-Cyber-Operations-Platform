import campus_ops.watchdog_api as watchdog


def _snapshot(capture_state: str = "ACTIVE", pid: int = 4321) -> dict[str, object]:
    return {
        "session_id": "session-1",
        "network": {"interface": "Wi-Fi"},
        "workers": {
            "network-discovery": {"state": "HEALTHY", "detail": "selected Wi-Fi"},
            "capture": {"state": "HEALTHY", "detail": "capture active"},
            "evidence-store": {"state": "HEALTHY", "detail": "history active"},
        },
        "event_bus": {
            "session-manager": {"queued": 0, "dropped": 0, "capacity": 2048},
        },
        "live": {
            "capture": {
                "state": capture_state,
                "backend": "tshark",
                "interface": "Wi-Fi",
                "capture_device": "4",
                "process_pid": pid,
                "detail": "capture active on Wi-Fi via tshark",
            }
        },
    }


def test_watchdog_healthy_snapshot_has_no_problem(monkeypatch):
    monkeypatch.setattr(watchdog.os, "name", "nt")
    monkeypatch.setattr(watchdog, "_pid_is_tshark", lambda pid: (True, f"tshark pid {pid}"))
    report = watchdog._diagnostics(_snapshot())
    assert report["state"] == "HEALTHY"
    assert report["problem_count"] == 0


def test_watchdog_failure_contains_evidence_cause_fix_and_verification(monkeypatch):
    monkeypatch.setattr(watchdog.os, "name", "nt")
    monkeypatch.setattr(watchdog, "_pid_is_tshark", lambda pid: (False, "no PID"))
    report = watchdog._diagnostics(_snapshot(capture_state="ERROR", pid=0))
    assert report["state"] == "ATTENTION"
    assert report["problem_count"] >= 1
    for problem in report["problems"]:
        assert problem["problem"]
        assert problem["evidence"]
        assert problem["cause"]
        assert problem["fix"]
        assert problem["verify"]
