from campus_ops.workers.operations_watchdog import OperationsWatchdogWorker


def _snapshot() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "network": {"interface": "Wi-Fi"},
        "workers": {
            "capture": {"state": "HEALTHY", "detail": "ok", "optional": False},
            "operations-watchdog": {"state": "HEALTHY", "detail": "watching", "optional": False},
        },
        "event_bus": {
            "capture": {"queued": 0, "dropped": 0, "capacity": 2048},
            "state-sink": {"queued": 0, "dropped": 0, "capacity": 2048},
        },
        "response_jobs": [],
        "managed_agents": [],
        "tools": [],
        "live": {
            "capture": {"state": "ACTIVE", "detail": "capturing"},
            "metrics": {},
            "incidents": [],
            "assets": [],
            "flows": [],
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
    bus["flow-engine"] = {"queued": 0, "dropped": 3, "capacity": 2048}

    conditions = OperationsWatchdogWorker.evaluate(snapshot)
    assert "capture-unavailable" in conditions
    assert "worker-failed:flow-engine" in conditions
    assert conditions["event-loss"]["count"] == 3


def test_watchdog_detects_pipeline_pressure_before_drop():
    snapshot = _snapshot()
    bus = snapshot["event_bus"]
    assert isinstance(bus, dict)
    bus["flow-engine"] = {"queued": 1800, "dropped": 0, "capacity": 2048}

    conditions = OperationsWatchdogWorker.evaluate(snapshot)
    assert "event-pressure" in conditions
    assert "1800/2048" in conditions["event-pressure"]["detail"]


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


def test_watchdog_builds_human_operational_briefing():
    snapshot = _snapshot()
    live = snapshot["live"]
    assert isinstance(live, dict)
    live["assets"] = [{"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}]
    live["flows"] = [{"src": "10.0.0.2", "dst": "10.0.0.3"}]

    text = OperationsWatchdogWorker.briefing(snapshot)
    assert "Sai Tanveesh" not in text
    assert "Wi-Fi" in text
    assert "2 assets" in text
    assert "1 active flows" in text
    assert "no open incidents" in text


def test_watchdog_briefing_identifies_highest_priority_incident():
    snapshot = _snapshot()
    live = snapshot["live"]
    assert isinstance(live, dict)
    live["incidents"] = [
        {
            "status": "OPEN",
            "severity": "HIGH",
            "title": "Suspicious fan-out",
            "source": "10.0.0.22",
            "confidence": 91,
            "last_seen": "2026-09-12T03:00:00+00:00",
            "latest_evidence": {"unique_destinations": 17},
        }
    ]

    text = OperationsWatchdogWorker.briefing(snapshot)
    assert "Suspicious fan-out" in text
    assert "10.0.0.22" in text
    assert "17 destinations" in text


def test_watchdog_detects_disabled_defender_and_firewall_profile():
    snapshot = _snapshot()
    live = snapshot["live"]
    assert isinstance(live, dict)
    metrics = live["metrics"]
    assert isinstance(metrics, dict)
    metrics["windows_security"] = {
        "available": True,
        "defender": {"antivirus_enabled": True, "realtime_enabled": False},
        "firewall": {"Domain": True, "Private": True, "Public": False},
    }

    conditions = OperationsWatchdogWorker.evaluate(snapshot)
    assert "defender-protection-disabled" in conditions
    assert "firewall-profiles-disabled" in conditions
    assert conditions["firewall-profiles-disabled"]["count"] == 1
