from campus_ops.workers.endpoint_deep_monitor import analyze_agent


def test_analyze_agent_correlates_processes_connections_and_listeners():
    agent = {
        "endpoint_id": "lab-01",
        "name": "LAB-01",
        "host": "10.0.0.10",
        "platform": "windows",
        "status": "ONLINE",
        "telemetry": {
            "users": ["student"],
            "processes": [
                {"pid": 100, "name": "tool.exe", "user": "student", "memory_percent": 4.2},
                {"pid": 200, "name": "server.exe", "user": "SYSTEM", "memory_percent": 1.0},
            ],
            "connection_sample": [
                {"type": "TCP", "local": "10.0.0.10:52000", "remote": "8.8.8.8:443", "status": "ESTABLISHED", "pid": 100},
                {"type": "TCP", "local": "10.0.0.10:3389", "remote": "", "status": "LISTEN", "pid": 200},
            ],
            "services": [
                {"name": "TermService", "status": "running"},
                {"name": "StoppedSvc", "status": "stopped"},
            ],
            "isolation_state": "NORMAL",
        },
    }

    result = analyze_agent(agent)

    assert result["process_count"] == 2
    assert result["remote_connection_count"] == 1
    assert result["listener_count"] == 1
    assert result["running_service_count"] == 1
    assert result["listeners"][0]["port"] == 3389
    assert result["listeners"][0]["administrative_port"] is True
    process = next(item for item in result["processes"] if item["pid"] == 100)
    assert process["public_peer_count"] == 1
    assert process["peer_count"] == 1
