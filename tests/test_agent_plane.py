from campus_ops.agent_plane import AgentRegistry


def test_agent_enrollment_auth_heartbeat_and_jobs(tmp_path):
    registry = AgentRegistry(tmp_path / "agents.json")
    enrolled = registry.enroll("lab-01", "LAB-01", "windows", "10.0.0.10")
    token = enrolled["enrollment_token"]

    assert registry.authenticate("lab-01", token)
    assert not registry.authenticate("lab-01", "wrong")

    updated = registry.heartbeat(
        "lab-01",
        token,
        host="LAB-01",
        version="0.3.0",
        telemetry={"cpu_percent": 12.5},
    )
    assert updated["status"] == "ONLINE"
    assert updated["telemetry"]["cpu_percent"] == 12.5

    queued = registry.queue_job("lab-01", "COLLECT_SNAPSHOT", {})
    claimed = registry.claim_jobs("lab-01", token)
    assert [item["job_id"] for item in claimed] == [queued["job_id"]]
    result = registry.report_job(
        "lab-01",
        token,
        queued["job_id"],
        "SUCCEEDED",
        {"ok": True},
    )
    assert result["status"] == "SUCCEEDED"
    assert result["result"] == {"ok": True}
