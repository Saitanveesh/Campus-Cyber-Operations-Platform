from campus_ops.enterprise_telemetry import telemetry_fabric_status


def test_telemetry_fabric_truthful_shape():
    state = telemetry_fabric_status()
    assert state["state"] in {"READY", "PARTIAL", "BASELINE_ONLY"}
    assert state["total_tools"] >= 10
    assert len(state["tools"]) == state["total_tools"]
    assert {"gnmi", "netconf", "restconf", "syslog"}.issubset(state["streaming_telemetry"])
    for tool in state["tools"]:
        assert tool["state"] in {"READY_NATIVE", "READY_WSL", "NOT_INSTALLED", "NOT_APPLICABLE",
                                 "REQUIRES_DEPLOYMENT", "READY_LISTENING", "READY_RECEIVING",
                                 "NOT_RUNNING", "WAITING_INTERFACE", "FAILED", "BLOCKED",
                                 "EXTERNAL_SERVICE", "RETRY_WAIT", "STOPPED"}


def test_unconfigured_streaming_telemetry_is_not_faked(monkeypatch):
    for name in (
        "CAMPUS_OPS_GNMI_TARGETS",
        "CAMPUS_OPS_NETCONF_TARGETS",
        "CAMPUS_OPS_RESTCONF_TARGETS",
        "CAMPUS_OPS_SYSLOG_PORT",
    ):
        monkeypatch.delenv(name, raising=False)
    state = telemetry_fabric_status()
    assert all(row["state"] == "NOT_CONFIGURED" for row in state["streaming_telemetry"].values())
