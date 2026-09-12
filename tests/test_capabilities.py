from campus_ops.capabilities import capability_status


def test_capability_status_scores_ready_core_capabilities():
    tools = [
        {"key": "npcap", "available": True},
        {"key": "tshark", "available": True},
        {"key": "dumpcap", "available": True},
        {"key": "powershell", "available": True},
        {"key": "wevtutil", "available": True},
        {"key": "suricata", "available": False},
        {"key": "yara", "available": True},
        {"key": "pktmon", "available": True},
        {"key": "netsh", "available": True},
    ]
    healthy = {"state": "HEALTHY"}
    workers = {
        "capture": healthy,
        "flow-engine": healthy,
        "protocol-engine": healthy,
        "forensic-pcap": healthy,
        "malware-analysis": healthy,
        "local-host-telemetry": healthy,
        "endpoint-identity": healthy,
        "windows-security-telemetry": healthy,
        "syslog-receiver": healthy,
        "flow-telemetry-receiver": healthy,
        "snmp-poller": healthy,
        "infrastructure-intelligence": healthy,
        "topology-engine": healthy,
        "asset-engine": healthy,
        "identity-engine": healthy,
        "risk-graph": healthy,
        "job-scheduler": healthy,
    }

    result = capability_status({"tools": tools, "workers": workers})

    assert result["score"] >= 70
    assert result["core_ready"] == result["core_total"]
    rows = {row["key"]: row for row in result["capabilities"]}
    assert rows["live_packet_visibility"]["state"] == "READY"
    assert rows["windows_security_posture"]["state"] == "READY"
    assert rows["network_ids"]["state"] in {"PARTIAL", "MISSING"}


def test_capability_status_reports_missing_packet_tooling():
    result = capability_status(
        {
            "tools": [
                {"key": "npcap", "available": False},
                {"key": "tshark", "available": False},
            ],
            "workers": {},
        }
    )
    rows = {row["key"]: row for row in result["capabilities"]}
    packet = rows["live_packet_visibility"]
    assert packet["state"] == "MISSING"
    assert "npcap" in packet["missing_tools"]
    assert "tshark" in packet["missing_tools"]
