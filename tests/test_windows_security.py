from campus_ops.workers.windows_security import WindowsSecurityTelemetryWorker


def test_windows_security_normalizes_defender_firewall_and_sysmon():
    result = WindowsSecurityTelemetryWorker.normalize(
        {
            "defender": {
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "BehaviorMonitorEnabled": False,
                "IoavProtectionEnabled": True,
                "NISEnabled": True,
                "AntivirusSignatureLastUpdated": "2026-09-12T08:00:00",
            },
            "firewall": [
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True},
                {"Name": "Public", "Enabled": False},
            ],
            "sysmon": {"Name": "Sysmon64", "Status": "Running"},
        }
    )

    assert result["available"] is True
    assert result["defender"]["realtime_enabled"] is True
    assert result["defender"]["behavior_monitor_enabled"] is False
    assert result["firewall"]["Domain"] is True
    assert result["firewall"]["Public"] is False
    assert result["sysmon"] == [{"name": "Sysmon64", "status": "Running"}]


def test_windows_security_accepts_single_firewall_object():
    result = WindowsSecurityTelemetryWorker.normalize(
        {"firewall": {"Name": "Private", "Enabled": "True"}, "sysmon": []}
    )
    assert result["firewall"] == {"Private": True}
