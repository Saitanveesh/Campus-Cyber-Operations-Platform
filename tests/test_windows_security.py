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


def test_windows_security_uses_raw_firewall_value_when_json_value_is_unknown():
    result = WindowsSecurityTelemetryWorker.normalize(
        {
            "firewall": [
                {"Name": "Domain", "Enabled": None, "EnabledRaw": "True"},
                {"Name": "Private", "Enabled": None, "EnabledRaw": "False"},
            ]
        }
    )
    assert result["firewall"] == {"Domain": True, "Private": False}


def test_windows_security_converts_legacy_powershell_date():
    result = WindowsSecurityTelemetryWorker.normalize(
        {
            "defender": {
                "AntivirusSignatureLastUpdated": "/Date(1789150340000)/",
            }
        }
    )
    timestamp = result["defender"]["signature_updated"]
    assert isinstance(timestamp, str)
    assert timestamp.startswith("2026-")
