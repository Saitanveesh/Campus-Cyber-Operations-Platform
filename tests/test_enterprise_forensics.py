from campus_ops.enterprise_forensics import parse_sysmon_message, structured_sysmon


def test_parse_sysmon_message_extracts_network_fields() -> None:
    parsed = parse_sysmon_message(
        """
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
ProcessId: 4242
User: LAB\\student
SourceIp: 10.20.87.55
DestinationIp: 10.20.87.10
DestinationPort: 445
"""
    )
    assert parsed["image"].endswith("powershell.exe")
    assert parsed["processid"] == "4242"
    assert parsed["destinationip"] == "10.20.87.10"
    assert parsed["destinationport"] == "445"


def test_structured_sysmon_preserves_raw_fields() -> None:
    rows = structured_sysmon(
        [
            {
                "record_id": 10,
                "event_id": 3,
                "time": "2026-09-12T10:00:00+00:00",
                "message": "Image: C:\\x.exe\nDestinationIp: 8.8.8.8\nDestinationPort: 443",
            }
        ]
    )
    assert rows[0]["event_id"] == 3
    assert rows[0]["destination_ip"] == "8.8.8.8"
    assert rows[0]["destination_port"] == "443"
    assert rows[0]["fields"]["image"] == "C:\\x.exe"
