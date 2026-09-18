import subprocess

from campus_ops.workers import windows_capture
from campus_ops.workers.windows_capture import _parse_tshark_interfaces


def test_tshark_interface_parser_keeps_npcap_guid_description():
    rows = _parse_tshark_interfaces(
        "1. \\Device\\NPF_{11111111-2222-3333-4444-555555555555} (Wi-Fi)\n"
        "2. \\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} (Ethernet)\n"
    )
    assert rows == [
        {
            "index": "1",
            "description": r"\Device\NPF_{11111111-2222-3333-4444-555555555555} (Wi-Fi)",
        },
        {
            "index": "2",
            "description": r"\Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} (Ethernet)",
        },
    ]


def test_tshark_interface_parser_rejects_non_interface_lines():
    rows = _parse_tshark_interfaces("npcap status\n1. Wi-Fi\nrandom text")
    assert rows == [{"index": "1", "description": "Wi-Fi"}]


def test_powershell_timeout_degrades_to_alias_fallback(monkeypatch):
    monkeypatch.setattr(windows_capture.os, "name", "nt")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=5)

    monkeypatch.setattr(windows_capture.subprocess, "run", timeout)

    assert windows_capture._powershell_json("Get-NetAdapter") == []
    assert windows_capture._adapter_guid("Wi-Fi") is None


def test_powershell_json_accepts_windows_bom(monkeypatch):
    monkeypatch.setattr(windows_capture.os, "name", "nt")

    class Result:
        returncode = 0
        stdout = '\ufeff{"InterfaceGuid":"{ABCDEF00-1111-2222-3333-444444444444}"}'
        stderr = ""

    monkeypatch.setattr(windows_capture.subprocess, "run", lambda *args, **kwargs: Result())

    assert windows_capture._adapter_guid("Wi-Fi") == "ABCDEF00-1111-2222-3333-444444444444"
