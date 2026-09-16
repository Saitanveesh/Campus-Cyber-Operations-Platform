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
