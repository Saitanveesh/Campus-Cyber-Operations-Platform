from campus_ops.workers.tcp_intelligence import _flag_value


def test_tcp_flag_parser_accepts_tshark_hex():
    assert _flag_value("0x0002") == 0x02
    assert _flag_value("0x0012") == 0x12


def test_tcp_flag_parser_fails_closed():
    assert _flag_value("") == 0
    assert _flag_value("not-a-flag") == 0
