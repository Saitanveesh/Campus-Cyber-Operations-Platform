from campus_ops.workers.dns_intelligence import _rcode, _truthy


def test_dns_helpers() -> None:
    assert _truthy("1") is True
    assert _truthy("true") is True
    assert _truthy("0") is False
    assert _rcode("3") == 3
    assert _rcode("0x2") == 2
    assert _rcode("") is None
    assert _rcode("invalid") is None
