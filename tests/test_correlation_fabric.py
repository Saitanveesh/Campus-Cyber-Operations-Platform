from types import SimpleNamespace

from campus_ops.correlation_fabric import _valid_ip


def test_valid_ip_rejects_unspecified_and_multicast():
    assert _valid_ip("10.20.30.40") is True
    assert _valid_ip("0.0.0.0") is False
    assert _valid_ip("224.0.0.1") is False


def test_valid_ip_accepts_ipv6_unicast():
    assert _valid_ip("2001:db8::10") is True
