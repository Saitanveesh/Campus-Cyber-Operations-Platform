from campus_ops.workers.service_intelligence import service_name


def test_common_service_names() -> None:
    assert service_name("tcp", 443) == "HTTPS"
    assert service_name("UDP", "53") == "DNS"
    assert service_name("tcp", 3389) == "RDP"


def test_unknown_service_keeps_transport_and_port() -> None:
    assert service_name("TCP", 65000) == "TCP/65000"
    assert service_name("UDP", "not-a-port") == "UNKNOWN"
