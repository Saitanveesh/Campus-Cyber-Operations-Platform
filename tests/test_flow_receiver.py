import ipaddress
import struct

from campus_ops.workers.flow_receiver import IpfixTemplateCache, decode_ipfix, decode_netflow_v5


def test_decode_netflow_v5_record():
    header = struct.pack("!HHIIIIBBH", 5, 1, 1000, 1700000000, 0, 7, 0, 0, 0)
    record = struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        ipaddress.IPv4Address("10.0.0.10").packed,
        ipaddress.IPv4Address("8.8.8.8").packed,
        ipaddress.IPv4Address("10.0.0.1").packed,
        1,
        2,
        10,
        1000,
        100,
        500,
        12345,
        53,
        0,
        0x10,
        17,
        0,
        0,
        0,
        24,
        0,
        0,
    )
    rows = decode_netflow_v5(header + record, "10.0.0.254")
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "10.0.0.10"
    assert rows[0]["dst_ip"] == "8.8.8.8"
    assert rows[0]["dst_port"] == 53
    assert rows[0]["transport"] == "UDP"
    assert rows[0]["packets"] == 10


def test_ipfix_template_and_data_decode():
    cache = IpfixTemplateCache()
    template_body = struct.pack("!HHHHHHHH", 256, 3, 8, 4, 12, 4, 2, 8)
    template_set = struct.pack("!HH", 2, 4 + len(template_body)) + template_body
    template_message = struct.pack(
        "!HHIII",
        10,
        16 + len(template_set),
        1700000000,
        1,
        42,
    ) + template_set
    assert decode_ipfix(template_message, "10.0.0.254", cache) == []

    data_body = (
        ipaddress.IPv4Address("10.0.0.5").packed
        + ipaddress.IPv4Address("1.1.1.1").packed
        + (123).to_bytes(8, "big")
    )
    data_set = struct.pack("!HH", 256, 4 + len(data_body)) + data_body
    data_message = struct.pack(
        "!HHIII",
        10,
        16 + len(data_set),
        1700000001,
        2,
        42,
    ) + data_set
    rows = decode_ipfix(data_message, "10.0.0.254", cache)
    assert rows[0]["src_ip"] == "10.0.0.5"
    assert rows[0]["dst_ip"] == "1.1.1.1"
    assert rows[0]["packets"] == 123
