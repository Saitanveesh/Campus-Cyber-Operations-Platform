import ipaddress

import pytest

from campus_ops.authorized_discovery import _private_scope
from campus_ops.enterprise_telemetry import TOOLS
from campus_ops.runtime_ui import _clean_console_copy


def test_operational_console_copy_is_renamed():
    html = "<title>Live Operations Console</title><div>LIVE OPERATIONS CONSOLE</div>"
    cleaned = _clean_console_copy(html)
    assert "Operational Console" in cleaned
    assert "OPERATIONAL CONSOLE" in cleaned
    assert "Live Operations Console" not in cleaned


def test_discovery_allows_private_host_and_small_private_network():
    assert str(_private_scope("10.20.80.25", network_allowed=False)) == "10.20.80.25"
    network = _private_scope("10.20.80.0/24", network_allowed=True)
    assert isinstance(network, ipaddress.IPv4Network)
    assert network.num_addresses == 256


def test_discovery_rejects_public_or_large_scope():
    with pytest.raises(ValueError):
        _private_scope("8.8.8.8", network_allowed=False)
    with pytest.raises(ValueError):
        _private_scope("10.0.0.0/16", network_allowed=True)


def test_enterprise_tool_registry_contains_major_planes():
    names = {row[0] for row in TOOLS}
    for expected in (
        "TShark",
        "Zeek",
        "Suricata",
        "Arkime",
        "Nmap",
        "Angry IP Scanner",
        "osquery",
        "Velociraptor",
        "Sigma",
        "YARA",
    ):
        assert expected in names
