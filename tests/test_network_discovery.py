from campus_ops.models import NetworkCandidate
from campus_ops.workers.network_discovery import elect_network, score_candidate


def candidate(name: str, **overrides) -> NetworkCandidate:
    base = {
        "name": name,
        "is_up": True,
        "is_loopback": False,
        "ipv4": ("192.0.2.10",),
        "ipv6": (),
        "default_route": False,
        "route_metric": None,
        "bytes_recv": 100,
        "bytes_sent": 100,
        "category": "ethernet",
    }
    base.update(overrides)
    return NetworkCandidate(**base)


def test_default_route_wins_interface_election():
    local_only = candidate("Ethernet 2")
    routed = candidate("Ethernet", default_route=True, route_metric=5)
    selected = elect_network([local_only, routed])
    assert selected is not None
    assert selected.interface == "Ethernet"


def test_virtual_interface_is_penalized():
    physical = candidate("Ethernet")
    virtual = candidate("vEthernet", default_route=True, category="virtual")
    physical_score, _ = score_candidate(physical)
    virtual_score, _ = score_candidate(virtual)
    assert physical_score > 0
    assert virtual_score > 0
    assert virtual_score < physical_score + 45


def test_down_interface_is_not_viable():
    selected = elect_network([candidate("Ethernet", is_up=False)])
    assert selected is None
