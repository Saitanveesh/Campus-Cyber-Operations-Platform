import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import NetworkCandidate, SelectedNetwork
from campus_ops.workers.network_discovery import (
    NetworkDiscoveryWorker,
    elect_network,
    score_candidate,
)


def candidate(name: str, **overrides) -> NetworkCandidate:
    base = {
        "name": name,
        "is_up": True,
        "is_loopback": False,
        "ipv4": ("192.0.2.10",),
        "ipv6": (),
        "prefixes": ("192.0.2.0/24",),
        "default_route": False,
        "route_metric": None,
        "gateway": None,
        "bytes_recv": 100,
        "bytes_sent": 100,
        "category": "ethernet",
    }
    base.update(overrides)
    return NetworkCandidate(**base)


def selected(**overrides) -> SelectedNetwork:
    base = {
        "interface": "Ethernet",
        "score": 100,
        "reasons": ("up",),
        "ipv4": ("192.0.2.10",),
        "ipv6": (),
        "prefixes": ("192.0.2.0/24",),
        "default_route": True,
        "route_metric": 5,
        "gateway": "192.0.2.1",
    }
    base.update(overrides)
    return SelectedNetwork(**base)


def test_default_route_wins_interface_election():
    local_only = candidate("Ethernet 2")
    routed = candidate("Ethernet", default_route=True, route_metric=5)
    chosen = elect_network([local_only, routed])
    assert chosen is not None
    assert chosen.interface == "Ethernet"


def test_virtual_interface_is_penalized():
    physical = candidate("Ethernet")
    virtual = candidate("vEthernet", default_route=True, category="virtual")
    physical_score, _ = score_candidate(physical)
    virtual_score, _ = score_candidate(virtual)
    assert physical_score > 0
    assert virtual_score > 0
    assert virtual_score < physical_score + 45


def test_down_interface_is_not_viable():
    chosen = elect_network([candidate("Ethernet", is_up=False)])
    assert chosen is None


@pytest.mark.asyncio
async def test_same_interface_network_identity_change_emits_event():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1)
    worker.selected = selected()

    await worker._consider(selected(ipv4=("192.0.2.20",)))

    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_IDENTITY_CHANGED"
    assert event.payload["previous"]["ipv4"] == ("192.0.2.10",)
    assert event.payload["current"]["ipv4"] == ("192.0.2.20",)
