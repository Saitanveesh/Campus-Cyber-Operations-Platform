import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import NetworkCandidate, SelectedNetwork
from campus_ops.workers.network_discovery import (
    NetworkDiscoveryWorker,
    classify_interface,
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


def test_interface_classifier_does_not_treat_every_lo_prefix_as_loopback():
    assert classify_interface("lo") == "loopback"
    assert classify_interface("loopback0") == "loopback"
    assert classify_interface("localnet0") != "loopback"
    assert classify_interface("wlp2s0") == "wireless"
    assert classify_interface("eth0") == "ethernet"


@pytest.mark.asyncio
async def test_same_interface_network_identity_change_emits_event_when_configured_immediate():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=1)
    worker.selected = selected()

    await worker._consider(selected(ipv4=("192.0.2.20",)))

    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_IDENTITY_CHANGED"
    assert event.payload["previous"]["ipv4"] == ("192.0.2.10",)
    assert event.payload["current"]["ipv4"] == ("192.0.2.20",)


@pytest.mark.asyncio
async def test_material_identity_change_requires_repeated_confirmation_by_default():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=3)
    original = selected()
    changed = selected(ipv4=("192.0.2.20",))
    worker.selected = original

    await worker._consider(changed)
    await worker._consider(changed)
    assert worker.selected.ipv4 == original.ipv4
    assert sub.queue.empty()

    await worker._consider(changed)
    assert worker.selected.ipv4 == changed.ipv4
    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_IDENTITY_CHANGED"


@pytest.mark.asyncio
async def test_ipv6_privacy_address_rotation_does_not_reset_ipv4_session():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=3)
    worker.selected = selected(
        ipv6=("2001:db8::100",),
        prefixes=("192.0.2.0/24", "2001:db8::/64"),
    )
    rotated = selected(
        ipv6=("2001:db8::200",),
        prefixes=("192.0.2.0/24", "2001:db8::/64"),
    )

    await worker._consider(rotated)

    assert worker.selected.ipv6 == rotated.ipv6
    assert worker._pending_identity_count == 0
    assert sub.queue.empty()


@pytest.mark.asyncio
async def test_ipv6_only_address_rotation_with_same_prefix_does_not_reset_session():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=3)
    worker.selected = selected(
        ipv4=(),
        ipv6=("2001:db8:1::100",),
        prefixes=("2001:db8:1::/64",),
        gateway="fe80::1",
    )
    rotated = selected(
        ipv4=(),
        ipv6=("2001:db8:1::200",),
        prefixes=("2001:db8:1::/64",),
        gateway="fe80::1",
    )

    await worker._consider(rotated)

    assert worker.selected.ipv6 == rotated.ipv6
    assert sub.queue.empty()


@pytest.mark.asyncio
async def test_single_missing_poll_does_not_destroy_active_hotspot_session():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    worker.selected = selected(interface="wlp130s0f0", reasons=("explicit-interface",))

    await worker._consider(None)

    assert worker.selected is not None
    assert worker.selected.interface == "wlp130s0f0"
    assert worker._loss_count == 1
    assert sub.queue.empty()


@pytest.mark.asyncio
async def test_network_unavailable_requires_consecutive_confirmations():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    worker.selected = selected(interface="wlp130s0f0", reasons=("explicit-interface",))

    await worker._consider(None)
    await worker._consider(None)
    assert worker.selected is not None
    assert sub.queue.empty()

    await worker._consider(None)
    assert worker.selected is None
    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_UNAVAILABLE"
    assert event.payload["previous"]["interface"] == "wlp130s0f0"


@pytest.mark.asyncio
async def test_link_recovery_clears_loss_counter_without_session_reset():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = NetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    hotspot = selected(interface="wlp130s0f0", reasons=("explicit-interface",))
    worker.selected = hotspot

    await worker._consider(None)
    assert worker._loss_count == 1

    await worker._consider(hotspot)
    assert worker.selected == hotspot
    assert worker._loss_count == 0
    assert sub.queue.empty()
