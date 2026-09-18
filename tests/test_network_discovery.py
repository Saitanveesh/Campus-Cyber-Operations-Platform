import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import NetworkCandidate, SelectedNetwork
from campus_ops.workers.windows_network import (
    WindowsNetworkDiscoveryWorker,
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
    routed = candidate("Wi-Fi", default_route=True, route_metric=5, category="wireless")
    chosen = elect_network([local_only, routed])
    assert chosen is not None
    assert chosen.interface == "Wi-Fi"


def test_virtual_interface_is_heavily_penalized():
    physical = candidate("Ethernet", default_route=True, route_metric=25)
    virtual = candidate(
        "vEthernet (Default Switch)",
        default_route=True,
        route_metric=5,
        category="virtual",
    )
    physical_score, _ = score_candidate(physical)
    virtual_score, _ = score_candidate(virtual)
    assert physical_score > virtual_score
    assert elect_network([physical, virtual]).interface == "Ethernet"


def test_down_interface_is_not_viable():
    chosen = elect_network([candidate("Ethernet", is_up=False)])
    assert chosen is None


def test_windows_interface_classifier():
    assert classify_interface("Loopback Pseudo-Interface 1") == "loopback"
    assert classify_interface("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz") == "wireless"
    assert classify_interface("Ethernet", "Realtek PCIe GbE Family Controller") == "ethernet"
    assert classify_interface("vEthernet (Default Switch)", virtual=True) == "virtual"
    assert classify_interface("Ethernet 2", "Hyper-V Virtual Ethernet Adapter", virtual=True) == "virtual"


@pytest.mark.asyncio
async def test_same_interface_network_identity_change_emits_event_when_immediate():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=1)
    worker.selected = selected()

    await worker._consider(selected(ipv4=("192.0.2.20",)))

    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_IDENTITY_CHANGED"
    assert event.payload["previous"]["ipv4"] == ("192.0.2.10",)
    assert event.payload["current"]["ipv4"] == ("192.0.2.20",)


@pytest.mark.asyncio
async def test_material_identity_change_requires_repeated_confirmation():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=3)
    original = selected()
    changed = selected(ipv4=("192.0.2.20",))
    worker.selected = original

    await worker._consider(changed)
    await worker._consider(changed)
    assert worker.selected.ipv4 == original.ipv4
    assert sub.queue.empty()

    await worker._consider(changed)
    assert worker.selected.ipv4 == changed.ipv4
    assert sub.queue.get_nowait().payload["change"] == "NETWORK_IDENTITY_CHANGED"


@pytest.mark.asyncio
async def test_ipv6_privacy_rotation_does_not_reset_ipv4_session():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, identity_confirmations=3)
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
async def test_single_missing_poll_does_not_destroy_windows_session():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    worker.selected = selected(interface="Wi-Fi", reasons=("explicit-interface",))

    await worker._consider(None)

    assert worker.selected is not None
    assert worker.selected.interface == "Wi-Fi"
    assert worker._loss_count == 1
    assert sub.queue.empty()


@pytest.mark.asyncio
async def test_network_unavailable_requires_consecutive_confirmations():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    worker.selected = selected(interface="Ethernet", reasons=("explicit-interface",))

    await worker._consider(None)
    await worker._consider(None)
    assert worker.selected is not None
    assert sub.queue.empty()

    await worker._consider(None)
    assert worker.selected is None
    event = sub.queue.get_nowait()
    assert event.payload["change"] == "NETWORK_UNAVAILABLE"
    assert event.payload["previous"]["interface"] == "Ethernet"


@pytest.mark.asyncio
async def test_link_recovery_clears_loss_counter_without_session_reset():
    bus = EventBus()
    sub = await bus.subscribe("test")
    worker = WindowsNetworkDiscoveryWorker(bus, confirmations=1, unavailable_confirmations=3)
    wifi = selected(interface="Wi-Fi", reasons=("explicit-interface",))
    worker.selected = wifi

    await worker._consider(None)
    assert worker._loss_count == 1

    await worker._consider(wifi)
    assert worker.selected == wifi
    assert worker._loss_count == 0
    assert sub.queue.empty()
