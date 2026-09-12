import asyncio

import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind
from campus_ops.state import LiveState
from campus_ops.workers.topology_engine import TopologyEngineWorker


@pytest.mark.asyncio
async def test_topology_engine_keeps_live_protocol_and_application_context():
    bus = EventBus()
    state = LiveState()
    state.start_session("session-1", "fingerprint")
    network = {
        "ipv4": ("10.0.0.10",),
        "ipv6": (),
        "prefixes": ("10.0.0.0/24",),
        "gateway": "10.0.0.1",
    }
    worker = TopologyEngineWorker(
        bus,
        state,
        lambda: "session-1",
        lambda: network,
    )
    await worker.start()
    await asyncio.sleep(0)

    await bus.publish(
        Event(
            source="capture",
            kind=EventKind.OBSERVATION,
            session_id="session-1",
            payload={
                "type": "PACKET",
                "src_ip": "10.0.0.10",
                "dst_ip": "8.8.8.8",
                "src_port": "52000",
                "dst_port": "443",
                "transport": "TCP",
                "protocol": "TLS",
                "length": 512,
                "tls_sni": "example.test",
                "vlan_id": "20",
            },
        )
    )
    await asyncio.sleep(0.05)

    edge = state.get_edge("10.0.0.10>8.8.8.8")
    assert edge["source_role"] == "SENSOR"
    assert edge["target_role"] == "PUBLIC_PEER"
    assert edge["packets"] == 1
    assert edge["bytes"] == 512
    assert edge["protocols"]["TLS"] == 1
    assert edge["transports"]["TCP"] == 1
    assert edge["destination_ports"] == ["443"]
    assert edge["applications"] == ["example.test"]
    assert edge["vlans"] == ["20"]
    assert edge["last_tls_sni"] == "example.test"

    await worker.stop()


def test_topology_helpers_bound_and_rank_context():
    counts = TopologyEngineWorker._count({"DNS": 2, "TLS": 5}, "DNS")
    assert list(counts)[:2] == ["TLS", "DNS"]
    assert counts["DNS"] == 3

    remembered = TopologyEngineWorker._remember(["53", "443"], "443")
    assert remembered == ["53", "443"]
