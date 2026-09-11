import pytest

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind


@pytest.mark.asyncio
async def test_bus_is_bounded_and_accounts_for_drops():
    bus = EventBus(queue_size=2)
    sub = await bus.subscribe("slow")
    for number in range(3):
        await bus.publish(Event(source="test", kind=EventKind.SYSTEM, payload={"n": number}))
    assert sub.queue.qsize() == 2
    assert sub.dropped == 1
    assert bus.stats()["slow"] == {"queued": 2, "dropped": 1, "capacity": 2}
    assert (await sub.queue.get()).payload["n"] == 1
