from __future__ import annotations

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class StateSinkWorker(BaseWorker):
    """Copies current-session bus events into the authoritative live-state ring buffers."""

    def __init__(self, bus: EventBus, state: LiveState) -> None:
        super().__init__("state-sink", bus)
        self.state = state

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                accepted = self.state.ingest_event(event)
                self.health.heartbeat("event accepted" if accepted else "non-current event rejected")
        finally:
            await self.bus.unsubscribe(self.name)
