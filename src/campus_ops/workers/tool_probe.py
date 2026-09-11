from __future__ import annotations

import asyncio

from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.tooling.registry import probe_tools_json
from campus_ops.workers.base import BaseWorker


class ToolProbeWorker(BaseWorker):
    def __init__(self, bus, interval: float = 30.0) -> None:
        super().__init__("tool-probe", bus)
        self.interval = interval
        self.statuses: list[dict[str, object]] = []

    async def run(self) -> None:
        while not self.stopping:
            self.statuses = probe_tools_json()
            available = sum(1 for item in self.statuses if item["available"])
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat(f"{available}/{len(self.statuses)} optional tools available")
            await self.bus.publish(
                Event(source=self.name, kind=EventKind.TOOL, payload={"tools": self.statuses})
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
