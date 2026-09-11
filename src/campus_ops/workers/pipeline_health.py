from __future__ import annotations

import asyncio

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class PipelineHealthWorker(BaseWorker):
    """Tracks event-bus backlog and dropped observations across workers."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        interval: float = 3.0,
    ) -> None:
        super().__init__("pipeline-health", bus)
        self.state = state
        self.interval = interval
        self._last_dropped = 0

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            stats = self.bus.stats()
            dropped = sum(item.get("dropped", 0) for item in stats.values())
            queued = sum(item.get("queued", 0) for item in stats.values())
            max_queue = max((item.get("queued", 0) for item in stats.values()), default=0)
            worst = max(stats, key=lambda name: stats[name].get("queued", 0), default=None)
            new_drops = max(0, dropped - self._last_dropped)
            self._last_dropped = dropped

            self.state.update_metrics(
                pipeline_subscribers=len(stats),
                pipeline_queued_events=queued,
                pipeline_max_subscriber_queue=max_queue,
                pipeline_dropped_events=dropped,
                pipeline_recent_drops=new_drops,
                pipeline_worst_subscriber=worst,
            )
            if new_drops > 0:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(f"dropped={dropped} recent={new_drops} worst={worst}")
            else:
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat(f"queued={queued} dropped={dropped}")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
