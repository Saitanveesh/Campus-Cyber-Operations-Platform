from __future__ import annotations

import asyncio

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class StaleCleanupWorker(BaseWorker):
    """Expires stale current-session assets, flows and topology edges."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider,
        interval: float = 15.0,
    ) -> None:
        super().__init__("stale-cleanup", bus)
        self.state = state
        self.session_provider = session_provider
        self.interval = interval

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            if session_id:
                removed = self.state.prune_stale()
                total = sum(removed.values())
                self.health.heartbeat(
                    f"expired={total} assets={removed['assets']} flows={removed['flows']}"
                )
            else:
                self.health.heartbeat("waiting for live session")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
