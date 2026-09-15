from __future__ import annotations

from collections import Counter

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class ProtocolEngineWorker(BaseWorker):
    """Owns live protocol counters and protocol-stack observations."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("protocol-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._stacks: Counter[str] = Counter()

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if self._session != session_id:
                    self._session = session_id
                    self._stacks.clear()
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                protocol = str(event.payload.get("protocol") or "UNKNOWN").upper()
                self.state.increment_protocol(protocol)
                stack = str(event.payload.get("protocol_stack") or "")
                if stack:
                    self._stacks[stack] += 1
                self.state.update_metrics(
                    protocol_unique=len(self.state.snapshot()["protocols"]),
                    protocol_stack_top=dict(self._stacks.most_common(20)),
                )
                self.health.heartbeat(f"protocols={len(self.state.snapshot()['protocols'])}")
        finally:
            await self.bus.unsubscribe(self.name)
