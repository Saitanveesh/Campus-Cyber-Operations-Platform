from __future__ import annotations

from collections import deque

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class PerformanceEngineWorker(BaseWorker):
    """Maintains rolling interface performance windows from OS telemetry."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("performance-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._rx: deque[float] = deque(maxlen=300)
        self._tx: deque[float] = deque(maxlen=300)
        self._rx_pps: deque[float] = deque(maxlen=300)
        self._tx_pps: deque[float] = deque(maxlen=300)

    @staticmethod
    def _average(values: deque[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _peak(values: deque[float]) -> float:
        return max(values) if values else 0.0

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
                    self._rx.clear()
                    self._tx.clear()
                    self._rx_pps.clear()
                    self._tx_pps.clear()
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PERFORMANCE":
                    continue
                self._rx.append(float(event.payload.get("rx_bps") or 0.0))
                self._tx.append(float(event.payload.get("tx_bps") or 0.0))
                self._rx_pps.append(float(event.payload.get("rx_pps") or 0.0))
                self._tx_pps.append(float(event.payload.get("tx_pps") or 0.0))
                self.state.update_metrics(
                    performance_window_samples=len(self._rx),
                    performance_rx_avg_bps=round(self._average(self._rx), 2),
                    performance_tx_avg_bps=round(self._average(self._tx), 2),
                    performance_rx_peak_bps=round(self._peak(self._rx), 2),
                    performance_tx_peak_bps=round(self._peak(self._tx), 2),
                    performance_rx_avg_pps=round(self._average(self._rx_pps), 2),
                    performance_tx_avg_pps=round(self._average(self._tx_pps), 2),
                )
                self.health.heartbeat(f"samples={len(self._rx)}")
        finally:
            await self.bus.unsubscribe(self.name)
