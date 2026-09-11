from __future__ import annotations

import asyncio

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class CaptureHealthWorker(BaseWorker):
    """Cross-checks capture progress against OS receive counters without false stall claims."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider,
        interval: float = 5.0,
        suspect_checks: int = 6,
    ) -> None:
        super().__init__("capture-health", bus)
        self.state = state
        self.session_provider = session_provider
        self.interval = interval
        self.suspect_checks = max(2, suspect_checks)
        self._last_session: str | None = None
        self._last_packets: int | None = None
        self._unchanged_busy_checks = 0

    def _reset(self, session_id: str | None) -> None:
        self._last_session = session_id
        self._last_packets = None
        self._unchanged_busy_checks = 0

    def _evaluate(self, session_id: str) -> tuple[str, str]:
        snapshot = self.state.snapshot()
        capture = snapshot["capture"]
        metrics = snapshot["metrics"]
        capture_state = str(capture.get("state") or "UNAVAILABLE")
        packets = int(capture.get("packets") or 0)
        rx_pps = float(metrics.get("rx_pps") or 0.0)

        if self._last_session != session_id:
            self._reset(session_id)

        progressed = self._last_packets is not None and packets > self._last_packets
        if progressed:
            self._unchanged_busy_checks = 0
            status = "OK"
            reason = "decoder packet counter is advancing"
        elif capture_state in {"ERROR", "UNAVAILABLE"}:
            self._unchanged_busy_checks = 0
            status = "DEGRADED"
            reason = str(capture.get("detail") or "capture backend unavailable")
        elif capture_state in {"STARTING", "WAITING"}:
            self._unchanged_busy_checks = 0
            status = "STARTING"
            reason = str(capture.get("detail") or "capture is starting")
        elif rx_pps >= 20.0:
            self._unchanged_busy_checks += 1
            if self._unchanged_busy_checks >= self.suspect_checks:
                status = "SUSPECT"
                reason = (
                    "OS receive counters are active but the decoder packet counter has not advanced; "
                    "verify capture interface binding and permissions"
                )
            else:
                status = "OBSERVING"
                reason = "waiting to confirm whether decoder progress is stalled"
        else:
            self._unchanged_busy_checks = 0
            status = "IDLE"
            reason = "low interface traffic; no capture fault inferred"

        self._last_packets = packets
        self.state.update_metrics(
            capture_watchdog_status=status,
            capture_watchdog_reason=reason,
            capture_watchdog_rx_pps=round(rx_pps, 3),
            capture_watchdog_unchanged_checks=self._unchanged_busy_checks,
        )
        return status, reason

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            if not session_id:
                self._reset(None)
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat("waiting for live session")
            else:
                status, reason = self._evaluate(session_id)
                self.health.state = (
                    WorkerState.DEGRADED if status in {"DEGRADED", "SUSPECT"} else WorkerState.HEALTHY
                )
                self.health.heartbeat(f"{status}: {reason}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
