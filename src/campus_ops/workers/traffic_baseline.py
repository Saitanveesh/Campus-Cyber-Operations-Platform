from __future__ import annotations

import math
import time
from collections import deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class TrafficBaselineWorker(BaseWorker):
    """Adaptive interface-rate baseline with evidence-backed deviation alerts."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("traffic-baseline", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._rx: deque[float] = deque(maxlen=180)
        self._tx: deque[float] = deque(maxlen=180)
        self._rx_pps: deque[float] = deque(maxlen=180)
        self._consecutive = 0
        self._last_alert = 0.0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._rx.clear()
        self._tx.clear()
        self._rx_pps.clear()
        self._consecutive = 0
        self._last_alert = 0.0

    @staticmethod
    def _stats(values: deque[float]) -> tuple[float, float]:
        if not values:
            return 0.0, 0.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        return mean, math.sqrt(variance)

    async def _emit_alert(
        self,
        session_id: str,
        rx_bps: float,
        rx_pps: float,
        mean_bps: float,
        std_bps: float,
        ratio: float,
    ) -> None:
        now = time.monotonic()
        if now - self._last_alert < 60:
            return
        self._last_alert = now
        z_score = (rx_bps - mean_bps) / max(std_bps, 1.0)
        confidence = min(95, 65 + int(min(20.0, ratio * 3.0)))
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.MEDIUM,
                evidence_class="ADAPTIVE_RATE_BASELINE",
                payload={
                    "type": "SECURITY_INDICATOR",
                    "title": "Sustained traffic rate deviation",
                    "confidence": confidence,
                    "evidence": {
                        "source": "network-interface",
                        "rx_bps": round(rx_bps, 2),
                        "rx_pps": round(rx_pps, 2),
                        "baseline_rx_bps": round(mean_bps, 2),
                        "baseline_stddev": round(std_bps, 2),
                        "baseline_ratio": round(ratio, 2),
                        "z_score": round(z_score, 2),
                        "consecutive_windows": self._consecutive,
                        "claim": "RATE_DEVIATION_NOT_ATTACK_CONFIRMATION",
                    },
                },
            )
        )

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
                    self._reset(session_id)
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PERFORMANCE":
                    continue

                rx_bps = float(event.payload.get("rx_bps") or 0.0)
                tx_bps = float(event.payload.get("tx_bps") or 0.0)
                rx_pps = float(event.payload.get("rx_pps") or 0.0)
                mean_bps, std_bps = self._stats(self._rx)
                enough = len(self._rx) >= 30
                ratio = rx_bps / max(mean_bps, 1.0) if enough else 1.0
                z_score = (rx_bps - mean_bps) / max(std_bps, 1.0) if enough else 0.0

                abnormal = enough and rx_bps >= 1_000_000 and ratio >= 4.0 and z_score >= 5.0
                self._consecutive = self._consecutive + 1 if abnormal else 0
                if self._consecutive >= 3:
                    await self._emit_alert(
                        session_id,
                        rx_bps,
                        rx_pps,
                        mean_bps,
                        std_bps,
                        ratio,
                    )

                if not abnormal:
                    self._rx.append(rx_bps)
                    self._tx.append(tx_bps)
                    self._rx_pps.append(rx_pps)

                baseline_rx, baseline_std = self._stats(self._rx)
                baseline_tx, _ = self._stats(self._tx)
                baseline_pps, _ = self._stats(self._rx_pps)
                self.state.update_metrics(
                    baseline_samples=len(self._rx),
                    baseline_rx_bps=round(baseline_rx, 2),
                    baseline_tx_bps=round(baseline_tx, 2),
                    baseline_rx_pps=round(baseline_pps, 2),
                    baseline_rx_stddev=round(baseline_std, 2),
                    baseline_current_ratio=round(ratio, 2),
                    baseline_deviation_windows=self._consecutive,
                )
                self.health.heartbeat(f"samples={len(self._rx)} ratio={ratio:.2f}")
        finally:
            await self.bus.unsubscribe(self.name)
