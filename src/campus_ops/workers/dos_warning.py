from __future__ import annotations

import asyncio
import math
import time
from collections import Counter, deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class DosEarlyWarningWorker(BaseWorker):
    """Adaptive DoS-risk indicator; it never claims to predict an attack with certainty."""

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("dos-early-warning", bus)
        self.session_provider = session_provider
        self._session: str | None = None
        self._baseline: deque[float] = deque(maxlen=300)
        self._window_start = time.monotonic()
        self._packets = 0
        self._syn = 0
        self._udp = 0
        self._icmp = 0
        self._sources: Counter[str] = Counter()
        self._destinations: Counter[str] = Counter()
        self._last_alert = 0.0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._baseline.clear()
        self._window_start = time.monotonic()
        self._clear_window()
        self._last_alert = 0.0

    def _clear_window(self) -> None:
        self._packets = 0
        self._syn = 0
        self._udp = 0
        self._icmp = 0
        self._sources.clear()
        self._destinations.clear()

    @staticmethod
    def _baseline_stats(values: deque[float]) -> tuple[float, float]:
        if not values:
            return 0.0, 0.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        return mean, math.sqrt(variance)

    async def _evaluate(self, session_id: str) -> None:
        now = time.monotonic()
        duration = max(now - self._window_start, 0.001)
        pps = self._packets / duration
        mean, stddev = self._baseline_stats(self._baseline)
        enough_baseline = len(self._baseline) >= 20
        baseline_ratio = pps / max(mean, 1.0) if enough_baseline else 1.0
        z_score = (pps - mean) / max(stddev, 1.0) if enough_baseline else 0.0
        syn_ratio = self._syn / max(self._packets, 1)
        udp_ratio = self._udp / max(self._packets, 1)
        icmp_ratio = self._icmp / max(self._packets, 1)
        unique_sources = len(self._sources)
        unique_destinations = len(self._destinations)
        top_destination_count = self._destinations.most_common(1)[0][1] if self._destinations else 0
        destination_concentration = top_destination_count / max(self._packets, 1)

        signals: list[str] = []
        if enough_baseline and pps >= 250 and baseline_ratio >= 4.0 and z_score >= 5.0:
            signals.append("packet-rate-baseline-deviation")
        if self._packets >= 200 and syn_ratio >= 0.70:
            signals.append("syn-dominance")
        if self._packets >= 300 and udp_ratio >= 0.85:
            signals.append("udp-dominance")
        if self._packets >= 200 and icmp_ratio >= 0.70:
            signals.append("icmp-dominance")
        if self._packets >= 300 and unique_sources >= 20 and destination_concentration >= 0.75:
            signals.append("many-sources-single-destination")

        if (len(signals) >= 2 or (pps >= 5000 and signals)) and now - self._last_alert >= 30:
            confidence = min(
                96,
                55 + 10 * len(signals) + min(20, int(max(0.0, baseline_ratio - 1) * 2)),
            )
            self._last_alert = now
            await self.bus.publish(
                Event(
                    source=self.name,
                    kind=EventKind.ALERT,
                    session_id=session_id,
                    severity=Severity.HIGH,
                    evidence_class="ADAPTIVE_TRAFFIC_ANOMALY",
                    payload={
                        "type": "SECURITY_INDICATOR",
                        "title": "DoS early-warning conditions observed",
                        "confidence": confidence,
                        "evidence": {
                            "source": "network",
                            "window_seconds": round(duration, 2),
                            "packets_per_second": round(pps, 2),
                            "baseline_pps": round(mean, 2),
                            "baseline_ratio": round(baseline_ratio, 2),
                            "z_score": round(z_score, 2),
                            "syn_ratio": round(syn_ratio, 3),
                            "udp_ratio": round(udp_ratio, 3),
                            "icmp_ratio": round(icmp_ratio, 3),
                            "unique_sources": unique_sources,
                            "unique_destinations": unique_destinations,
                            "destination_concentration": round(destination_concentration, 3),
                            "signals": signals,
                            "claim": "EARLY_WARNING_NOT_ATTACK_CONFIRMATION",
                        },
                    },
                )
            )

        if self._packets > 0 and not signals:
            self._baseline.append(pps)
        self._window_start = now
        self._clear_window()

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                try:
                    event = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
                except TimeoutError:
                    event = None
                session_id = self.session_provider()
                if not session_id:
                    continue
                if self._session != session_id:
                    self._reset(session_id)
                if (
                    event is not None
                    and event.session_id == session_id
                    and event.kind == EventKind.OBSERVATION
                    and event.payload.get("type") == "PACKET"
                ):
                    payload = event.payload
                    self._packets += 1
                    transport = str(payload.get("transport") or "")
                    flags = str(payload.get("tcp_flags") or "").lower()
                    if transport == "UDP":
                        self._udp += 1
                    if payload.get("icmp_type"):
                        self._icmp += 1
                    if flags in {"0x0002", "0x002", "0x02", "2"}:
                        self._syn += 1
                    source = str(payload.get("src_ip") or "")
                    destination = str(payload.get("dst_ip") or "")
                    if source:
                        self._sources[source] += 1
                    if destination:
                        self._destinations[destination] += 1
                if time.monotonic() - self._window_start >= 5.0:
                    await self._evaluate(session_id)
                self.health.heartbeat(f"baseline windows={len(self._baseline)}")
        finally:
            await self.bus.unsubscribe(self.name)
