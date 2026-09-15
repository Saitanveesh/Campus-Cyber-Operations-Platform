from __future__ import annotations

import ipaddress
import statistics
import time
from collections import defaultdict, deque
from itertools import pairwise

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def periodicity_score(values: list[float]) -> tuple[float, float] | None:
    if len(values) < 8:
        return None
    intervals = [b - a for a, b in pairwise(values) if b > a]
    if len(intervals) < 7:
        return None
    median = statistics.median(intervals)
    if median < 5 or median > 300:
        return None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return None
    deviation = statistics.pstdev(intervals)
    cv = deviation / mean
    return median, cv


def _private(value: object) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return ip.is_private and not (
        ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    )


def _public(value: object) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


class BeaconingWorker(BaseWorker):
    """Find repeated periodic outbound connection starts to public peers."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("beaconing-watch", bus)
        self.state = state
        self.session_provider = session_provider
        self.windows: dict[tuple[str, str, int], deque[float]] = defaultdict(
            lambda: deque(maxlen=20)
        )
        self.last_alert: dict[tuple[str, str, int], float] = {}

    @staticmethod
    def _syn(payload: dict[str, object]) -> bool:
        flags = str(payload.get("tcp_flags") or "").lower()
        return flags in {"0x0002", "0x002", "0x02", "2"}

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue

                payload = dict(event.payload)
                if not self._syn(payload):
                    continue
                src = str(payload.get("src_ip") or "")
                dst = str(payload.get("dst_ip") or "")
                try:
                    dport = int(payload.get("dst_port") or 0)
                except (TypeError, ValueError):
                    dport = 0
                if not src or not dst or not dport or not _private(src) or not _public(dst):
                    continue

                key = (src, dst, dport)
                now = time.monotonic()
                window = self.windows[key]
                window.append(now)
                result = periodicity_score(list(window))
                if result is None:
                    self.health.heartbeat("periodic outbound connection watch active")
                    continue
                median, cv = result
                if cv > 0.15:
                    continue
                if now - self.last_alert.get(key, 0.0) < 600:
                    continue
                self.last_alert[key] = now
                confidence = max(55, min(92, round(92 - cv * 200)))
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.ALERT,
                        session_id=session_id,
                        severity=Severity.MEDIUM,
                        evidence_class="PASSIVE_NETWORK_BEHAVIOUR",
                        payload={
                            "type": "PERIODIC_CONNECTION_INDICATOR",
                            "title": "Periodic outbound connection pattern observed",
                            "confidence": confidence,
                            "evidence": {
                                "source": src,
                                "destination": dst,
                                "destination_port": dport,
                                "samples": len(window),
                                "median_interval_seconds": round(median, 2),
                                "interval_variation": round(cv, 4),
                                "claim": "PERIODICITY_INDICATOR_NOT_MALWARE_CONFIRMATION",
                            },
                        },
                    )
                )
                self.state.update_metrics(
                    beaconing_watch={
                        "tracked_pairs": len(self.windows),
                        "last_candidate": {
                            "source": src,
                            "destination": dst,
                            "destination_port": dport,
                            "median_interval_seconds": round(median, 2),
                            "interval_variation": round(cv, 4),
                        },
                    }
                )
                self.health.heartbeat("periodic outbound connection watch active")
        finally:
            await self.bus.unsubscribe(self.name)
