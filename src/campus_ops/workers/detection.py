from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class BehaviourDetectionWorker(BaseWorker):
    """Evidence-backed defensive heuristics over passive packet metadata."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("behaviour-detection", bus)
        self.state = state
        self.session_provider = session_provider
        self.syn_windows: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.dns_windows: dict[str, deque[float]] = defaultdict(deque)
        self.last_alert: dict[str, float] = {}

    async def _alert(self, session_id: str, key: str, severity: Severity, title: str, evidence: dict[str, object]) -> None:
        now = time.monotonic()
        if now - self.last_alert.get(key, 0.0) < 20:
            return
        self.last_alert[key] = now
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=severity,
                evidence_class="BEHAVIOURAL_INDICATOR",
                payload={"type": "SECURITY_INDICATOR", "title": title, "confidence": evidence.pop("confidence", 0), "evidence": evidence},
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
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                p = event.payload
                src = str(p.get("src_ip") or "")
                dst = str(p.get("dst_ip") or "")
                dport = str(p.get("dst_port") or "")
                flags = str(p.get("tcp_flags") or "").lower()
                now = time.monotonic()

                if src and flags in {"0x0002", "0x002", "0x02", "2"}:
                    window = self.syn_windows[src]
                    window.append((now, dst, dport))
                    while window and now - window[0][0] > 10:
                        window.popleft()
                    targets = {item[1] for item in window if item[1]}
                    ports = {item[2] for item in window if item[2]}
                    if len(window) >= 80 and (len(targets) >= 12 or len(ports) >= 20):
                        await self._alert(
                            session_id,
                            f"syn:{src}",
                            Severity.HIGH,
                            "Possible reconnaissance or SYN burst",
                            {
                                "source": src,
                                "syn_packets_10s": len(window),
                                "unique_destinations": len(targets),
                                "unique_destination_ports": len(ports),
                                "confidence": min(95, 55 + len(targets) + len(ports)),
                            },
                        )

                if src and p.get("dns_query"):
                    window2 = self.dns_windows[src]
                    window2.append(now)
                    while window2 and now - window2[0] > 10:
                        window2.popleft()
                    if len(window2) >= 120:
                        await self._alert(
                            session_id,
                            f"dns:{src}",
                            Severity.MEDIUM,
                            "Unusually high DNS query rate",
                            {"source": src, "queries_10s": len(window2), "confidence": 70},
                        )

                self.health.heartbeat("passive behavioural analysis active")
        finally:
            await self.bus.unsubscribe(self.name)
