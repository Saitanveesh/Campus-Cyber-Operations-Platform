from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}


def _private_host(value: object) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return ip.is_private and not (
        ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    )


class LateralMovementWorker(BaseWorker):
    """Detect internal administrative-protocol fan-out without claiming compromise."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("lateral-movement-watch", bus)
        self.state = state
        self.session_provider = session_provider
        self.windows: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self.last_alert: dict[str, float] = {}

    async def _emit(
        self,
        session_id: str,
        source: str,
        targets: set[str],
        ports: set[int],
        sample_count: int,
    ) -> None:
        now = time.monotonic()
        if now - self.last_alert.get(source, 0.0) < 90:
            return
        self.last_alert[source] = now
        severity = Severity.HIGH if len(targets) >= 12 else Severity.MEDIUM
        confidence = min(94, 52 + len(targets) * 3 + min(12, len(ports) * 2))
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=severity,
                evidence_class="PASSIVE_NETWORK_BEHAVIOUR",
                payload={
                    "type": "LATERAL_MOVEMENT_INDICATOR",
                    "title": "Administrative-protocol fan-out observed",
                    "confidence": confidence,
                    "evidence": {
                        "source": source,
                        "unique_destinations": len(targets),
                        "destinations": sorted(targets)[:30],
                        "destination_ports": sorted(ports),
                        "observations_120s": sample_count,
                        "claim": "FANOUT_INDICATOR_NOT_COMPROMISE_CONFIRMATION",
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
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue

                payload = event.payload
                src = str(payload.get("src_ip") or "")
                dst = str(payload.get("dst_ip") or "")
                try:
                    dport = int(payload.get("dst_port") or 0)
                except (TypeError, ValueError):
                    dport = 0
                if dport not in ADMIN_PORTS or not _private_host(src) or not _private_host(dst):
                    continue
                if src == dst:
                    continue

                now = time.monotonic()
                window = self.windows[src]
                window.append((now, dst, dport))
                while window and now - window[0][0] > 120:
                    window.popleft()

                targets = {item[1] for item in window}
                ports = {item[2] for item in window}
                if len(targets) >= 5 and len(window) >= 10:
                    await self._emit(session_id, src, targets, ports, len(window))

                self.state.update_metrics(
                    lateral_movement_watch={
                        "sources_tracked": len(self.windows),
                        "highest_fanout": max(
                            (
                                len({item[1] for item in values})
                                for values in self.windows.values()
                            ),
                            default=0,
                        ),
                    }
                )
                self.health.heartbeat("administrative-protocol fan-out watch active")
        finally:
            await self.bus.unsubscribe(self.name)
