from __future__ import annotations

import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class ArpGuardWorker(BaseWorker):
    """Detect changes in observed ARP ownership without claiming confirmed spoofing."""

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("arp-guard", bus)
        self.session_provider = session_provider
        self._session: str | None = None
        self._owners: dict[str, str] = {}
        self._last_alert: dict[str, float] = {}

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._owners.clear()
        self._last_alert.clear()

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
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue

                payload = event.payload
                protocol_stack = str(payload.get("protocol_stack") or "").lower()
                protocol = str(payload.get("protocol") or "").lower()
                if "arp" not in protocol_stack and protocol != "arp":
                    continue
                ip = str(payload.get("src_ip") or "")
                mac = str(payload.get("eth_src") or "").lower()
                if not ip or not mac:
                    continue

                previous = self._owners.get(ip)
                if previous and previous != mac:
                    key = f"{ip}:{previous}:{mac}"
                    now = time.monotonic()
                    if now - self._last_alert.get(key, 0.0) >= 30:
                        self._last_alert[key] = now
                        await self.bus.publish(
                            Event(
                                source=self.name,
                                kind=EventKind.ALERT,
                                session_id=session_id,
                                severity=Severity.MEDIUM,
                                evidence_class="ARP_OWNERSHIP_CHANGE",
                                payload={
                                    "type": "SECURITY_INDICATOR",
                                    "title": "ARP address ownership changed",
                                    "confidence": 78,
                                    "evidence": {
                                        "source": ip,
                                        "previous_mac": previous,
                                        "observed_mac": mac,
                                        "claim": "ARP_CONFLICT_INDICATOR_NOT_CONFIRMED_SPOOFING",
                                    },
                                },
                            )
                        )
                self._owners[ip] = mac
                self.health.heartbeat(f"tracked ARP owners={len(self._owners)}")
        finally:
            await self.bus.unsubscribe(self.name)
