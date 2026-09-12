from __future__ import annotations

import ipaddress
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class ArpGuardWorker(BaseWorker):
    """Detect confirmed ARP ownership changes while filtering probes and transient noise."""

    INITIAL_CONFIRMATIONS = 3
    CHANGE_CONFIRMATIONS = 3
    CANDIDATE_TTL_SECONDS = 20.0
    ALERT_SUPPRESSION_SECONDS = 900.0

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("arp-guard", bus)
        self.session_provider = session_provider
        self._session: str | None = None
        self._owners: dict[str, str] = {}
        self._candidates: dict[tuple[str, str], dict[str, float]] = {}
        self._last_alert: dict[str, float] = {}

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._owners.clear()
        self._candidates.clear()
        self._last_alert.clear()

    @staticmethod
    def _valid_arp_ip(value: object) -> str | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None
        if ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            return None
        if raw == "255.255.255.255":
            return None
        return str(ip)

    @staticmethod
    def _valid_unicast_mac(value: object) -> str | None:
        raw = str(value or "").strip().lower().replace("-", ":")
        parts = raw.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            return None
        try:
            octets = [int(part, 16) for part in parts]
        except ValueError:
            return None
        if all(item == 0 for item in octets) or all(item == 255 for item in octets):
            return None
        if octets[0] & 1:
            return None
        return ":".join(f"{item:02x}" for item in octets)

    def _observe_candidate(self, ip: str, mac: str, now: float) -> tuple[int, float]:
        key = (ip, mac)
        current = self._candidates.get(key)
        if current is None or now - current["last"] > self.CANDIDATE_TTL_SECONDS:
            current = {"count": 0.0, "first": now, "last": now}
            self._candidates[key] = current
        current["count"] += 1
        current["last"] = now
        return int(current["count"]), max(0.0, current["last"] - current["first"])

    def _clear_candidates(self, ip: str) -> None:
        for key in [key for key in self._candidates if key[0] == ip]:
            del self._candidates[key]

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

                ip = self._valid_arp_ip(payload.get("src_ip"))
                mac = self._valid_unicast_mac(payload.get("eth_src"))
                if not ip or not mac:
                    self.health.heartbeat(
                        f"tracked ARP owners={len(self._owners)}; ignored non-owner ARP observation"
                    )
                    continue

                now = time.monotonic()
                previous = self._owners.get(ip)
                if previous is None:
                    count, _window = self._observe_candidate(ip, mac, now)
                    if count >= self.INITIAL_CONFIRMATIONS:
                        self._owners[ip] = mac
                        self._clear_candidates(ip)
                    self.health.heartbeat(
                        f"tracked ARP owners={len(self._owners)} candidates={len(self._candidates)}"
                    )
                    continue

                if previous == mac:
                    self._clear_candidates(ip)
                    self.health.heartbeat(f"tracked ARP owners={len(self._owners)}")
                    continue

                count, window = self._observe_candidate(ip, mac, now)
                if count < self.CHANGE_CONFIRMATIONS:
                    self.health.heartbeat(
                        f"ARP change candidate {ip}; confirmations={count}/{self.CHANGE_CONFIRMATIONS}"
                    )
                    continue

                key = f"{ip}:{previous}:{mac}"
                last = self._last_alert.get(key, 0.0)
                self._owners[ip] = mac
                self._clear_candidates(ip)
                if now - last < self.ALERT_SUPPRESSION_SECONDS:
                    self.health.heartbeat(f"suppressed repeated ARP transition for {ip}")
                    continue

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
                            "title": "Confirmed ARP ownership change",
                            "confidence": 65,
                            "evidence": {
                                "source": ip,
                                "previous_mac": previous,
                                "observed_mac": mac,
                                "confirmations": count,
                                "observation_window_seconds": round(window, 3),
                                "claim": "ARP_CONFLICT_INDICATOR_NOT_CONFIRMED_SPOOFING",
                            },
                        },
                    )
                )
                self.health.heartbeat(f"tracked ARP owners={len(self._owners)}")
        finally:
            await self.bus.unsubscribe(self.name)
