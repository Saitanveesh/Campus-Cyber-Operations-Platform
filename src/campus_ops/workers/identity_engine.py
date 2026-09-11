from __future__ import annotations

from collections import defaultdict
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def _ttl_identity(raw: object) -> tuple[str | None, int]:
    try:
        ttl = int(str(raw or ""))
    except ValueError:
        return None, 0
    if ttl <= 0:
        return None, 0
    if ttl <= 64:
        return "Linux / Unix-like", 35
    if ttl <= 128:
        return "Windows-like", 35
    if ttl <= 255:
        return "Network / appliance-like", 25
    return None, 0


class IdentityEngineWorker(BaseWorker):
    """Enriches packet-evidenced assets with vendor, hostname and low-confidence OS hints."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("identity-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._services: dict[str, set[str]] = defaultdict(set)

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
                    self._services.clear()
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                payload = dict(event.payload)
                src_ip = str(payload.get("src_ip") or "")
                if not src_ip:
                    continue
                asset = self.state.get_asset(src_ip)
                if not asset:
                    continue
                vendor = payload.get("eth_src_vendor") or asset.get("vendor")
                hostname = payload.get("dhcp_hostname") or asset.get("hostname")
                os_guess, os_confidence = _ttl_identity(payload.get("ip_ttl"))
                src_port = str(payload.get("src_port") or "")
                protocol = str(payload.get("protocol") or payload.get("transport") or "")
                if src_port and protocol:
                    self._services[src_ip].add(f"{protocol}/{src_port}")
                identity: dict[str, Any] = dict(asset.get("identity") or {})
                identity.update(
                    {
                        "vendor": vendor,
                        "hostname": hostname,
                        "os_guess": os_guess or identity.get("os_guess"),
                        "os_confidence": max(int(identity.get("os_confidence") or 0), os_confidence),
                        "observed_services": sorted(self._services[src_ip])[:40],
                        "source": "PASSIVE_NETWORK_INFERENCE",
                    }
                )
                self.state.upsert_asset(
                    src_ip,
                    {
                        **asset,
                        "vendor": vendor,
                        "hostname": hostname,
                        "os_guess": identity.get("os_guess"),
                        "os_confidence": identity.get("os_confidence"),
                        "identity": identity,
                    },
                )
                self.health.heartbeat("identity enrichment active")
        finally:
            await self.bus.unsubscribe(self.name)
