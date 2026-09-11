from __future__ import annotations

from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


class AssetEngineWorker(BaseWorker):
    """Creates and refreshes assets only from source-side packet evidence."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("asset-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider

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
                src_ip = str(payload.get("src_ip") or "")
                if not src_ip:
                    continue
                role = endpoint_role(src_ip, self.network_provider())
                if role in {"SPECIAL_ADDRESS", "MULTICAST", "BROADCAST", "UNKNOWN"}:
                    continue
                now = datetime.now(UTC).isoformat()
                previous = self.state.get_asset(src_ip)
                vendor = payload.get("eth_src_vendor") or previous.get("vendor")
                hostname = payload.get("dhcp_hostname") or previous.get("hostname")
                self.state.upsert_asset(
                    src_ip,
                    {
                        **previous,
                        "id": src_ip,
                        "ip": src_ip,
                        "mac": payload.get("eth_src") or previous.get("mac"),
                        "vendor": vendor,
                        "role": role,
                        "classification": role,
                        "local_device": role in {"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"},
                        "hostname": hostname,
                        "dhcp_hostname": hostname,
                        "vlan_id": payload.get("vlan_id") or previous.get("vlan_id"),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "packets_as_source": int(previous.get("packets_as_source", 0)) + 1,
                        "evidence": "PASSIVE_SOURCE_FRAME",
                    },
                )
                self.health.heartbeat(f"assets={len(self.state.snapshot()['assets'])}")
        finally:
            await self.bus.unsubscribe(self.name)
