from __future__ import annotations

import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class InfrastructureIntelligenceWorker(BaseWorker):
    """Tracks directly observed LLDP neighbors and DHCP server identities."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("infrastructure-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._lldp: dict[str, dict[str, object]] = {}
        self._dhcp_servers: dict[str, dict[str, object]] = {}
        self._last_multi_dhcp_alert = 0.0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._lldp.clear()
        self._dhcp_servers.clear()
        self._last_multi_dhcp_alert = 0.0

    def _publish(self) -> None:
        self.state.update_metrics(
            lldp_neighbor_count=len(self._lldp),
            lldp_neighbors=list(self._lldp.values())[:50],
            dhcp_server_count=len(self._dhcp_servers),
            dhcp_servers=list(self._dhcp_servers.values())[:20],
        )

    async def _check_dhcp(self, session_id: str) -> None:
        now = time.monotonic()
        if len(self._dhcp_servers) < 2 or now - self._last_multi_dhcp_alert < 120.0:
            return
        self._last_multi_dhcp_alert = now
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.MEDIUM,
                evidence_class="DHCP_SERVER_OBSERVATION",
                payload={
                    "type": "SECURITY_INDICATOR",
                    "title": "Multiple DHCP server identities observed",
                    "confidence": 70,
                    "evidence": {
                        "source": "network",
                        "server_count": len(self._dhcp_servers),
                        "servers": list(self._dhcp_servers.keys())[:20],
                        "claim": "MULTIPLE_SERVERS_NOT_ROGUE_SERVER_CONFIRMATION",
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
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue

                payload = event.payload
                changed = False
                chassis = str(payload.get("lldp_chassis_id") or "").strip()
                port = str(payload.get("lldp_port_id") or "").strip()
                system_name = str(payload.get("lldp_system_name") or "").strip()
                if chassis or port or system_name:
                    key = f"{chassis}|{port}|{system_name}"
                    self._lldp[key] = {
                        "chassis_id": chassis or None,
                        "port_id": port or None,
                        "system_name": system_name or None,
                        "source_mac": payload.get("eth_src") or None,
                        "source_vendor": payload.get("eth_src_vendor") or None,
                        "last_seen": event.timestamp.isoformat(),
                        "evidence": "DIRECT_LLDP_ADVERTISEMENT",
                    }
                    changed = True

                dhcp_server = str(payload.get("dhcp_server_id") or "").strip()
                if dhcp_server:
                    self._dhcp_servers[dhcp_server] = {
                        "server_id": dhcp_server,
                        "source_ip": payload.get("src_ip") or None,
                        "source_mac": payload.get("eth_src") or None,
                        "last_seen": event.timestamp.isoformat(),
                        "evidence": "DHCP_SERVER_IDENTIFIER",
                    }
                    changed = True
                    await self._check_dhcp(session_id)

                if changed:
                    self._publish()
                self.health.heartbeat(
                    f"lldp={len(self._lldp)} dhcp_servers={len(self._dhcp_servers)}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
