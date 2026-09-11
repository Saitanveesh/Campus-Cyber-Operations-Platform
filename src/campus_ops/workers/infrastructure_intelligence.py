from __future__ import annotations

import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class InfrastructureIntelligenceWorker(BaseWorker):
    """Correlates LLDP, DHCP, flow exporters, syslog and optional SNMP observations."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("infrastructure-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._lldp: dict[str, dict[str, object]] = {}
        self._dhcp_servers: dict[str, dict[str, object]] = {}
        self._flow_exporters: dict[str, dict[str, object]] = {}
        self._syslog_senders: dict[str, int] = {}
        self._snmp: dict[str, dict[str, object]] = {}
        self._syslog_messages = 0
        self._last_multi_dhcp_alert = 0.0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._lldp.clear()
        self._dhcp_servers.clear()
        self._flow_exporters.clear()
        self._syslog_senders.clear()
        self._snmp.clear()
        self._syslog_messages = 0
        self._last_multi_dhcp_alert = 0.0

    def _publish(self) -> None:
        self.state.update_metrics(
            lldp_neighbor_count=len(self._lldp),
            lldp_neighbors=list(self._lldp.values())[:50],
            lldp_systems={
                str(item.get("system_name") or item.get("chassis_id") or "unknown"): item
                for item in self._lldp.values()
            },
            dhcp_server_count=len(self._dhcp_servers),
            dhcp_servers=list(self._dhcp_servers.values())[:20],
            flow_exporters=len(self._flow_exporters),
            flow_exporter_details=list(self._flow_exporters.values())[:50],
            syslog_messages=self._syslog_messages,
            syslog_senders=dict(sorted(self._syslog_senders.items(), key=lambda item: -item[1])[:50]),
            snmp_device_count=len(self._snmp),
            snmp_devices=list(self._snmp.values())[:50],
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
                if event.kind != EventKind.OBSERVATION:
                    continue

                payload = event.payload
                event_type = str(payload.get("type") or "")
                changed = False
                if event_type == "PACKET":
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
                elif event_type == "FLOW_TELEMETRY":
                    exporter = str(payload.get("exporter") or "").strip()
                    if exporter:
                        self._flow_exporters[exporter] = {
                            "exporter": exporter,
                            "source": payload.get("source"),
                            "last_seen": event.timestamp.isoformat(),
                            "observation_domain": payload.get("observation_domain"),
                        }
                        changed = True
                elif event_type == "SYSLOG":
                    sender = str(payload.get("sender") or "unknown")
                    self._syslog_messages += 1
                    self._syslog_senders[sender] = self._syslog_senders.get(sender, 0) + 1
                    changed = True
                elif event_type == "SNMP_TELEMETRY":
                    target = str(payload.get("target") or "").strip()
                    if target:
                        self._snmp[target] = {
                            "target": target,
                            "sysName": payload.get("sysName"),
                            "sysDescr": payload.get("sysDescr"),
                            "sysUpTime": payload.get("sysUpTime"),
                            "last_seen": event.timestamp.isoformat(),
                        }
                        changed = True

                if changed:
                    self._publish()
                self.health.heartbeat(
                    f"lldp={len(self._lldp)} dhcp={len(self._dhcp_servers)} "
                    f"flow_exporters={len(self._flow_exporters)} syslog={self._syslog_messages}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
