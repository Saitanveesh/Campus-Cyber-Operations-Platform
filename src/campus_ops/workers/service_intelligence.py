from __future__ import annotations

from collections import Counter

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

SERVICE_NAMES: dict[tuple[str, int], str] = {
    ("TCP", 20): "FTP-DATA",
    ("TCP", 21): "FTP",
    ("TCP", 22): "SSH",
    ("TCP", 23): "TELNET",
    ("TCP", 25): "SMTP",
    ("TCP", 53): "DNS",
    ("UDP", 53): "DNS",
    ("UDP", 67): "DHCP-SERVER",
    ("UDP", 68): "DHCP-CLIENT",
    ("TCP", 80): "HTTP",
    ("UDP", 123): "NTP",
    ("TCP", 110): "POP3",
    ("TCP", 135): "MS-RPC",
    ("UDP", 137): "NETBIOS-NS",
    ("UDP", 138): "NETBIOS-DGM",
    ("TCP", 139): "NETBIOS-SSN",
    ("TCP", 143): "IMAP",
    ("UDP", 161): "SNMP",
    ("TCP", 389): "LDAP",
    ("UDP", 389): "LDAP",
    ("TCP", 443): "HTTPS",
    ("UDP", 443): "QUIC/HTTPS",
    ("TCP", 445): "SMB",
    ("UDP", 500): "IKE",
    ("UDP", 514): "SYSLOG",
    ("TCP", 587): "SMTP-SUBMISSION",
    ("TCP", 636): "LDAPS",
    ("UDP", 1900): "SSDP",
    ("TCP", 3306): "MYSQL",
    ("TCP", 3389): "RDP",
    ("TCP", 5432): "POSTGRESQL",
    ("UDP", 5353): "MDNS",
    ("TCP", 5900): "VNC",
    ("TCP", 6379): "REDIS",
    ("TCP", 8080): "HTTP-ALT",
    ("TCP", 8443): "HTTPS-ALT",
}


def service_name(transport: str, port: object) -> str:
    try:
        number = int(str(port or ""))
    except ValueError:
        return "UNKNOWN"
    protocol = transport.upper()
    return SERVICE_NAMES.get((protocol, number), f"{protocol}/{number}")


class ServiceIntelligenceWorker(BaseWorker):
    """Current-session destination service and port telemetry."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("service-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._services: Counter[str] = Counter()
        self._ports: Counter[str] = Counter()
        self._destinations: Counter[str] = Counter()
        self._observations = 0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._services.clear()
        self._ports.clear()
        self._destinations.clear()
        self._observations = 0

    def _publish(self) -> None:
        self.state.update_metrics(
            service_observations=self._observations,
            service_unique=len(self._services),
            service_top=dict(self._services.most_common(15)),
            destination_port_top=dict(self._ports.most_common(15)),
            destination_unique=len(self._destinations),
            destination_top=dict(self._destinations.most_common(15)),
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

                transport = str(event.payload.get("transport") or "").upper()
                dst_port = event.payload.get("dst_port")
                dst_ip = str(event.payload.get("dst_ip") or "")
                if transport not in {"TCP", "UDP"} or not dst_port:
                    continue

                try:
                    port_number = int(str(dst_port))
                except ValueError:
                    continue
                if not 1 <= port_number <= 65535:
                    continue

                label = service_name(transport, port_number)
                self._observations += 1
                self._services[label] += 1
                self._ports[f"{transport}/{port_number}"] += 1
                if dst_ip:
                    self._destinations[dst_ip] += 1
                self._publish()
                self.health.heartbeat(
                    f"services={len(self._services)} destinations={len(self._destinations)}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
