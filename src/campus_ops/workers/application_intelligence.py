from __future__ import annotations

from collections import Counter

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class ApplicationIntelligenceWorker(BaseWorker):
    """Tracks high-level application metadata observed in the current session."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("application-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._dns: Counter[str] = Counter()
        self._tls: Counter[str] = Counter()
        self._http: Counter[str] = Counter()
        self._dhcp: Counter[str] = Counter()
        self._dns_queries = 0
        self._tls_sni = 0
        self._http_hosts = 0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._dns.clear()
        self._tls.clear()
        self._http.clear()
        self._dhcp.clear()
        self._dns_queries = 0
        self._tls_sni = 0
        self._http_hosts = 0

    def _publish(self) -> None:
        self.state.update_metrics(
            dns_queries=self._dns_queries,
            dns_unique_names=len(self._dns),
            dns_top_names=dict(self._dns.most_common(10)),
            tls_sni_observations=self._tls_sni,
            tls_unique_server_names=len(self._tls),
            tls_top_server_names=dict(self._tls.most_common(10)),
            http_host_observations=self._http_hosts,
            http_unique_hosts=len(self._http),
            http_top_hosts=dict(self._http.most_common(10)),
            dhcp_hostnames=list(self._dhcp.keys())[:50],
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
                dns_query = str(payload.get("dns_query") or "").strip().lower()
                tls_sni = str(payload.get("tls_sni") or "").strip().lower()
                http_host = str(payload.get("http_host") or "").strip().lower()
                dhcp_hostname = str(payload.get("dhcp_hostname") or "").strip()
                changed = False
                if dns_query:
                    self._dns_queries += 1
                    self._dns[dns_query] += 1
                    changed = True
                if tls_sni:
                    self._tls_sni += 1
                    self._tls[tls_sni] += 1
                    changed = True
                if http_host:
                    self._http_hosts += 1
                    self._http[http_host] += 1
                    changed = True
                if dhcp_hostname:
                    self._dhcp[dhcp_hostname] += 1
                    changed = True
                if changed:
                    self._publish()
                self.health.heartbeat(
                    f"dns={self._dns_queries} tls={self._tls_sni} http={self._http_hosts}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
