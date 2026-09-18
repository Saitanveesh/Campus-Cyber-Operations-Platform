from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def _valid_ip(value: object) -> str:
    raw = str(value or "").strip().split(",", 1)[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return ""
    return str(ip)


class ApplicationIntelligenceWorker(BaseWorker):
    """Track application metadata and passive IP-to-name evidence.

    Name mappings are learned only from the current packet stream: DNS answers, TLS SNI,
    HTTP Host and DHCP. MON does not perform reverse-DNS or active target lookups.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("application-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._dns: Counter[str] = Counter()
        self._tls: Counter[str] = Counter()
        self._http: Counter[str] = Counter()
        self._dhcp: Counter[str] = Counter()
        self._ip_names: dict[str, Counter[str]] = defaultdict(Counter)
        self._dns_queries = 0
        self._tls_sni = 0
        self._http_hosts = 0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._dns.clear()
        self._tls.clear()
        self._http.clear()
        self._dhcp.clear()
        self._ip_names.clear()
        self._dns_queries = 0
        self._tls_sni = 0
        self._http_hosts = 0

    def _remember_name(self, ip_value: object, name: object, source: str) -> None:
        ip = _valid_ip(ip_value)
        clean = str(name or "").strip().rstrip(".").lower()
        if not ip or not clean or len(clean) > 253:
            return
        self._ip_names[ip][f"{source}|{clean}"] += 1

    def _name_map(self) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        # Bound snapshot size; most recently inserted IP keys are retained.
        for ip in list(self._ip_names.keys())[-500:]:
            rows: list[dict[str, object]] = []
            for combined, count in self._ip_names[ip].most_common(5):
                source, _, name = combined.partition("|")
                rows.append({"name": name, "source": source, "observations": count})
            result[ip] = rows
        return result

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
            passive_ip_names=self._name_map(),
            passive_name_policy="CURRENT_SESSION_DNS_TLS_HTTP_DHCP_PACKET_EVIDENCE_ONLY",
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
                    self._remember_name(payload.get("dst_ip"), tls_sni, "TLS_SNI")
                    changed = True

                if http_host:
                    self._http_hosts += 1
                    self._http[http_host] += 1
                    self._remember_name(payload.get("dst_ip"), http_host, "HTTP_HOST")
                    changed = True

                if dhcp_hostname:
                    self._dhcp[dhcp_hostname] += 1
                    self._remember_name(payload.get("src_ip"), dhcp_hostname, "DHCP")
                    changed = True

                if dns_query:
                    self._remember_name(payload.get("dns_a"), dns_query, "DNS_A")
                    self._remember_name(payload.get("dns_aaaa"), dns_query, "DNS_AAAA")

                response_name = str(payload.get("dns_response_name") or "").strip()
                transport = str(payload.get("transport") or "").upper()
                src_port = str(payload.get("src_port") or "")
                dst_port = str(payload.get("dst_port") or "")
                discovery_ports = {src_port, dst_port}
                if response_name and transport == "UDP" and "5353" in discovery_ports:
                    self._remember_name(payload.get("src_ip"), response_name, "MDNS_RESPONSE")
                    changed = True
                llmnr_name = str(payload.get("llmnr_name") or "").strip()
                if llmnr_name and transport == "UDP" and "5355" in discovery_ports:
                    self._remember_name(payload.get("src_ip"), llmnr_name, "LLMNR")
                    changed = True
                nbns_name = str(payload.get("nbns_name") or "").strip()
                if nbns_name and transport == "UDP" and "137" in discovery_ports:
                    self._remember_name(payload.get("src_ip"), nbns_name, "NBNS")
                    changed = True

                if changed:
                    self._publish()
                self.health.heartbeat(
                    f"dns={self._dns_queries} tls={self._tls_sni} http={self._http_hosts} "
                    f"named_ips={len(self._ip_names)}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
