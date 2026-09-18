from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

_AUTH_SERVICE_PORTS = {21, 22, 23, 445, 3389, 5900}
_LATERAL_MOVEMENT_PORTS = {22, 445, 3389}


def _flag_value(raw: object) -> int:
    text = str(raw or "").strip().lower()
    if not text:
        return 0
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


def _private(value: object) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return ip.is_private and not (
        ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    )


def _dns_tunnel_shape(name: str) -> bool:
    value = name.strip().rstrip(".").lower()
    if len(value) < 55:
        return False
    labels = [label for label in value.split(".") if label]
    if not labels:
        return False
    longest = max(labels, key=len)
    if len(longest) < 30:
        return False
    unique_ratio = len(set(longest)) / max(len(longest), 1)
    digit_ratio = sum(ch.isdigit() for ch in longest) / max(len(longest), 1)
    return unique_ratio >= 0.40 and (digit_ratio >= 0.10 or len(longest) >= 40)


class BehaviourDetectionWorker(BaseWorker):
    """Evidence-backed defensive heuristics over passive packet metadata.

    Rules intentionally emit indicators, not compromise verdicts. They require repeated
    packet evidence inside bounded windows and include the measurements that triggered
    each alert so the operator can distinguish attacks from legitimate scanners,
    administration or high-volume applications.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("behaviour-detection", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self.syn_windows: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self.auth_windows: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self.lateral_windows: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self.icmp_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.dns_rate_windows: dict[str, deque[float]] = defaultdict(deque)
        self.dns_shape_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.arp_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.last_alert: dict[str, float] = {}

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self.syn_windows.clear()
        self.auth_windows.clear()
        self.lateral_windows.clear()
        self.icmp_windows.clear()
        self.dns_rate_windows.clear()
        self.dns_shape_windows.clear()
        self.arp_windows.clear()
        self.last_alert.clear()

    @staticmethod
    def _trim(window: deque, now: float, seconds: float) -> None:
        while window and now - window[0][0] > seconds:
            window.popleft()

    async def _alert(
        self,
        session_id: str,
        key: str,
        severity: Severity,
        title: str,
        evidence: dict[str, object],
        suppression_seconds: float = 60.0,
    ) -> None:
        now = time.monotonic()
        if now - self.last_alert.get(key, 0.0) < suppression_seconds:
            return
        self.last_alert[key] = now
        payload_evidence = dict(evidence)
        confidence = int(payload_evidence.pop("confidence", 0) or 0)
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=severity,
                evidence_class="BEHAVIOURAL_INDICATOR",
                payload={
                    "type": "SECURITY_INDICATOR",
                    "title": title,
                    "confidence": confidence,
                    "evidence": payload_evidence,
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

                p = event.payload
                src = str(p.get("src_ip") or "")
                dst = str(p.get("dst_ip") or "")
                try:
                    dport = int(p.get("dst_port") or 0)
                except (TypeError, ValueError):
                    dport = 0
                flags = _flag_value(p.get("tcp_flags"))
                syn_only = bool(flags & 0x02 and not flags & 0x10)
                now = time.monotonic()

                # Broad TCP reconnaissance: many SYNs spread across destinations/ports.
                if src and syn_only:
                    window = self.syn_windows[src]
                    window.append((now, dst, dport))
                    self._trim(window, now, 10.0)
                    targets = {item[1] for item in window if item[1]}
                    ports = {item[2] for item in window if item[2]}
                    if len(window) >= 60 and (len(targets) >= 10 or len(ports) >= 18):
                        await self._alert(
                            session_id,
                            f"syn-recon:{src}",
                            Severity.HIGH,
                            "Possible TCP reconnaissance / SYN scan",
                            {
                                "source": src,
                                "syn_packets_10s": len(window),
                                "unique_destinations": len(targets),
                                "unique_destination_ports": len(ports),
                                "confidence": min(95, 58 + len(targets) + len(ports)),
                                "claim": "RECONNAISSANCE_INDICATOR_NOT_ATTACK_CONFIRMATION",
                            },
                        )

                # Repeated connection starts to authentication/admin services.
                if src and dst and syn_only and dport in _AUTH_SERVICE_PORTS:
                    key = (src, dst, dport)
                    attempts = self.auth_windows[key]
                    attempts.append(now)
                    while attempts and now - attempts[0] > 30.0:
                        attempts.popleft()
                    threshold = 25 if dport == 445 else 18
                    if len(attempts) >= threshold:
                        await self._alert(
                            session_id,
                            f"auth-burst:{src}:{dst}:{dport}",
                            Severity.MEDIUM,
                            "Repeated administrative-service connection attempts",
                            {
                                "source": src,
                                "destination": dst,
                                "destination_port": dport,
                                "syn_attempts_30s": len(attempts),
                                "confidence": min(90, 60 + len(attempts) // 2),
                                "claim": "AUTHENTICATION_ATTACK_INDICATOR_NOT_LOGIN_FAILURE_PROOF",
                            },
                            suppression_seconds=120.0,
                        )

                # One private host touching the same admin port across many private hosts.
                if (
                    src
                    and dst
                    and syn_only
                    and dport in _LATERAL_MOVEMENT_PORTS
                    and _private(src)
                    and _private(dst)
                ):
                    lateral = self.lateral_windows[src]
                    lateral.append((now, dst, dport))
                    self._trim(lateral, now, 30.0)
                    unique_targets = {item[1] for item in lateral}
                    if len(lateral) >= 12 and len(unique_targets) >= 8:
                        await self._alert(
                            session_id,
                            f"lateral:{src}:{dport}",
                            Severity.HIGH,
                            "Possible lateral-movement or internal service sweep",
                            {
                                "source": src,
                                "destination_port": dport,
                                "attempts_30s": len(lateral),
                                "unique_private_destinations": len(unique_targets),
                                "confidence": min(94, 62 + len(unique_targets) * 3),
                                "claim": "LATERAL_MOVEMENT_INDICATOR_NOT_COMPROMISE_CONFIRMATION",
                            },
                            suppression_seconds=180.0,
                        )

                # ICMP echo sweep across many destinations.
                icmp_type = str(p.get("icmp_type") or "").split(",", 1)[0].strip()
                if src and dst and icmp_type == "8":
                    icmp = self.icmp_windows[src]
                    icmp.append((now, dst))
                    self._trim(icmp, now, 15.0)
                    unique_icmp_targets = {item[1] for item in icmp}
                    if len(icmp) >= 14 and len(unique_icmp_targets) >= 12:
                        await self._alert(
                            session_id,
                            f"icmp-sweep:{src}",
                            Severity.MEDIUM,
                            "Possible ICMP host-discovery sweep",
                            {
                                "source": src,
                                "echo_requests_15s": len(icmp),
                                "unique_destinations": len(unique_icmp_targets),
                                "confidence": min(90, 58 + len(unique_icmp_targets) * 2),
                                "claim": "HOST_DISCOVERY_INDICATOR_NOT_ATTACK_CONFIRMATION",
                            },
                            suppression_seconds=120.0,
                        )

                # DNS rate anomaly plus a separate long/high-entropy-name tunneling heuristic.
                dns_query = str(p.get("dns_query") or "").strip().lower()
                if src and dns_query:
                    rate = self.dns_rate_windows[src]
                    rate.append(now)
                    while rate and now - rate[0] > 10.0:
                        rate.popleft()
                    if len(rate) >= 120:
                        await self._alert(
                            session_id,
                            f"dns-rate:{src}",
                            Severity.MEDIUM,
                            "Unusually high DNS query rate",
                            {
                                "source": src,
                                "queries_10s": len(rate),
                                "confidence": 70,
                                "claim": "DNS_RATE_ANOMALY_NOT_TUNNEL_CONFIRMATION",
                            },
                        )

                    if _dns_tunnel_shape(dns_query):
                        shaped = self.dns_shape_windows[src]
                        shaped.append((now, dns_query))
                        self._trim(shaped, now, 30.0)
                        unique_names = {item[1] for item in shaped}
                        if len(shaped) >= 20 and len(unique_names) >= 15:
                            avg_length = sum(len(item[1]) for item in shaped) / len(shaped)
                            await self._alert(
                                session_id,
                                f"dns-tunnel:{src}",
                                Severity.HIGH,
                                "Possible DNS tunneling pattern",
                                {
                                    "source": src,
                                    "suspicious_queries_30s": len(shaped),
                                    "unique_names_30s": len(unique_names),
                                    "average_query_length": round(avg_length, 1),
                                    "confidence": min(92, 65 + len(unique_names)),
                                    "claim": "DNS_TUNNEL_INDICATOR_NOT_EXFILTRATION_CONFIRMATION",
                                },
                                suppression_seconds=180.0,
                            )

                # ARP request sweep / discovery burst.
                arp_opcode = str(p.get("arp_opcode") or "").strip()
                arp_target = str(p.get("arp_target_ip") or "").strip()
                if src and arp_opcode in {"1", "0x0001"} and arp_target:
                    arp = self.arp_windows[src]
                    arp.append((now, arp_target))
                    self._trim(arp, now, 10.0)
                    unique_arp_targets = {item[1] for item in arp}
                    if len(arp) >= 24 and len(unique_arp_targets) >= 20:
                        await self._alert(
                            session_id,
                            f"arp-sweep:{src}",
                            Severity.MEDIUM,
                            "Possible ARP discovery sweep",
                            {
                                "source": src,
                                "arp_requests_10s": len(arp),
                                "unique_targets": len(unique_arp_targets),
                                "confidence": min(90, 55 + len(unique_arp_targets)),
                                "claim": "ARP_DISCOVERY_INDICATOR_NOT_ATTACK_CONFIRMATION",
                            },
                            suppression_seconds=120.0,
                        )

                self.state.update_metrics(
                    detection_engine={
                        "mode": "PASSIVE_EVIDENCE_BACKED",
                        "rules": [
                            "TCP_SYN_RECON",
                            "ADMIN_SERVICE_ATTEMPT_BURST",
                            "INTERNAL_LATERAL_SWEEP",
                            "ICMP_HOST_DISCOVERY",
                            "DNS_RATE_ANOMALY",
                            "DNS_TUNNEL_SHAPE",
                            "ARP_DISCOVERY_SWEEP",
                        ],
                    }
                )
                self.health.heartbeat("passive multi-rule attack detection active")
        finally:
            await self.bus.unsubscribe(self.name)
