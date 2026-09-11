from __future__ import annotations

import time
from collections import Counter, defaultdict, deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _rcode(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


class DnsIntelligenceWorker(BaseWorker):
    """Current-session DNS response quality and name telemetry."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("dns-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._queries = 0
        self._responses = 0
        self._nxdomain = 0
        self._servfail = 0
        self._answers_v4 = 0
        self._answers_v6 = 0
        self._names: Counter[str] = Counter()
        self._rcodes: Counter[str] = Counter()
        self._client_windows: dict[str, deque[tuple[float, bool]]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._queries = 0
        self._responses = 0
        self._nxdomain = 0
        self._servfail = 0
        self._answers_v4 = 0
        self._answers_v6 = 0
        self._names.clear()
        self._rcodes.clear()
        self._client_windows.clear()
        self._last_alert.clear()

    def _publish(self) -> None:
        response_total = max(self._responses, 1)
        self.state.update_metrics(
            dns_queries_total=self._queries,
            dns_responses_total=self._responses,
            dns_nxdomain_total=self._nxdomain,
            dns_servfail_total=self._servfail,
            dns_nxdomain_ratio=round(self._nxdomain / response_total, 4),
            dns_ipv4_answers=self._answers_v4,
            dns_ipv6_answers=self._answers_v6,
            dns_rcode_counts=dict(self._rcodes.most_common(10)),
            dns_top_names_detailed=dict(self._names.most_common(15)),
        )

    async def _maybe_alert_client(self, session_id: str, client: str, now: float) -> None:
        window = self._client_windows[client]
        while window and now - window[0][0] > 30.0:
            window.popleft()
        if len(window) < 25:
            return
        failures = sum(1 for _timestamp, failed in window if failed)
        ratio = failures / len(window)
        if ratio < 0.70 or now - self._last_alert.get(client, 0.0) < 60.0:
            return
        self._last_alert[client] = now
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.MEDIUM,
                evidence_class="DNS_RESPONSE_PATTERN",
                payload={
                    "type": "SECURITY_INDICATOR",
                    "title": "High DNS name failure ratio",
                    "confidence": min(90, 60 + int(ratio * 30)),
                    "evidence": {
                        "source": client,
                        "responses_30s": len(window),
                        "nxdomain_or_servfail_30s": failures,
                        "failure_ratio": round(ratio, 3),
                        "claim": "DNS_ANOMALY_NOT_COMPROMISE_CONFIRMATION",
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
                name = str(payload.get("dns_query") or "").strip().lower()
                is_response = _truthy(payload.get("dns_is_response"))
                rcode = _rcode(payload.get("dns_rcode"))
                if name:
                    self._names[name] += 1
                if is_response:
                    self._responses += 1
                    if rcode is not None:
                        self._rcodes[str(rcode)] += 1
                    failed = rcode in {2, 3}
                    if rcode == 3:
                        self._nxdomain += 1
                    elif rcode == 2:
                        self._servfail += 1
                    if payload.get("dns_a"):
                        self._answers_v4 += 1
                    if payload.get("dns_aaaa"):
                        self._answers_v6 += 1
                    client = str(payload.get("dst_ip") or "")
                    if client and rcode is not None:
                        now = time.monotonic()
                        self._client_windows[client].append((now, failed))
                        await self._maybe_alert_client(session_id, client, now)
                elif name:
                    self._queries += 1

                if name or is_response:
                    self._publish()
                self.health.heartbeat(
                    f"queries={self._queries} responses={self._responses} nxdomain={self._nxdomain}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
