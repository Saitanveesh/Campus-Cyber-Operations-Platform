from __future__ import annotations

import time
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.ioc_store import IocStore
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _domain_match(observed: str, indicator: str) -> bool:
    observed = observed.lower().rstrip(".")
    indicator = indicator.lower().rstrip(".")
    return observed == indicator or observed.endswith("." + indicator)


def match_observables(payload: dict[str, Any], indicators: list[dict[str, object]]) -> list[dict[str, object]]:
    ips = {
        str(payload.get("src_ip") or "").strip(),
        str(payload.get("dst_ip") or "").strip(),
    }
    domains = {
        str(payload.get("dns_query") or "").strip(),
        str(payload.get("tls_sni") or "").strip(),
        str(payload.get("http_host") or "").strip(),
    }
    sha256 = str(payload.get("sha256") or "").strip().lower()
    matches: list[dict[str, object]] = []
    for item in indicators:
        kind = str(item.get("kind") or "").upper()
        value = str(item.get("value") or "")
        matched = False
        observable = ""
        if kind == "IP" and value in ips:
            matched = True
            observable = value
        elif kind == "DOMAIN":
            for domain in domains:
                if domain and _domain_match(domain, value):
                    matched = True
                    observable = domain
                    break
        elif kind == "SHA256" and sha256 and sha256 == value.lower():
            matched = True
            observable = sha256
        if matched:
            matches.append({**item, "observable": observable})
    return matches


class IocMatcherWorker(BaseWorker):
    """Match live packet/file observables against operator-supplied IOC watchlists."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        store: IocStore,
        session_provider,
    ) -> None:
        super().__init__("ioc-watch", bus)
        self.state = state
        self.store = store
        self.session_provider = session_provider
        self.last_alert: dict[tuple[str, str], float] = {}
        self.matches_total = 0

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                payload = dict(event.payload)
                if payload.get("type") not in {"PACKET", "FILE_ANALYSIS"}:
                    continue
                indicators = self.store.enabled()
                if not indicators:
                    self.state.update_metrics(
                        ioc_watch={"enabled": 0, "matches_total": self.matches_total}
                    )
                    self.health.heartbeat("IOC watchlist empty")
                    continue

                for match in match_observables(payload, indicators):
                    indicator_id = str(match.get("indicator_id") or "")
                    observable = str(match.get("observable") or "")
                    key = (indicator_id, observable)
                    now = time.monotonic()
                    if now - self.last_alert.get(key, 0.0) < 300:
                        continue
                    self.last_alert[key] = now
                    self.matches_total += 1
                    severity = SEVERITY_MAP.get(
                        str(match.get("severity") or "HIGH").upper(), Severity.HIGH
                    )
                    await self.bus.publish(
                        Event(
                            source=self.name,
                            kind=EventKind.ALERT,
                            session_id=session_id,
                            severity=severity,
                            evidence_class="OPERATOR_IOC_MATCH",
                            payload={
                                "type": "IOC_MATCH",
                                "title": "Watchlist indicator matched live telemetry",
                                "confidence": 100,
                                "evidence": {
                                    "indicator_id": indicator_id,
                                    "indicator_kind": match.get("kind"),
                                    "indicator": match.get("value"),
                                    "label": match.get("label"),
                                    "observable": observable,
                                    "source": payload.get("src_ip"),
                                    "destination": payload.get("dst_ip"),
                                    "dns_query": payload.get("dns_query"),
                                    "tls_sni": payload.get("tls_sni"),
                                    "http_host": payload.get("http_host"),
                                    "sha256": payload.get("sha256"),
                                },
                            },
                        )
                    )
                    self.state.update_metrics(
                        ioc_watch={
                            "enabled": len(indicators),
                            "matches_total": self.matches_total,
                            "last_match": {
                                "kind": match.get("kind"),
                                "value": match.get("value"),
                                "observable": observable,
                            },
                        }
                    )
                self.health.heartbeat(
                    f"enabled={len(indicators)} matches={self.matches_total}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
