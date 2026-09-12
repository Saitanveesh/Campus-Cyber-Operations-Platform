from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from campus_ops.models import Event, EventKind, Severity


class LiveState:
    """Authoritative current-session-only live state."""

    def __init__(self, max_events: int = 1000, max_alerts: int = 500, max_packets: int = 300) -> None:
        self._lock = RLock()
        self.session_id: str | None = None
        self.session_started_at: datetime | None = None
        self.network_fingerprint: str | None = None
        self.visibility_mode = "HOST_ACCESS_PORT"
        self.metrics: dict[str, Any] = {}
        self.protocols: dict[str, int] = {}
        self.assets: dict[str, dict[str, Any]] = {}
        self.flows: dict[str, dict[str, Any]] = {}
        self.topology_edges: dict[str, dict[str, Any]] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.packet_feed: deque[dict[str, Any]] = deque(maxlen=max_packets)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self.incidents: dict[str, dict[str, Any]] = {}
        self.capture: dict[str, Any] = {}
        self.close_session()

    def start_session(self, session_id: str, fingerprint: str | None = None) -> None:
        with self._lock:
            self.session_id = session_id
            self.session_started_at = datetime.now(UTC)
            self.network_fingerprint = fingerprint
            self.metrics.clear()
            self.protocols.clear()
            self.assets.clear()
            self.flows.clear()
            self.topology_edges.clear()
            self.events.clear()
            self.packet_feed.clear()
            self.alerts.clear()
            self.incidents.clear()
            self.capture = {
                "state": "STARTING",
                "interface": None,
                "backend": None,
                "packets": 0,
                "bytes": 0,
                "last_packet_at": None,
                "detail": "new live session",
            }

    def close_session(self) -> None:
        with self._lock:
            self.session_id = None
            self.session_started_at = None
            self.network_fingerprint = None
            self.metrics.clear()
            self.protocols.clear()
            self.assets.clear()
            self.flows.clear()
            self.topology_edges.clear()
            self.events.clear()
            self.packet_feed.clear()
            self.alerts.clear()
            self.incidents.clear()
            self.capture = {
                "state": "UNAVAILABLE",
                "interface": None,
                "backend": None,
                "packets": 0,
                "bytes": 0,
                "last_packet_at": None,
                "detail": "no active session",
            }

    @staticmethod
    def _event_item(event: Event) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "kind": event.kind.value,
            "severity": event.severity.value,
            "evidence_class": event.evidence_class,
            "payload": dict(event.payload),
        }

    def ingest_event(self, event: Event) -> bool:
        with self._lock:
            if self.session_id is None or event.session_id != self.session_id:
                return False
            item = self._event_item(event)
            if event.payload.get("type") == "PACKET":
                self.packet_feed.appendleft(item)
            elif event.payload.get("type") != "PERFORMANCE":
                self.events.appendleft(item)
            if event.kind == EventKind.ALERT and event.severity in {
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            }:
                self.alerts.appendleft(item)
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "session_id": self.session_id,
                "session_started_at": self.session_started_at.isoformat() if self.session_started_at else None,
                "network_fingerprint": self.network_fingerprint,
                "visibility_mode": self.visibility_mode,
                "capture": dict(self.capture),
                "metrics": dict(self.metrics),
                "protocols": dict(self.protocols),
                "assets": list(self.assets.values()),
                "flows": list(self.flows.values()),
                "topology_edges": list(self.topology_edges.values()),
                "events": list(self.events),
                "packet_feed": list(self.packet_feed),
                "alerts": list(self.alerts),
                "incidents": list(self.incidents.values()),
            }

    def set_capture(self, **values: Any) -> None:
        with self._lock:
            self.capture.update(values)

    def get_capture(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.capture)

    def update_metrics(self, **values: Any) -> None:
        with self._lock:
            self.metrics.update(values)

    def increment_protocol(self, protocol: str, amount: int = 1) -> None:
        with self._lock:
            self.protocols[protocol] = self.protocols.get(protocol, 0) + amount

    def get_asset(self, key: str) -> dict[str, Any]:
        with self._lock:
            return dict(self.assets.get(key, {}))

    def upsert_asset(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            if self.session_id is not None:
                self.assets[key] = dict(value)

    def get_flow(self, key: str) -> dict[str, Any]:
        with self._lock:
            return dict(self.flows.get(key, {}))

    def upsert_flow(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            if self.session_id is not None:
                self.flows[key] = dict(value)

    def get_edge(self, key: str) -> dict[str, Any]:
        with self._lock:
            return dict(self.topology_edges.get(key, {}))

    def upsert_edge(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            if self.session_id is not None:
                self.topology_edges[key] = dict(value)

    def get_incident(self, incident_id: str | None) -> dict[str, Any]:
        with self._lock:
            if not incident_id:
                return {}
            return dict(self.incidents.get(incident_id, {}))

    def add_incident(self, incident_id: str, value: dict[str, Any]) -> None:
        with self._lock:
            if self.session_id is not None:
                self.incidents[incident_id] = dict(value)

    def update_incident(self, incident_id: str, **values: Any) -> dict[str, Any] | None:
        with self._lock:
            current = self.incidents.get(incident_id)
            if current is None:
                return None
            current.update(values)
            return dict(current)

    def incident_count(self) -> int:
        with self._lock:
            return len(self.incidents)

    @staticmethod
    def _age_seconds(raw_timestamp: object, now: datetime) -> float | None:
        if not raw_timestamp:
            return None
        try:
            timestamp = datetime.fromisoformat(str(raw_timestamp))
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return max(0.0, (now - timestamp.astimezone(UTC)).total_seconds())

    def prune_stale(
        self,
        *,
        now: datetime | None = None,
        asset_ttl_seconds: float = 600.0,
        flow_ttl_seconds: float = 180.0,
        edge_ttl_seconds: float = 180.0,
    ) -> dict[str, int]:
        """Expire stale live entities without touching historical storage."""
        current = now or datetime.now(UTC)
        removed = {"assets": 0, "flows": 0, "edges": 0}
        with self._lock:
            if self.session_id is None:
                return removed

            stale_assets = [
                key
                for key, value in self.assets.items()
                if (age := self._age_seconds(value.get("last_seen"), current)) is not None
                and age > asset_ttl_seconds
            ]
            stale_flows = [
                key
                for key, value in self.flows.items()
                if (age := self._age_seconds(value.get("last_seen"), current)) is not None
                and age > flow_ttl_seconds
            ]
            stale_edges = [
                key
                for key, value in self.topology_edges.items()
                if (age := self._age_seconds(value.get("last_seen"), current)) is not None
                and age > edge_ttl_seconds
            ]

            for key in stale_assets:
                del self.assets[key]
            for key in stale_flows:
                del self.flows[key]
            for key in stale_edges:
                del self.topology_edges[key]

            removed["assets"] = len(stale_assets)
            removed["flows"] = len(stale_flows)
            removed["edges"] = len(stale_edges)
            self.metrics.update(
                live_assets=len(self.assets),
                live_flows=len(self.flows),
                live_edges=len(self.topology_edges),
                last_prune_removed=sum(removed.values()),
                last_prune_at=current.isoformat(),
            )
        return removed
