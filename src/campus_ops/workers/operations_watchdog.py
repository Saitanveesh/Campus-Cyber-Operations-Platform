from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

SnapshotProvider = Callable[[], dict[str, object]]
SessionProvider = Callable[[], str | None]


class OperationsWatchdogWorker(BaseWorker):
    """Continuous supervisory watch over live capture, workers, incidents and control jobs."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider: SessionProvider,
        snapshot_provider: SnapshotProvider,
        interval: float = 2.0,
    ) -> None:
        super().__init__("operations-watchdog", bus)
        self.state = state
        self.session_provider = session_provider
        self.snapshot_provider = snapshot_provider
        self.interval = max(1.0, interval)
        self._active: dict[str, dict[str, object]] = {}
        self._last_check: str | None = None
        self._checks = 0

    @staticmethod
    def _condition(
        key: str,
        severity: Severity,
        title: str,
        detail: str,
        voice: str | None = None,
    ) -> tuple[str, dict[str, object]]:
        return (
            key,
            {
                "severity": severity.value,
                "title": title,
                "detail": detail,
                "voice": voice or title,
            },
        )

    @classmethod
    def evaluate(cls, snapshot: dict[str, object]) -> dict[str, dict[str, object]]:
        conditions: dict[str, dict[str, object]] = {}
        session_id = snapshot.get("session_id")
        live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
        capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
        workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}

        if session_id:
            capture_state = str(capture.get("state") or "UNKNOWN").upper()
            detail = str(capture.get("detail") or capture_state)
            if capture_state in {"ERROR", "UNAVAILABLE"}:
                key, value = cls._condition(
                    "capture-unavailable",
                    Severity.HIGH,
                    "Packet capture needs attention",
                    detail,
                    "Sai Tanveesh, packet capture needs attention.",
                )
                conditions[key] = value
            elif capture_state in {"STARTING", "WAITING"}:
                key, value = cls._condition(
                    "capture-not-ready",
                    Severity.MEDIUM,
                    "Packet capture is not ready",
                    detail,
                    "Packet capture is not ready yet.",
                )
                conditions[key] = value

        for name, raw in workers.items():
            if name == "operations-watchdog" or not isinstance(raw, dict):
                continue
            if bool(raw.get("optional")):
                continue
            state = str(raw.get("state") or "UNKNOWN").upper()
            detail = str(raw.get("detail") or "")
            if state == WorkerState.FAILED.value:
                key, value = cls._condition(
                    f"worker-failed:{name}",
                    Severity.HIGH,
                    f"{name} worker failed",
                    detail or "worker failure",
                    f"Attention. {name.replace('-', ' ')} worker has failed.",
                )
                conditions[key] = value
            elif state == WorkerState.DEGRADED.value:
                key, value = cls._condition(
                    f"worker-degraded:{name}",
                    Severity.MEDIUM,
                    f"{name} worker degraded",
                    detail or "worker degraded",
                    f"{name.replace('-', ' ')} is degraded.",
                )
                conditions[key] = value

        event_bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), dict) else {}
        dropped = 0
        for raw in event_bus.values():
            if isinstance(raw, dict):
                dropped += int(raw.get("dropped") or 0)
        if dropped:
            key, value = cls._condition(
                "event-loss",
                Severity.HIGH,
                "Event pipeline dropped data",
                f"dropped events={dropped}",
                "Attention. The event pipeline has dropped data.",
            )
            value["count"] = dropped
            conditions[key] = value

        incidents = live.get("incidents") if isinstance(live.get("incidents"), list) else []
        critical_open = 0
        high_open = 0
        for incident in incidents:
            if not isinstance(incident, dict) or str(incident.get("status") or "OPEN") == "CLOSED":
                continue
            severity = str(incident.get("severity") or "").upper()
            critical_open += int(severity == Severity.CRITICAL.value)
            high_open += int(severity == Severity.HIGH.value)
        if critical_open:
            key, value = cls._condition(
                "critical-incidents",
                Severity.CRITICAL,
                "Critical incident requires attention",
                f"open critical incidents={critical_open}",
                f"Critical alert. {critical_open} critical incident{'s' if critical_open != 1 else ''} require attention.",
            )
            value["count"] = critical_open
            conditions[key] = value
        elif high_open:
            key, value = cls._condition(
                "high-incidents",
                Severity.HIGH,
                "High severity incident requires attention",
                f"open high incidents={high_open}",
                f"{high_open} high severity incident{'s' if high_open != 1 else ''} require attention.",
            )
            value["count"] = high_open
            conditions[key] = value

        jobs = snapshot.get("response_jobs") if isinstance(snapshot.get("response_jobs"), list) else []
        failed_jobs = sum(
            1
            for job in jobs[:100]
            if isinstance(job, dict) and str(job.get("status") or "").upper() in {"FAILED", "REJECTED"}
        )
        if failed_jobs:
            key, value = cls._condition(
                "response-job-failures",
                Severity.MEDIUM,
                "Response jobs need review",
                f"failed or rejected response jobs={failed_jobs}",
                "One or more response jobs need review.",
            )
            value["count"] = failed_jobs
            conditions[key] = value

        return conditions

    @staticmethod
    def _severity(value: object) -> Severity:
        try:
            return Severity(str(value))
        except ValueError:
            return Severity.MEDIUM

    async def _publish_transition(self, key: str, condition: dict[str, object], resolved: bool) -> None:
        session_id = self.session_provider()
        if resolved:
            payload = {
                "type": "WATCHDOG_STATUS",
                "condition": key,
                "state": "RESOLVED",
                "title": f"Resolved: {condition.get('title')}",
                "detail": condition.get("detail"),
            }
            severity = Severity.INFO
        else:
            payload = {
                "type": "WATCHDOG_STATUS",
                "condition": key,
                "state": "ACTIVE",
                "title": condition.get("title"),
                "detail": condition.get("detail"),
                "voice": condition.get("voice"),
            }
            severity = self._severity(condition.get("severity"))
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.HEALTH,
                session_id=session_id,
                severity=severity,
                evidence_class="SYSTEM_HEALTH_WATCHDOG",
                payload=payload,
            )
        )

    def status(self) -> dict[str, object]:
        highest = Severity.INFO
        rank = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        for item in self._active.values():
            severity = self._severity(item.get("severity"))
            if rank[severity] > rank[highest]:
                highest = severity
        return {
            "state": "WATCHING" if self.health.state == WorkerState.HEALTHY else self.health.state.value,
            "last_check": self._last_check,
            "checks": self._checks,
            "interval_seconds": self.interval,
            "active_conditions": dict(self._active),
            "active_count": len(self._active),
            "highest_severity": highest.value,
        }

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        self.health.heartbeat("watchdog started")
        while not self.stopping:
            snapshot = self.snapshot_provider()
            current = self.evaluate(snapshot)
            previous = self._active

            for key, condition in current.items():
                if key not in previous or condition != previous[key]:
                    await self._publish_transition(key, condition, resolved=False)
            for key, condition in previous.items():
                if key not in current:
                    await self._publish_transition(key, condition, resolved=True)

            self._active = current
            self._checks += 1
            self._last_check = datetime.now(UTC).isoformat()
            if current:
                self.health.heartbeat(f"watching; active conditions={len(current)}")
            else:
                self.health.heartbeat("watching; no active conditions")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
