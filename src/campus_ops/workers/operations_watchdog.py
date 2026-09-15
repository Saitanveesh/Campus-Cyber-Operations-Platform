from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

SnapshotProvider = Callable[[], dict[str, object]]
SessionProvider = Callable[[], str | None]


class OperationsWatchdogWorker(BaseWorker):
    """Continuous supervisory watch over capture, workers, incidents and response control."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider: SessionProvider,
        snapshot_provider: SnapshotProvider,
        interval: float = 2.0,
        briefing_interval: float = 300.0,
    ) -> None:
        super().__init__("operations-watchdog", bus)
        self.state = state
        self.session_provider = session_provider
        self.snapshot_provider = snapshot_provider
        self.interval = max(1.0, interval)
        self.briefing_interval = max(60.0, briefing_interval)
        self._active: dict[str, dict[str, object]] = {}
        self._last_check: str | None = None
        self._checks = 0
        self._last_announced: dict[str, float] = {}
        self._last_briefing_at: str | None = None
        self._last_briefing_monotonic = time.monotonic()

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

    @staticmethod
    def _age_seconds(value: object) -> float | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return max(0.0, (datetime.now(UTC) - parsed.astimezone(UTC)).total_seconds())

    @classmethod
    def evaluate(cls, snapshot: dict[str, object]) -> dict[str, dict[str, object]]:
        conditions: dict[str, dict[str, object]] = {}
        session_id = snapshot.get("session_id")
        live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
        capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
        metrics = live.get("metrics") if isinstance(live.get("metrics"), dict) else {}
        workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}

        if session_id:
            capture_state = str(capture.get("state") or "UNKNOWN").upper()
            detail = str(capture.get("detail") or capture_state)
            if capture_state in {"ERROR", "UNAVAILABLE", "CAPTURE_ERROR"}:
                key, value = cls._condition(
                    "capture-unavailable",
                    Severity.HIGH,
                    "Packet capture needs attention",
                    detail,
                    "Packet capture needs attention.",
                )
                conditions[key] = value
            elif capture_state in {"STARTING", "WAITING", "READY_FOR_CAPTURE"}:
                key, value = cls._condition(
                    "capture-not-ready",
                    Severity.MEDIUM,
                    "Packet capture is not ready",
                    detail,
                    "Packet capture is not ready yet.",
                )
                conditions[key] = value
            elif capture_state in {"STALLED", "CAPTURE_STALLED", "CAPTURE_SUSPECT"}:
                key, value = cls._condition(
                    "capture-stalled",
                    Severity.HIGH,
                    "Packet capture may be stalled",
                    detail,
                    "Attention. Packet capture may be stalled.",
                )
                conditions[key] = value

        windows_security = metrics.get("windows_security") if isinstance(metrics.get("windows_security"), dict) else {}
        if bool(windows_security.get("available")):
            defender = windows_security.get("defender") if isinstance(windows_security.get("defender"), dict) else {}
            if defender.get("realtime_enabled") is False or defender.get("antivirus_enabled") is False:
                key, value = cls._condition(
                    "defender-protection-disabled",
                    Severity.HIGH,
                    "Windows Defender protection is disabled",
                    f"antivirus={defender.get('antivirus_enabled')} realtime={defender.get('realtime_enabled')}",
                    "Attention. Windows Defender protection is disabled on the monitoring host.",
                )
                conditions[key] = value
            firewall = windows_security.get("firewall") if isinstance(windows_security.get("firewall"), dict) else {}
            disabled_profiles = [name for name, enabled in firewall.items() if enabled is False]
            if disabled_profiles:
                key, value = cls._condition(
                    "firewall-profiles-disabled",
                    Severity.MEDIUM,
                    "Windows Firewall profile is disabled",
                    ", ".join(disabled_profiles),
                    "One or more Windows Firewall profiles are disabled on the monitoring host.",
                )
                value["count"] = len(disabled_profiles)
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
            elif state == WorkerState.HEALTHY.value:
                heartbeat_age = cls._age_seconds(raw.get("last_heartbeat"))
                if heartbeat_age is not None and heartbeat_age > 45:
                    key, value = cls._condition(
                        f"worker-stale:{name}",
                        Severity.HIGH,
                        f"{name} worker stopped reporting",
                        f"last heartbeat {int(heartbeat_age)} seconds ago",
                        f"Attention. {name.replace('-', ' ')} stopped reporting.",
                    )
                    conditions[key] = value

        event_bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), dict) else {}
        dropped = 0
        pressured: list[str] = []
        for name, raw in event_bus.items():
            if not isinstance(raw, dict):
                continue
            dropped += int(raw.get("dropped") or 0)
            queued = int(raw.get("queued") or 0)
            capacity = int(raw.get("capacity") or 0)
            if capacity > 0 and queued / capacity >= 0.75:
                pressured.append(f"{name}={queued}/{capacity}")
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
        elif pressured:
            key, value = cls._condition(
                "event-pressure",
                Severity.MEDIUM,
                "Event pipeline is under pressure",
                ", ".join(pressured[:8]),
                "The event pipeline is under pressure.",
            )
            conditions[key] = value

        incidents = live.get("incidents") if isinstance(live.get("incidents"), list) else []
        critical_open = 0
        high_open = 0
        unattended: list[str] = []
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            status = str(incident.get("status") or "OPEN").upper()
            if status == "CLOSED":
                continue
            severity = str(incident.get("severity") or "").upper()
            critical_open += int(severity == Severity.CRITICAL.value)
            high_open += int(severity == Severity.HIGH.value)
            if status == "OPEN" and severity in {Severity.HIGH.value, Severity.CRITICAL.value}:
                age = cls._age_seconds(incident.get("first_seen"))
                if age is not None and age >= 60:
                    unattended.append(str(incident.get("id") or incident.get("title") or "incident"))
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
        if unattended:
            key, value = cls._condition(
                "unattended-incidents",
                Severity.HIGH,
                "Open incidents are awaiting acknowledgement",
                f"unacknowledged high-priority incidents={len(unattended)}",
                "High priority incidents are still awaiting acknowledgement.",
            )
            value["count"] = len(unattended)
            conditions[key] = value

        jobs = snapshot.get("response_jobs") if isinstance(snapshot.get("response_jobs"), list) else []
        failed_jobs = 0
        stuck_jobs = 0
        for job in jobs[:200]:
            if not isinstance(job, dict):
                continue
            status = str(job.get("status") or "").upper()
            if status in {"FAILED", "REJECTED"}:
                failed_jobs += 1
                continue
            age = cls._age_seconds(job.get("claimed_at") or job.get("created_at"))
            if age is None:
                continue
            if status == "QUEUED" and age >= 120:
                stuck_jobs += 1
            elif status == "CLAIMED" and age >= 180:
                stuck_jobs += 1
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
        if stuck_jobs:
            key, value = cls._condition(
                "response-job-stalled",
                Severity.HIGH,
                "Response jobs appear stalled",
                f"stalled response jobs={stuck_jobs}",
                "Attention. One or more response jobs appear stalled.",
            )
            value["count"] = stuck_jobs
            conditions[key] = value

        agents = snapshot.get("managed_agents") if isinstance(snapshot.get("managed_agents"), list) else []
        offline = [
            agent
            for agent in agents
            if isinstance(agent, dict)
            and agent.get("last_seen")
            and str(agent.get("status") or "").upper() == "OFFLINE"
        ]
        if offline:
            key, value = cls._condition(
                "managed-agents-offline",
                Severity.MEDIUM,
                "Managed endpoint agents are offline",
                f"offline agents={len(offline)}",
                f"{len(offline)} managed endpoint agent{'s are' if len(offline) != 1 else ' is'} offline.",
            )
            value["count"] = len(offline)
            conditions[key] = value

        tools = snapshot.get("tools") if isinstance(snapshot.get("tools"), list) else []
        required_missing = [
            str(tool.get("label") or tool.get("key") or "tool")
            for tool in tools
            if isinstance(tool, dict) and bool(tool.get("required")) and not bool(tool.get("available"))
        ]
        if required_missing:
            key, value = cls._condition(
                "required-tools-missing",
                Severity.HIGH,
                "Required monitoring tools are unavailable",
                ", ".join(required_missing),
                "Attention. Required monitoring tools are unavailable.",
            )
            conditions[key] = value

        return conditions

    @staticmethod
    def _severity(value: object) -> Severity:
        try:
            return Severity(str(value))
        except ValueError:
            return Severity.MEDIUM

    @staticmethod
    def _reminder_seconds(severity: Severity) -> float:
        if severity == Severity.CRITICAL:
            return 90.0
        if severity == Severity.HIGH:
            return 180.0
        return 600.0

    @staticmethod
    def _incident_voice_detail(incident: dict[str, object]) -> str:
        title = str(incident.get("title") or "unnamed incident")
        severity = str(incident.get("severity") or "unknown").lower()
        source = str(incident.get("source") or "unknown source")
        evidence = incident.get("latest_evidence") if isinstance(incident.get("latest_evidence"), dict) else {}
        detail = f"highest priority is {title}, {severity} severity, source {source}"
        target = evidence.get("target") or evidence.get("destination") or evidence.get("dst")
        if target and str(target) != source:
            detail += f", targeting {target}"
        fanout = evidence.get("unique_destinations") or evidence.get("destination_count") or evidence.get("distinct_destinations")
        if fanout:
            detail += f", touching {fanout} destinations"
        return detail

    @classmethod
    def briefing(cls, snapshot: dict[str, object]) -> str:
        live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
        capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
        network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
        session_id = snapshot.get("session_id")
        if not session_id:
            return "There is no active monitoring session right now."

        interface = str(network.get("interface") or "the selected interface")
        capture_state = str(capture.get("state") or "unknown").replace("_", " ").lower()
        assets = live.get("assets") if isinstance(live.get("assets"), list) else []
        flows = live.get("flows") if isinstance(live.get("flows"), list) else []
        incidents = live.get("incidents") if isinstance(live.get("incidents"), list) else []
        open_incidents = [
            item
            for item in incidents
            if isinstance(item, dict) and str(item.get("status") or "OPEN").upper() != "CLOSED"
        ]
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        open_incidents.sort(
            key=lambda item: (
                severity_rank.get(str(item.get("severity") or "INFO").upper(), 0),
                int(item.get("confidence") or 0),
                str(item.get("last_seen") or ""),
            ),
            reverse=True,
        )
        critical = sum(
            1
            for item in open_incidents
            if str(item.get("severity") or "").upper() == Severity.CRITICAL.value
        )
        high = sum(
            1
            for item in open_incidents
            if str(item.get("severity") or "").upper() == Severity.HIGH.value
        )
        agents = snapshot.get("managed_agents") if isinstance(snapshot.get("managed_agents"), list) else []
        online_agents = sum(
            1
            for item in agents
            if isinstance(item, dict) and str(item.get("status") or "").upper() == "ONLINE"
        )
        watch = cls.evaluate(snapshot)

        parts = [
            f"Monitoring is running on {interface}",
            f"packet capture is {capture_state}",
            f"I can currently see {len(assets)} assets and {len(flows)} active flows",
        ]
        if open_incidents:
            parts.append(
                f"there are {len(open_incidents)} open incidents, including {critical} critical and {high} high severity"
            )
            parts.append(cls._incident_voice_detail(open_incidents[0]))
        else:
            parts.append("there are no open incidents")
        if agents:
            parts.append(f"{online_agents} of {len(agents)} managed endpoint agents are online")
        if watch:
            parts.append(f"the watchdog is tracking {len(watch)} operational conditions")
        else:
            parts.append("the watchdog reports no active operational problems")
        return ". ".join(parts) + "."

    async def _publish_transition(self, key: str, condition: dict[str, object], resolved: bool) -> None:
        session_id = self.session_provider()
        if resolved:
            payload = {
                "type": "WATCHDOG_STATUS",
                "condition": key,
                "state": "RESOLVED",
                "title": f"Resolved: {condition.get('title')}",
                "detail": condition.get("detail"),
                "voice": f"Resolved. {condition.get('title')}.",
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

    async def _publish_briefing(self, snapshot: dict[str, object]) -> None:
        text = self.briefing(snapshot)
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.ACTION,
                session_id=self.session_provider(),
                severity=Severity.INFO,
                evidence_class="OPERATIONS_ASSISTANT_BRIEFING",
                payload={
                    "action": "OPERATIONS_BRIEFING",
                    "message": text,
                    "voice": text,
                },
            )
        )
        self._last_briefing_at = datetime.now(UTC).isoformat()
        self._last_briefing_monotonic = time.monotonic()

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
            "briefing_interval_seconds": self.briefing_interval,
            "last_briefing_at": self._last_briefing_at,
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
            now = time.monotonic()

            for key, condition in current.items():
                severity = self._severity(condition.get("severity"))
                first_seen = key not in previous
                changed = not first_seen and condition != previous[key]
                due = now - self._last_announced.get(key, 0.0) >= self._reminder_seconds(severity)
                if first_seen or changed or due:
                    await self._publish_transition(key, condition, resolved=False)
                    self._last_announced[key] = now
            for key, condition in previous.items():
                if key not in current:
                    await self._publish_transition(key, condition, resolved=True)
                    self._last_announced.pop(key, None)

            self._active = current
            self._checks += 1
            self._last_check = datetime.now(UTC).isoformat()
            if now - self._last_briefing_monotonic >= self.briefing_interval:
                await self._publish_briefing(snapshot)

            if current:
                self.health.heartbeat(f"watching; active conditions={len(current)}")
            else:
                self.health.heartbeat("watching; no active conditions")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
