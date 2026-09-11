from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class WorkerState(StrEnum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventKind(StrEnum):
    SYSTEM = "SYSTEM"
    HEALTH = "HEALTH"
    NETWORK = "NETWORK"
    TOOL = "TOOL"
    OBSERVATION = "OBSERVATION"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    ACTION = "ACTION"


@dataclass(frozen=True, slots=True)
class Event:
    source: str
    kind: EventKind
    payload: Mapping[str, Any]
    session_id: str | None = None
    severity: Severity = Severity.INFO
    evidence_class: str = "SYSTEM_DERIVED"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class WorkerHealth:
    name: str
    state: WorkerState = WorkerState.STOPPED
    detail: str = ""
    last_heartbeat: datetime | None = None
    last_error: str | None = None
    dropped_events: int = 0

    def heartbeat(self, detail: str | None = None) -> None:
        self.last_heartbeat = datetime.now(UTC)
        if detail is not None:
            self.detail = detail


@dataclass(frozen=True, slots=True)
class NetworkCandidate:
    name: str
    is_up: bool
    is_loopback: bool
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    default_route: bool = False
    route_metric: int | None = None
    bytes_recv: int = 0
    bytes_sent: int = 0
    category: str = "unknown"


@dataclass(frozen=True, slots=True)
class SelectedNetwork:
    interface: str
    score: int
    reasons: tuple[str, ...]
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    default_route: bool
    route_metric: int | None
