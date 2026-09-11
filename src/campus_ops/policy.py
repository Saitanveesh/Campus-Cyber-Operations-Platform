from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    OBSERVER = "OBSERVER"
    ANALYST = "ANALYST"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    LAB_ADMINISTRATOR = "LAB_ADMINISTRATOR"
    PLATFORM_ADMINISTRATOR = "PLATFORM_ADMINISTRATOR"


class ControlAction(StrEnum):
    VIEW = "VIEW"
    ACKNOWLEDGE_INCIDENT = "ACKNOWLEDGE_INCIDENT"
    EXPORT_EVIDENCE = "EXPORT_EVIDENCE"
    CONNECT_ENDPOINT = "CONNECT_ENDPOINT"
    COLLECT_SNAPSHOT = "COLLECT_SNAPSHOT"
    STOP_PROCESS = "STOP_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    BLOCK_REMOTE_IP = "BLOCK_REMOTE_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    RESTORE_NETWORK = "RESTORE_NETWORK"
    MANAGE_ENDPOINTS = "MANAGE_ENDPOINTS"
    MANAGE_PLATFORM = "MANAGE_PLATFORM"


ROLE_ACTIONS: dict[Role, frozenset[ControlAction]] = {
    Role.OBSERVER: frozenset({ControlAction.VIEW}),
    Role.ANALYST: frozenset(
        {
            ControlAction.VIEW,
            ControlAction.ACKNOWLEDGE_INCIDENT,
            ControlAction.EXPORT_EVIDENCE,
        }
    ),
    Role.INCIDENT_RESPONDER: frozenset(
        {
            ControlAction.VIEW,
            ControlAction.ACKNOWLEDGE_INCIDENT,
            ControlAction.EXPORT_EVIDENCE,
            ControlAction.CONNECT_ENDPOINT,
            ControlAction.COLLECT_SNAPSHOT,
            ControlAction.STOP_PROCESS,
            ControlAction.QUARANTINE_FILE,
            ControlAction.BLOCK_REMOTE_IP,
        }
    ),
    Role.LAB_ADMINISTRATOR: frozenset(
        {
            ControlAction.VIEW,
            ControlAction.ACKNOWLEDGE_INCIDENT,
            ControlAction.EXPORT_EVIDENCE,
            ControlAction.CONNECT_ENDPOINT,
            ControlAction.COLLECT_SNAPSHOT,
            ControlAction.STOP_PROCESS,
            ControlAction.QUARANTINE_FILE,
            ControlAction.BLOCK_REMOTE_IP,
            ControlAction.ISOLATE_HOST,
            ControlAction.RESTORE_NETWORK,
            ControlAction.MANAGE_ENDPOINTS,
        }
    ),
    Role.PLATFORM_ADMINISTRATOR: frozenset(ControlAction),
}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    role: Role
    action: ControlAction
    reason: str


class PolicyEngine:
    """Small explicit authorization engine for operator and response actions."""

    def authorize(self, role: Role, action: ControlAction) -> PolicyDecision:
        allowed = action in ROLE_ACTIONS.get(role, frozenset())
        return PolicyDecision(
            allowed=allowed,
            role=role,
            action=action,
            reason="role permits action" if allowed else "role does not permit action",
        )
