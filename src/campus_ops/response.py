from __future__ import annotations

from campus_ops.agent_plane import AgentRegistry
from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity
from campus_ops.policy import ControlAction, PolicyEngine, Role

ACTION_MAP: dict[str, ControlAction] = {
    "COLLECT_SNAPSHOT": ControlAction.COLLECT_SNAPSHOT,
    "STOP_PROCESS": ControlAction.STOP_PROCESS,
    "QUARANTINE_FILE": ControlAction.QUARANTINE_FILE,
    "BLOCK_REMOTE_IP": ControlAction.BLOCK_REMOTE_IP,
}


class ResponseEngine:
    """Policy-gated response queue for explicitly enrolled endpoint agents."""

    def __init__(self, bus: EventBus, agents: AgentRegistry, session_provider) -> None:
        self.bus = bus
        self.agents = agents
        self.session_provider = session_provider
        self.policy = PolicyEngine()

    async def queue(
        self,
        *,
        endpoint_id: str,
        action: str,
        arguments: dict[str, object] | None = None,
        role: Role = Role.PLATFORM_ADMINISTRATOR,
        operator: str = "local-console",
        incident_id: str | None = None,
    ) -> dict[str, object]:
        normalized = action.upper()
        policy_action = ACTION_MAP.get(normalized)
        if policy_action is None:
            raise ValueError("unsupported response action")
        decision = self.policy.authorize(role, policy_action)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if self.agents.get(endpoint_id) is None:
            raise KeyError("endpoint agent not enrolled")

        job = self.agents.queue_job(
            endpoint_id,
            normalized,
            arguments,
            created_by=operator,
        )
        await self.bus.publish(
            Event(
                source="response-engine",
                kind=EventKind.ACTION,
                session_id=self.session_provider(),
                severity=Severity.MEDIUM if normalized != "COLLECT_SNAPSHOT" else Severity.INFO,
                evidence_class="OPERATOR_AUTHORIZED_ACTION",
                payload={
                    "action": "RESPONSE_JOB_QUEUED",
                    "response_action": normalized,
                    "endpoint_id": endpoint_id,
                    "job_id": job["job_id"],
                    "incident_id": incident_id,
                    "operator": operator,
                    "role": role.value,
                    "arguments": dict(arguments or {}),
                    "message": f"{normalized.replace('_', ' ').title()} queued for {endpoint_id}",
                    "voice": f"Response action queued for {endpoint_id}.",
                },
            )
        )
        return job

    async def record_result(self, job: dict[str, object]) -> None:
        status = str(job.get("status") or "UNKNOWN")
        await self.bus.publish(
            Event(
                source="response-engine",
                kind=EventKind.ACTION,
                session_id=self.session_provider(),
                severity=Severity.INFO if status == "SUCCEEDED" else Severity.MEDIUM,
                evidence_class="AGENT_RESPONSE_RESULT",
                payload={
                    "action": "RESPONSE_JOB_RESULT",
                    "response_action": job.get("action"),
                    "endpoint_id": job.get("endpoint_id"),
                    "job_id": job.get("job_id"),
                    "status": status,
                    "result": job.get("result"),
                    "message": f"Response job {status.lower()}",
                    "voice": f"Response job {status.lower()}.",
                },
            )
        )
