from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


def _root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ManagedAgent:
    endpoint_id: str
    name: str
    platform: str
    token_hash: str
    host: str = ""
    enrolled_at: str = field(default_factory=_now)
    last_seen: str | None = None
    version: str | None = None
    status: str = "ENROLLED"
    telemetry: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentJob:
    job_id: str
    endpoint_id: str
    action: str
    arguments: dict[str, Any]
    created_at: str
    created_by: str
    status: str = "QUEUED"
    claimed_at: str | None = None
    completed_at: str | None = None
    result: dict[str, Any] = field(default_factory=dict)


class AgentRegistry:
    """Authenticated registry and durable job queue for explicitly enrolled agents."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (_root() / "agents.json")
        self.jobs_path = _root() / "agent_jobs.json"
        self._agents: dict[str, ManagedAgent] = {}
        self._jobs: dict[str, AgentJob] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                for item in raw if isinstance(raw, list) else []:
                    agent = ManagedAgent(**item)
                    self._agents[agent.endpoint_id] = agent
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self._agents = {}
        if self.jobs_path.exists():
            try:
                raw_jobs = json.loads(self.jobs_path.read_text(encoding="utf-8"))
                for item in raw_jobs if isinstance(raw_jobs, list) else []:
                    job = AgentJob(**item)
                    self._jobs[job.job_id] = job
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self._jobs = {}

    @staticmethod
    def _atomic_write(path: Path, value: object) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")
        temp.replace(path)

    def _save_agents(self) -> None:
        self._atomic_write(self.path, [asdict(item) for item in self._agents.values()])

    def _save_jobs(self) -> None:
        retained = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)[:2000]
        self._jobs = {item.job_id: item for item in retained}
        self._atomic_write(self.jobs_path, [asdict(item) for item in retained])

    def enroll(self, endpoint_id: str, name: str, platform: str, host: str = "") -> dict[str, Any]:
        if endpoint_id in self._agents:
            raise ValueError("agent endpoint_id already enrolled")
        token = secrets.token_urlsafe(32)
        agent = ManagedAgent(
            endpoint_id=endpoint_id,
            name=name,
            platform=platform,
            host=host,
            token_hash=_token_hash(token),
        )
        self._agents[endpoint_id] = agent
        self._save_agents()
        public = self._public(agent)
        public["enrollment_token"] = token
        return public

    def rotate_token(self, endpoint_id: str) -> str:
        agent = self._agents.get(endpoint_id)
        if agent is None:
            raise KeyError("agent not enrolled")
        token = secrets.token_urlsafe(32)
        agent.token_hash = _token_hash(token)
        self._save_agents()
        return token

    def remove(self, endpoint_id: str) -> bool:
        removed = self._agents.pop(endpoint_id, None)
        if removed is None:
            return False
        for job_id in [job_id for job_id, job in self._jobs.items() if job.endpoint_id == endpoint_id]:
            del self._jobs[job_id]
        self._save_agents()
        self._save_jobs()
        return True

    @staticmethod
    def _public(agent: ManagedAgent) -> dict[str, Any]:
        return {
            "endpoint_id": agent.endpoint_id,
            "name": agent.name,
            "platform": agent.platform,
            "host": agent.host,
            "enrolled_at": agent.enrolled_at,
            "last_seen": agent.last_seen,
            "version": agent.version,
            "status": agent.status,
            "telemetry": dict(agent.telemetry),
        }

    def list(self) -> list[dict[str, Any]]:
        return [self._public(item) for item in sorted(self._agents.values(), key=lambda x: x.name.lower())]

    def get(self, endpoint_id: str) -> dict[str, Any] | None:
        agent = self._agents.get(endpoint_id)
        return self._public(agent) if agent else None

    def authenticate(self, endpoint_id: str, token: str) -> bool:
        agent = self._agents.get(endpoint_id)
        if agent is None or not token:
            return False
        return secrets.compare_digest(agent.token_hash, _token_hash(token))

    def heartbeat(
        self,
        endpoint_id: str,
        token: str,
        *,
        host: str,
        version: str,
        telemetry: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.authenticate(endpoint_id, token):
            raise PermissionError("agent authentication failed")
        agent = self._agents[endpoint_id]
        agent.host = host or agent.host
        agent.version = version
        agent.last_seen = _now()
        agent.status = "ONLINE"
        agent.telemetry = dict(telemetry)
        self._save_agents()
        return self._public(agent)

    def queue_job(
        self,
        endpoint_id: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        *,
        created_by: str = "local-console",
    ) -> dict[str, Any]:
        if endpoint_id not in self._agents:
            raise KeyError("agent not enrolled")
        job = AgentJob(
            job_id=str(uuid4()),
            endpoint_id=endpoint_id,
            action=action,
            arguments=dict(arguments or {}),
            created_at=_now(),
            created_by=created_by,
        )
        self._jobs[job.job_id] = job
        self._save_jobs()
        return asdict(job)

    def claim_jobs(self, endpoint_id: str, token: str, limit: int = 10) -> list[dict[str, Any]]:
        if not self.authenticate(endpoint_id, token):
            raise PermissionError("agent authentication failed")
        limit = max(1, min(limit, 25))
        pending = [
            job
            for job in sorted(self._jobs.values(), key=lambda item: item.created_at)
            if job.endpoint_id == endpoint_id and job.status == "QUEUED"
        ][:limit]
        claimed = _now()
        for job in pending:
            job.status = "CLAIMED"
            job.claimed_at = claimed
        if pending:
            self._save_jobs()
        return [asdict(job) for job in pending]

    def report_job(
        self,
        endpoint_id: str,
        token: str,
        job_id: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.authenticate(endpoint_id, token):
            raise PermissionError("agent authentication failed")
        job = self._jobs.get(job_id)
        if job is None or job.endpoint_id != endpoint_id:
            raise KeyError("job not found")
        normalized = status.upper()
        if normalized not in {"SUCCEEDED", "FAILED", "REJECTED"}:
            raise ValueError("invalid terminal job status")
        job.status = normalized
        job.result = dict(result or {})
        job.completed_at = _now()
        self._save_jobs()
        return asdict(job)

    def jobs(self, endpoint_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        items = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)
        if endpoint_id:
            items = [item for item in items if item.endpoint_id == endpoint_id]
        return [asdict(item) for item in items[: max(1, min(limit, 1000))]]
