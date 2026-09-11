from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.policy import Role
from campus_ops.response import ResponseEngine
from campus_ops.workers.base import BaseWorker


def _root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root


@dataclass(slots=True)
class ScheduledAction:
    schedule_id: str
    execute_at: str
    endpoint_id: str
    action: str
    arguments: dict[str, Any]
    role: str
    operator: str
    incident_id: str | None = None
    status: str = "SCHEDULED"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    result: dict[str, Any] = field(default_factory=dict)


class ResponseSchedulerWorker(BaseWorker):
    """Durable one-shot scheduler for policy-gated endpoint response jobs."""

    def __init__(self, bus: EventBus, response: ResponseEngine, path: Path | None = None) -> None:
        super().__init__("job-scheduler", bus)
        self.response = response
        self.path = path or (_root() / "scheduled_actions.json")
        self._items: dict[str, ScheduledAction] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                entry = ScheduledAction(**item)
                self._items[entry.schedule_id] = entry
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._items = {}

    def _save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(
            json.dumps([asdict(item) for item in self._items.values()], indent=2, default=str),
            encoding="utf-8",
        )
        temp.replace(self.path)

    def schedule(
        self,
        *,
        execute_at: datetime,
        endpoint_id: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        role: Role = Role.PLATFORM_ADMINISTRATOR,
        operator: str = "local-console",
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        when = execute_at.astimezone(UTC) if execute_at.tzinfo else execute_at.replace(tzinfo=UTC)
        if when <= datetime.now(UTC):
            raise ValueError("execute_at must be in the future")
        item = ScheduledAction(
            schedule_id=str(uuid4()),
            execute_at=when.isoformat(),
            endpoint_id=endpoint_id,
            action=action.upper(),
            arguments=dict(arguments or {}),
            role=role.value,
            operator=operator,
            incident_id=incident_id,
        )
        self._items[item.schedule_id] = item
        self._save()
        return asdict(item)

    def cancel(self, schedule_id: str) -> bool:
        item = self._items.get(schedule_id)
        if item is None or item.status != "SCHEDULED":
            return False
        item.status = "CANCELLED"
        self._save()
        return True

    def list(self, limit: int = 200) -> list[dict[str, Any]]:
        items = sorted(self._items.values(), key=lambda item: item.execute_at, reverse=True)
        return [asdict(item) for item in items[: max(1, min(limit, 1000))]]

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            now = datetime.now(UTC)
            changed = False
            for item in list(self._items.values()):
                if item.status != "SCHEDULED":
                    continue
                try:
                    execute_at = datetime.fromisoformat(item.execute_at)
                except ValueError:
                    item.status = "FAILED"
                    item.result = {"reason": "invalid execute_at"}
                    changed = True
                    continue
                if execute_at.tzinfo is None:
                    execute_at = execute_at.replace(tzinfo=UTC)
                if execute_at.astimezone(UTC) > now:
                    continue
                try:
                    job = await self.response.queue(
                        endpoint_id=item.endpoint_id,
                        action=item.action,
                        arguments=item.arguments,
                        role=Role(item.role),
                        operator=item.operator,
                        incident_id=item.incident_id,
                    )
                except (KeyError, ValueError, PermissionError) as exc:
                    item.status = "FAILED"
                    item.result = {"reason": str(exc)}
                else:
                    item.status = "QUEUED"
                    item.result = {"job_id": job["job_id"]}
                changed = True
            if changed:
                self._save()
            pending = sum(1 for item in self._items.values() if item.status == "SCHEDULED")
            self.health.heartbeat(f"scheduled={pending}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except TimeoutError:
                pass
