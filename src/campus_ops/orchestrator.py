from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from uuid import uuid4

from campus_ops.config import DEFAULT_SETTINGS, Settings
from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker
from campus_ops.workers.tool_probe import ToolProbeWorker


class Orchestrator:
    def __init__(self, settings: Settings = DEFAULT_SETTINGS) -> None:
        self.settings = settings
        self.bus = EventBus()
        self.started_at: datetime | None = None
        self.session_id: str | None = None
        self.network = NetworkDiscoveryWorker(
            self.bus,
            interval=settings.network_poll_seconds,
            switch_margin=settings.interface_switch_margin,
            confirmations=settings.interface_confirmations,
        )
        self.tools = ToolProbeWorker(self.bus, interval=settings.tool_probe_seconds)
        self.workers = [self.network, self.tools]

    async def start(self) -> None:
        if self.started_at is not None:
            return
        self.started_at = datetime.now(UTC)
        self.session_id = str(uuid4())
        for worker in self.workers:
            await worker.start()
        await self.bus.publish(
            Event(
                source="orchestrator",
                kind=EventKind.SYSTEM,
                session_id=self.session_id,
                payload={"state": "STARTED"},
            )
        )

    async def stop(self) -> None:
        for worker in reversed(self.workers):
            await worker.stop()
        self.session_id = None
        self.started_at = None

    def snapshot(self) -> dict[str, object]:
        worker_states = {
            worker.name: {
                "state": worker.health.state.value,
                "detail": worker.health.detail,
                "last_heartbeat": (
                    worker.health.last_heartbeat.isoformat() if worker.health.last_heartbeat else None
                ),
                "last_error": worker.health.last_error,
            }
            for worker in self.workers
        }
        overall = "HEALTHY"
        if any(worker.health.state == WorkerState.FAILED for worker in self.workers):
            overall = "FAILED"
        elif any(worker.health.state == WorkerState.DEGRADED for worker in self.workers):
            overall = "DEGRADED"
        return {
            "product": "Campus Cyber Operations Platform",
            "version": "0.1.0",
            "live_contract": "CURRENT_SESSION_ONLY",
            "overall": overall,
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "network": asdict(self.network.selected) if self.network.selected else None,
            "workers": worker_states,
            "tools": self.tools.statuses,
            "event_bus": self.bus.stats(),
        }
