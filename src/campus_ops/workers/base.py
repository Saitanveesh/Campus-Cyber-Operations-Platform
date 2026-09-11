from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerHealth, WorkerState


class BaseWorker(ABC):
    def __init__(self, name: str, bus: EventBus) -> None:
        self.name = name
        self.bus = bus
        self.health = WorkerHealth(name=name)
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self.health.state = WorkerState.STARTING
        self._task = asyncio.create_task(self._runner(), name=f"worker:{self.name}")

    async def stop(self) -> None:
        self.health.state = WorkerState.STOPPING
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.health.state = WorkerState.STOPPED

    async def _runner(self) -> None:
        try:
            await self.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.health.state = WorkerState.FAILED
            self.health.last_error = f"{type(exc).__name__}: {exc}"
            self.health.heartbeat("worker failed")
        else:
            if self.health.state not in {WorkerState.FAILED, WorkerState.STOPPING}:
                self.health.state = WorkerState.STOPPED

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    @abstractmethod
    async def run(self) -> None:
        raise NotImplementedError
