from __future__ import annotations

import asyncio
import socket

import psutil

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class LocalHostTelemetryWorker(BaseWorker):
    """Health telemetry for the Windows host running the console."""

    def __init__(self, bus: EventBus, state: LiveState, interval: float = 3.0) -> None:
        super().__init__("local-host-telemetry", bus)
        self.state = state
        self.interval = interval

    @staticmethod
    def _connections() -> tuple[int | None, list[int]]:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return None, []
        listening: set[int] = set()
        for item in connections:
            if item.status == psutil.CONN_LISTEN and item.laddr:
                listening.add(int(item.laddr.port))
        return len(connections), sorted(listening)[:100]

    async def run(self) -> None:
        psutil.cpu_percent(interval=None)
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            connection_count, listening_ports = await asyncio.to_thread(self._connections)
            virtual_memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            self.state.update_metrics(
                host_name=socket.gethostname(),
                host_cpu_percent=psutil.cpu_percent(interval=None),
                host_memory_percent=virtual_memory.percent,
                host_memory_used=virtual_memory.used,
                host_memory_total=virtual_memory.total,
                host_disk_percent=disk.percent,
                host_disk_used=disk.used,
                host_disk_total=disk.total,
                host_process_count=len(psutil.pids()),
                host_connection_count=connection_count,
                host_listening_ports=listening_ports,
            )
            detail = f"cpu={psutil.cpu_percent(interval=None):.0f}% mem={virtual_memory.percent:.0f}%"
            if connection_count is None:
                detail += " connections=restricted"
            else:
                detail += f" connections={connection_count}"
            self.health.heartbeat(detail)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
