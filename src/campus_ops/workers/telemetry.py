from __future__ import annotations

import asyncio
import time

import psutil

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class TelemetryWorker(BaseWorker):
    """Host/interface performance telemetry independent of packet decoders."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, interface_provider, interval: float = 1.0) -> None:
        super().__init__("telemetry", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self.interval = interval

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        previous = None
        previous_t = time.monotonic()
        while not self.stopping:
            interface = self.interface_provider()
            session_id = self.session_provider()
            counters = psutil.net_io_counters(pernic=True)
            current = counters.get(interface) if interface else None
            now = time.monotonic()
            cpu = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory().percent
            values = {
                "cpu_percent": cpu,
                "memory_percent": memory,
                "interface": interface,
                "rx_bps": 0.0,
                "tx_bps": 0.0,
                "rx_pps": 0.0,
                "tx_pps": 0.0,
                "rx_bytes_total": current.bytes_recv if current else 0,
                "tx_bytes_total": current.bytes_sent if current else 0,
            }
            if current is not None and previous is not None:
                dt = max(now - previous_t, 0.001)
                values.update(
                    rx_bps=max(0.0, (current.bytes_recv - previous.bytes_recv) * 8 / dt),
                    tx_bps=max(0.0, (current.bytes_sent - previous.bytes_sent) * 8 / dt),
                    rx_pps=max(0.0, (current.packets_recv - previous.packets_recv) / dt),
                    tx_pps=max(0.0, (current.packets_sent - previous.packets_sent) / dt),
                )
            self.state.update_metrics(**values)
            if session_id:
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.OBSERVATION,
                        session_id=session_id,
                        evidence_class="OS_INTERFACE_COUNTERS",
                        payload={"type": "PERFORMANCE", **values},
                    )
                )
            previous = current
            previous_t = now
            self.health.heartbeat(f"interface={interface or 'none'}")
            await asyncio.sleep(self.interval)
