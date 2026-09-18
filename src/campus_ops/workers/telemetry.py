from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import psutil

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class TelemetryWorker(BaseWorker):
    """Host/interface performance telemetry independent of packet decoders."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider,
        interface_provider,
        interval: float = 1.0,
    ) -> None:
        super().__init__("telemetry", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self.interval = interval

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        previous = None
        previous_interface: str | None = None
        previous_session_id: str | None = None
        previous_t = time.monotonic()
        while not self.stopping:
            interface = self.interface_provider()
            session_id = self.session_provider()
            now = time.monotonic()

            try:
                counters = psutil.net_io_counters(pernic=True)
                current = counters.get(interface) if interface else None
                cpu = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory().percent
            except (OSError, psutil.Error) as exc:
                previous = None
                previous_interface = None
                previous_t = now
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(f"telemetry retry after OS counter error: {exc}")
                await asyncio.sleep(self.interval)
                continue

            # Never compare counters across NICs or monitoring sessions. Doing so can
            # turn a legitimate failover/session reset into a synthetic traffic spike.
            if interface != previous_interface or session_id != previous_session_id:
                previous = None
                previous_t = now

            rate_valid = bool(
                session_id
                and interface
                and current is not None
                and previous is not None
                and interface == previous_interface
                and session_id == previous_session_id
            )
            values = {
                "cpu_percent": cpu,
                "memory_percent": memory,
                "interface": interface,
                "telemetry_rate_valid": rate_valid,
                "telemetry_sample_at": datetime.now(UTC).isoformat(),
                "rx_bps": None,
                "tx_bps": None,
                "rx_pps": None,
                "tx_pps": None,
                "rx_bytes_total": current.bytes_recv if current else None,
                "tx_bytes_total": current.bytes_sent if current else None,
            }
            if rate_valid:
                dt = max(now - previous_t, 0.001)
                values.update(
                    rx_bps=max(0.0, (current.bytes_recv - previous.bytes_recv) * 8 / dt),
                    tx_bps=max(0.0, (current.bytes_sent - previous.bytes_sent) * 8 / dt),
                    rx_pps=max(0.0, (current.packets_recv - previous.packets_recv) / dt),
                    tx_pps=max(0.0, (current.packets_sent - previous.packets_sent) / dt),
                )
            self.state.update_metrics(**values)

            # Downstream baselines receive only measured deltas. The first sample
            # after startup/session change is a baseline point, not a fabricated zero.
            if session_id and rate_valid:
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
            previous_interface = interface
            previous_session_id = session_id
            previous_t = now
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat(f"interface={interface or 'none'}")
            await asyncio.sleep(self.interval)
