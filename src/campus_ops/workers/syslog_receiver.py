from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.workers.base import BaseWorker

PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[tuple[bytes, tuple[str, int]]]) -> None:
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self.queue.put_nowait((data, addr))
            except asyncio.QueueFull:
                pass


def parse_syslog(raw: bytes, address: str) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace").strip()[:8192]
    facility = None
    severity = None
    match = PRI_RE.match(text)
    if match:
        pri = int(match.group("pri"))
        facility = pri // 8
        severity = pri % 8
    return {
        "type": "SYSLOG",
        "sender": address,
        "facility": facility,
        "syslog_severity": severity,
        "message": text,
    }


class SyslogReceiverWorker(BaseWorker):
    """Local UDP syslog collector feeding normalized operational events."""

    def __init__(self, bus: EventBus, session_provider, port: int | None = None) -> None:
        super().__init__("syslog-receiver", bus)
        self.session_provider = session_provider
        self.port = port if port is not None else int(os.environ.get("CAMPUS_OPS_SYSLOG_PORT", "5514"))
        self._transport: asyncio.DatagramTransport | None = None

    async def run(self) -> None:
        queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=2000)
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(queue),
                local_addr=("0.0.0.0", self.port),
            )
        except OSError as exc:
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat(f"syslog UDP/{self.port} unavailable: {exc}")
            while not self.stopping:
                await asyncio.sleep(5)
            return

        self._transport = transport
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                try:
                    raw, addr = await asyncio.wait_for(queue.get(), timeout=2.0)
                except TimeoutError:
                    self.health.heartbeat(f"listening UDP/{self.port}")
                    continue
                session_id = self.session_provider()
                payload = parse_syslog(raw, addr[0])
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.OBSERVATION,
                        session_id=session_id,
                        evidence_class="SYSLOG_MESSAGE",
                        payload=payload,
                    )
                )
                self.health.heartbeat(f"syslog from {addr[0]}")
        finally:
            transport.close()
            self._transport = None
