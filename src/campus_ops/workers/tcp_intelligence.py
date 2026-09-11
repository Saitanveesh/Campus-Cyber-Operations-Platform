from __future__ import annotations

import time
from collections import deque

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


def _flag_value(raw: object) -> int:
    text = str(raw or "").strip().lower()
    if not text:
        return 0
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


class TcpIntelligenceWorker(BaseWorker):
    """Current-session TCP health counters derived from observed packet metadata."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("tcp-intelligence", bus)
        self.state = state
        self.session_provider = session_provider
        self._session: str | None = None
        self._packets = 0
        self._syn = 0
        self._syn_ack = 0
        self._fin = 0
        self._rst = 0
        self._retransmissions = 0
        self._duplicate_acks = 0
        self._rtt_ms: deque[float] = deque(maxlen=1000)
        self._last_publish = 0.0

    def _reset(self, session_id: str) -> None:
        self._session = session_id
        self._packets = 0
        self._syn = 0
        self._syn_ack = 0
        self._fin = 0
        self._rst = 0
        self._retransmissions = 0
        self._duplicate_acks = 0
        self._rtt_ms.clear()
        self._last_publish = 0.0

    def _publish_metrics(self) -> None:
        average_rtt = sum(self._rtt_ms) / len(self._rtt_ms) if self._rtt_ms else None
        self.state.update_metrics(
            tcp_packets=self._packets,
            tcp_syn=self._syn,
            tcp_syn_ack=self._syn_ack,
            tcp_fin=self._fin,
            tcp_rst=self._rst,
            tcp_retransmissions=self._retransmissions,
            tcp_duplicate_acks=self._duplicate_acks,
            tcp_avg_rtt_ms=round(average_rtt, 3) if average_rtt is not None else None,
        )

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if self._session != session_id:
                    self._reset(session_id)
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                payload = event.payload
                if str(payload.get("transport") or "").upper() != "TCP":
                    continue

                self._packets += 1
                flags = _flag_value(payload.get("tcp_flags"))
                if flags & 0x02:
                    self._syn += 1
                    if flags & 0x10:
                        self._syn_ack += 1
                if flags & 0x01:
                    self._fin += 1
                if flags & 0x04:
                    self._rst += 1
                if payload.get("tcp_retransmission") or payload.get("tcp_fast_retransmission"):
                    self._retransmissions += 1
                if payload.get("tcp_duplicate_ack"):
                    self._duplicate_acks += 1
                raw_rtt = payload.get("tcp_ack_rtt")
                if raw_rtt not in {None, ""}:
                    try:
                        self._rtt_ms.append(float(str(raw_rtt).split(",", 1)[0]) * 1000.0)
                    except ValueError:
                        pass

                now = time.monotonic()
                if now - self._last_publish >= 0.5:
                    self._publish_metrics()
                    self._last_publish = now
                self.health.heartbeat(
                    f"tcp={self._packets} retrans={self._retransmissions} rst={self._rst}"
                )
        finally:
            await self.bus.unsubscribe(self.name)
