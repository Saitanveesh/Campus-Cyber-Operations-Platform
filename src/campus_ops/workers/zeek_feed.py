from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


def default_zeek_log_dirs() -> list[Path]:
    candidates: list[Path] = []
    configured = os.environ.get("CAMPUS_OPS_ZEEK_LOG_DIR", "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            Path(r"C:\ProgramData\Zeek\logs\current"),
            Path(r"C:\Program Files\Zeek\logs\current"),
            Path.home() / "zeek" / "logs" / "current",
        ]
    )
    return candidates


def _first_value(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in {None, ""}:
            return value
    return None


class ZeekFeedWorker(BaseWorker):
    """Tail Zeek JSON logs without importing historical data into the live session."""

    LOGS = ("conn.log", "dns.log", "ssl.log", "http.log", "notice.log")

    def __init__(self, bus: EventBus, session_provider, log_dirs: list[Path] | None = None) -> None:
        super().__init__("zeek-feed", bus)
        self.session_provider = session_provider
        self.log_dirs = log_dirs or default_zeek_log_dirs()
        self._offsets: dict[Path, int] = {}

    def _active_dir(self) -> Path | None:
        return next((path for path in self.log_dirs if path.exists() and path.is_dir()), None)

    @staticmethod
    def _event_for(path: Path, record: dict[str, Any], session_id: str) -> Event | None:
        name = path.name.lower()
        common = {
            "src_ip": _first_value(record, "id.orig_h", "src_ip"),
            "src_port": _first_value(record, "id.orig_p", "src_port"),
            "dst_ip": _first_value(record, "id.resp_h", "dst_ip"),
            "dst_port": _first_value(record, "id.resp_p", "dst_port"),
            "uid": record.get("uid"),
        }
        if name == "conn.log":
            payload = {
                "type": "ZEEK_CONNECTION",
                **common,
                "transport": record.get("proto"),
                "service": record.get("service"),
                "duration": record.get("duration"),
                "orig_bytes": record.get("orig_bytes"),
                "resp_bytes": record.get("resp_bytes"),
                "conn_state": record.get("conn_state"),
            }
            return Event(
                source="zeek-feed",
                kind=EventKind.OBSERVATION,
                session_id=session_id,
                evidence_class="ZEEK_CONN",
                payload=payload,
            )
        if name == "dns.log":
            return Event(
                source="zeek-feed",
                kind=EventKind.OBSERVATION,
                session_id=session_id,
                evidence_class="ZEEK_DNS",
                payload={
                    "type": "ZEEK_DNS",
                    **common,
                    "query": record.get("query"),
                    "qtype_name": record.get("qtype_name"),
                    "rcode_name": record.get("rcode_name"),
                    "answers": record.get("answers"),
                },
            )
        if name == "ssl.log":
            return Event(
                source="zeek-feed",
                kind=EventKind.OBSERVATION,
                session_id=session_id,
                evidence_class="ZEEK_TLS",
                payload={
                    "type": "ZEEK_TLS",
                    **common,
                    "server_name": record.get("server_name"),
                    "version": record.get("version"),
                    "cipher": record.get("cipher"),
                    "established": record.get("established"),
                    "subject": record.get("subject"),
                    "issuer": record.get("issuer"),
                },
            )
        if name == "http.log":
            return Event(
                source="zeek-feed",
                kind=EventKind.OBSERVATION,
                session_id=session_id,
                evidence_class="ZEEK_HTTP",
                payload={
                    "type": "ZEEK_HTTP",
                    **common,
                    "method": record.get("method"),
                    "host": record.get("host"),
                    "uri": record.get("uri"),
                    "status_code": record.get("status_code"),
                    "user_agent": record.get("user_agent"),
                },
            )
        if name == "notice.log":
            message = str(record.get("msg") or record.get("note") or "Zeek notice")
            return Event(
                source="zeek-feed",
                kind=EventKind.ALERT,
                session_id=session_id,
                severity=Severity.MEDIUM,
                evidence_class="ZEEK_NOTICE",
                payload={
                    "type": "SECURITY_INDICATOR",
                    "title": message,
                    "confidence": 70,
                    "evidence": {
                        **common,
                        "note": record.get("note"),
                        "message": record.get("msg"),
                        "sub": record.get("sub"),
                    },
                },
            )
        return None

    async def _consume_file(self, path: Path, session_id: str) -> int:
        if path not in self._offsets:
            self._offsets[path] = path.stat().st_size
            return 0
        size = path.stat().st_size
        offset = self._offsets[path]
        if size < offset:
            offset = 0
        emitted = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for line in handle:
                self._offsets[path] = handle.tell()
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                event = self._event_for(path, record, session_id)
                if event is not None:
                    await self.bus.publish(event)
                    emitted += 1
            self._offsets[path] = handle.tell()
        return emitted

    async def run(self) -> None:
        while not self.stopping:
            active = self._active_dir()
            if active is None:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("Zeek JSON log directory unavailable")
                await asyncio.sleep(5)
                continue
            session_id = self.session_provider()
            if not session_id:
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat("Zeek available; waiting for live session")
                await asyncio.sleep(2)
                continue
            emitted = 0
            files = [active / name for name in self.LOGS if (active / name).is_file()]
            if not files:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("Zeek directory found; JSON logs unavailable")
                await asyncio.sleep(3)
                continue
            for path in files:
                try:
                    emitted += await self._consume_file(path, session_id)
                except OSError as exc:
                    self.health.last_error = str(exc)
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat(f"Zeek JSON feed active; {emitted} new record(s)")
            await asyncio.sleep(1)
