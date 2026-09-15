from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from campus_ops.event_bus import EventBus
from campus_ops.fabric.records import fresh, timestamp
from campus_ops.fabric.tail import JsonTail
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker

SEVERITY_MAP = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM}


def default_eve_paths() -> list[Path]:
    candidates = []
    configured = os.environ.get("CAMPUS_OPS_SURICATA_EVE", "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path("/var/log/suricata/eve.json"))
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        if root := os.environ.get(env_name):
            candidates.append(Path(root) / "Suricata" / "log" / "eve.json")
    return candidates


class SuricataFeedWorker(BaseWorker):
    """Tail bounded EVE JSON alerts without startup history or cross-session replay."""

    def __init__(self, bus: EventBus, session_provider, paths: list[Path] | None = None) -> None:
        super().__init__("suricata-feed", bus)
        self.session_provider = session_provider
        self.paths = paths or default_eve_paths()
        self._tails: dict[Path, JsonTail] = {}
        self.records = 0
        self.last_received: float | None = None
        self.errors = 0

    def _find_path(self) -> Path | None:
        return next((path for path in self.paths if path.is_file()), None)

    @staticmethod
    def _event_for(record: dict, session_id: str) -> Event | None:
        alert = record.get("alert")
        observed = timestamp(record.get("timestamp"))
        if (record.get("event_type") != "alert" or not isinstance(alert, dict)
                or observed is None or not record.get("src_ip")):
            return None
        try:
            severity = SEVERITY_MAP.get(int(alert.get("severity") or 3), Severity.MEDIUM)
        except (ValueError, TypeError):
            return None
        return Event(
            source="suricata-feed", kind=EventKind.ALERT, session_id=session_id,
            severity=severity, evidence_class="SURICATA_SIGNATURE",
            payload={
                "type": "SECURITY_INDICATOR",
                "title": str(alert.get("signature") or "Suricata IDS alert")[:512],
                "observed_at": observed, "rule": str(alert.get("signature_id") or ""),
                "confidence": 90,
                "evidence": {
                    "signature_id": alert.get("signature_id"), "category": alert.get("category"),
                    "source": record.get("src_ip"), "source_port": record.get("src_port"),
                    "destination": record.get("dest_ip"), "destination_port": record.get("dest_port"),
                    "protocol": record.get("proto"), "flow_id": record.get("flow_id"),
                },
            },
        )

    async def run(self) -> None:
        while not self.stopping:
            path = self._find_path()
            if path is None:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("Suricata EVE feed unavailable")
                await asyncio.sleep(5)
                continue
            tail = self._tails.setdefault(path, JsonTail(path))
            before = tail.errors
            try:
                session = self.session_provider()
                for record in tail.read(session):
                    event = self._event_for(record, session) if session else None
                    if event is not None and fresh(event.payload["observed_at"]):
                        await self.bus.publish(event)
                        self.records += 1
                        self.last_received = time.time()
            except OSError as exc:
                self.errors += 1
                self.health.last_error = str(exc)
            self.errors += tail.errors - before
            self.health.state = WorkerState.DEGRADED if self.errors else WorkerState.HEALTHY
            self.health.heartbeat(f"EVE feed; {self.records} records, {self.errors} errors")
            await asyncio.sleep(1)
