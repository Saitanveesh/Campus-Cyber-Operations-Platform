from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


SEVERITY_MAP = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM}


def default_eve_paths() -> list[Path]:
    candidates: list[Path] = []
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(Path(program_files) / "Suricata" / "log" / "eve.json")
    candidates.extend([Path("C:/Program Files/Suricata/log/eve.json"), Path("C:/ProgramData/Suricata/log/eve.json")])
    return candidates


class SuricataFeedWorker(BaseWorker):
    """Consumes Suricata EVE alerts when a local Suricata deployment is available."""

    def __init__(self, bus: EventBus, session_provider, paths: list[Path] | None = None) -> None:
        super().__init__("suricata-feed", bus)
        self.session_provider = session_provider
        self.paths = paths or default_eve_paths()
        self._offsets: dict[Path, int] = {}

    def _find_path(self) -> Path | None:
        return next((path for path in self.paths if path.exists() and path.is_file()), None)

    async def run(self) -> None:
        while not self.stopping:
            path = self._find_path()
            if path is None:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("Suricata EVE feed unavailable")
                await asyncio.sleep(5)
                continue
            self.health.state = WorkerState.HEALTHY
            offset = self._offsets.get(path, path.stat().st_size)
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(min(offset, path.stat().st_size))
                while not self.stopping:
                    line = handle.readline()
                    if not line:
                        self._offsets[path] = handle.tell()
                        self.health.heartbeat(f"watching {path.name}")
                        await asyncio.sleep(1)
                        if path.stat().st_size < handle.tell():
                            break
                        continue
                    self._offsets[path] = handle.tell()
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("event_type") != "alert" or not isinstance(record.get("alert"), dict):
                        continue
                    session_id = self.session_provider()
                    if not session_id:
                        continue
                    alert = record["alert"]
                    suri_severity = int(alert.get("severity") or 3)
                    severity = SEVERITY_MAP.get(suri_severity, Severity.MEDIUM)
                    await self.bus.publish(
                        Event(
                            source=self.name,
                            kind=EventKind.ALERT,
                            session_id=session_id,
                            severity=severity,
                            evidence_class="SURICATA_SIGNATURE",
                            payload={
                                "type": "SECURITY_INDICATOR",
                                "title": str(alert.get("signature") or "Suricata IDS alert"),
                                "confidence": 90,
                                "evidence": {
                                    "signature_id": alert.get("signature_id"),
                                    "category": alert.get("category"),
                                    "source": record.get("src_ip"),
                                    "source_port": record.get("src_port"),
                                    "destination": record.get("dest_ip"),
                                    "destination_port": record.get("dest_port"),
                                    "protocol": record.get("proto"),
                                    "flow_id": record.get("flow_id"),
                                },
                            },
                        )
                    )
