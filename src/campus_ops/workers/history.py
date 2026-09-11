from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.workers.base import BaseWorker


def default_history_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root / "history.db"


class HistoryWorker(BaseWorker):
    """Append-only historical event storage; never feeds current live state."""

    def __init__(self, bus: EventBus, path: Path | None = None) -> None:
        super().__init__("history-storage", bus)
        self.path = path or default_history_path()
        self._conn: sqlite3.Connection | None = None

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence_class TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session_time ON events(session_id, timestamp)")
        conn.commit()
        return conn

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self._conn = self._open()
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                self._conn.execute(
                    "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.session_id,
                        event.source,
                        event.kind.value,
                        event.severity.value,
                        event.evidence_class,
                        json.dumps(dict(event.payload), sort_keys=True, default=str),
                    ),
                )
                self._conn.commit()
                self.health.heartbeat(f"history={self.path.name}")
        finally:
            await self.bus.unsubscribe(self.name)
            if self._conn:
                self._conn.close()
                self._conn = None

    def query_recent(self, limit: int = 100) -> list[dict[str, object]]:
        limit = max(1, min(limit, 1000))
        conn = sqlite3.connect(self.path)
        try:
            rows = conn.execute(
                "SELECT event_id,timestamp,session_id,source,kind,severity,evidence_class,payload_json "
                "FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()
        return [
            {
                "event_id": row[0],
                "timestamp": row[1],
                "session_id": row[2],
                "source": row[3],
                "kind": row[4],
                "severity": row[5],
                "evidence_class": row[6],
                "payload": json.loads(row[7]),
            }
            for row in rows
        ]
