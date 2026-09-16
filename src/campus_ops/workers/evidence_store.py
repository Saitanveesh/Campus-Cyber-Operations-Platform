from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.platform_paths import data_root
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class EvidenceStoreWorker(BaseWorker):
    """Persist bounded metadata evidence without retaining packet payloads.

    Enterprise monitoring needs history for investigations, but a school/college SaaS
    sensor should minimize sensitive data. MON therefore stores security/control events
    plus periodic aggregate asset/flow snapshots. Raw packet payloads and PCAP are not
    retained by this worker.
    """

    SNAPSHOT_SECONDS = 30.0
    RETENTION_DAYS = 7
    MAX_ROWS = 250_000

    def __init__(self, bus: EventBus, state: LiveState, session_provider) -> None:
        super().__init__("evidence-store", bus)
        self.state = state
        self.session_provider = session_provider
        self.path: Path = data_root() / "evidence.db"
        self._conn: sqlite3.Connection | None = None
        self._last_snapshot = 0.0
        self._last_prune = 0.0

    @staticmethod
    def _wanted(event: Event) -> bool:
        return event.kind in {
            EventKind.NETWORK,
            EventKind.ALERT,
            EventKind.INCIDENT,
            EventKind.ACTION,
            EventKind.HEALTH,
        }

    def _open(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                session_id TEXT,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence_class TEXT,
                target_ip TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_target ON events(target_ip);

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                session_id TEXT,
                record_type TEXT NOT NULL,
                target_ip TEXT,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);
            CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots(target_ip);
            """
        )
        connection.commit()
        return connection

    @staticmethod
    def _target_ip(payload: object) -> str | None:
        if not isinstance(payload, dict):
            return None
        evidence = payload.get("evidence")
        if isinstance(evidence, dict):
            for key in ("source", "src", "target", "ip"):
                value = str(evidence.get(key) or "").strip()
                if value:
                    return value
        for key in ("source", "src", "target", "ip"):
            value = str(payload.get(key) or "").strip()
            if value:
                return value
        return None

    def _write_event(self, event: Event) -> None:
        assert self._conn is not None
        payload = dict(event.payload)
        self._conn.execute(
            """
            INSERT INTO events(ts,session_id,kind,source,severity,evidence_class,target_ip,payload_json)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                event.timestamp.isoformat(),
                event.session_id,
                event.kind.value,
                event.source,
                event.severity.value,
                event.evidence_class,
                self._target_ip(payload),
                json.dumps(payload, separators=(",", ":"), default=str),
            ),
        )
        self._conn.commit()

    def _write_snapshot(self) -> None:
        assert self._conn is not None
        session_id = self.session_provider()
        if not session_id:
            return
        snapshot = self.state.snapshot()
        now = datetime.now(UTC).isoformat()
        rows: list[tuple[str, str, str, str | None, str]] = []
        for asset in snapshot.get("assets", [])[:5000]:
            if not isinstance(asset, dict):
                continue
            ip = str(asset.get("ip") or "").strip() or None
            rows.append((now, session_id, "asset", ip, json.dumps(asset, separators=(",", ":"), default=str)))
        flows = [item for item in snapshot.get("flows", []) if isinstance(item, dict)]
        flows.sort(key=lambda item: int(item.get("packets") or 0), reverse=True)
        for flow in flows[:5000]:
            src = str(flow.get("src") or "").strip()
            dst = str(flow.get("dst") or "").strip()
            target = src or dst or None
            rows.append((now, session_id, "flow", target, json.dumps(flow, separators=(",", ":"), default=str)))
        if rows:
            self._conn.executemany(
                "INSERT INTO snapshots(ts,session_id,record_type,target_ip,record_json) VALUES(?,?,?,?,?)",
                rows,
            )
            self._conn.commit()

    def _prune(self) -> None:
        assert self._conn is not None
        cutoff = (datetime.now(UTC) - timedelta(days=self.RETENTION_DAYS)).isoformat()
        self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        self._conn.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
        for table in ("events", "snapshots"):
            count = int(self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            excess = max(0, count - self.MAX_ROWS)
            if excess:
                self._conn.execute(
                    f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY id ASC LIMIT ?)",
                    (excess,),
                )
        self._conn.commit()

    async def run(self) -> None:
        try:
            self._conn = await asyncio.to_thread(self._open)
        except (OSError, sqlite3.Error) as exc:
            self.health.state = WorkerState.DEGRADED
            self.health.last_error = str(exc)
            self.health.heartbeat(f"evidence database unavailable: {exc}")
            while not self.stopping:
                await asyncio.sleep(5)
            return

        sub = await self.bus.subscribe(self.name, predicate=self._wanted)
        self.health.state = WorkerState.HEALTHY
        self.health.heartbeat(f"metadata history: {self.path}")
        self._last_snapshot = time.monotonic()
        self._last_prune = time.monotonic()
        try:
            while not self.stopping:
                try:
                    event = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
                except TimeoutError:
                    event = None
                if event is not None:
                    try:
                        await asyncio.to_thread(self._write_event, event)
                    except sqlite3.Error as exc:
                        self.health.state = WorkerState.DEGRADED
                        self.health.last_error = str(exc)
                        self.health.heartbeat(f"evidence write failed: {exc}")

                now = time.monotonic()
                if now - self._last_snapshot >= self.SNAPSHOT_SECONDS:
                    self._last_snapshot = now
                    try:
                        await asyncio.to_thread(self._write_snapshot)
                    except sqlite3.Error as exc:
                        self.health.state = WorkerState.DEGRADED
                        self.health.last_error = str(exc)
                if now - self._last_prune >= 3600:
                    self._last_prune = now
                    try:
                        await asyncio.to_thread(self._prune)
                    except sqlite3.Error as exc:
                        self.health.state = WorkerState.DEGRADED
                        self.health.last_error = str(exc)
                if self.health.state != WorkerState.DEGRADED:
                    self.health.state = WorkerState.HEALTHY
        finally:
            await self.bus.unsubscribe(self.name)
            if self._conn is not None:
                connection = self._conn
                self._conn = None
                await asyncio.to_thread(connection.close)

    @classmethod
    def query_ip(cls, target: str, limit: int = 250) -> dict[str, Any]:
        path = data_root() / "evidence.db"
        if not path.exists():
            return {"target": target, "events": [], "snapshots": [], "database": str(path)}
        connection = sqlite3.connect(path, timeout=5.0)
        try:
            events = []
            for row in connection.execute(
                """
                SELECT ts,session_id,kind,source,severity,evidence_class,payload_json
                FROM events
                WHERE target_ip = ? OR payload_json LIKE ?
                ORDER BY id DESC LIMIT ?
                """,
                (target, f'%"{target}"%', max(1, min(limit, 1000))),
            ):
                events.append(
                    {
                        "timestamp": row[0],
                        "session_id": row[1],
                        "kind": row[2],
                        "source": row[3],
                        "severity": row[4],
                        "evidence_class": row[5],
                        "payload": json.loads(row[6]),
                    }
                )
            snapshots = []
            for row in connection.execute(
                """
                SELECT ts,session_id,record_type,record_json
                FROM snapshots
                WHERE target_ip = ? OR record_json LIKE ?
                ORDER BY id DESC LIMIT ?
                """,
                (target, f'%"{target}"%', max(1, min(limit, 1000))),
            ):
                snapshots.append(
                    {
                        "timestamp": row[0],
                        "session_id": row[1],
                        "record_type": row[2],
                        "record": json.loads(row[3]),
                    }
                )
            return {
                "target": target,
                "events": events,
                "snapshots": snapshots,
                "retention_days": cls.RETENTION_DAYS,
                "database": str(path),
                "claim": "METADATA_ONLY_NO_PACKET_PAYLOAD_RETENTION",
            }
        finally:
            connection.close()
