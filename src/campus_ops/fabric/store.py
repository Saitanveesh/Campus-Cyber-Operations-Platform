"""Local bounded evidence and decision journal; never replays history as live evidence."""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from .records import EvidenceRecord, fresh


class EvidenceStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=5)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS evidence(
                id TEXT PRIMARY KEY, session TEXT NOT NULL, observed REAL NOT NULL,
                received REAL NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS evidence_session ON evidence(session, observed);
            CREATE TABLE IF NOT EXISTS journal(
                id INTEGER PRIMARY KEY, created REAL NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS investigations(
                key TEXT PRIMARY KEY, created REAL NOT NULL, body TEXT NOT NULL);
        """)
        self.accepted = 0

    def close(self) -> None:
        self.conn.close()

    def add(self, record: EvidenceRecord, now: float | None = None) -> bool:
        if not fresh(record.observed_at, now):
            return False
        with self.conn:
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?)",
                (record.record_id, record.session_id, record.observed_at,
                 record.received_at, json.dumps(asdict(record), default=str)),
            )
            added = cursor.rowcount == 1
            if added:
                self.accepted += 1
                if self.accepted % 100 == 0:
                    self.conn.execute(
                        "DELETE FROM evidence WHERE id IN "
                        "(SELECT id FROM evidence ORDER BY received DESC LIMIT -1 OFFSET 50000)"
                    )
        return added

    def recent(self, session: str | None, now: float | None = None,
               window: int = 300, limit: int = 5000) -> list[dict]:
        if not session:
            return []
        now = time.time() if now is None else now
        rows = self.conn.execute(
            "SELECT body FROM evidence WHERE session=? AND observed BETWEEN ? AND ? "
            "ORDER BY observed DESC LIMIT ?",
            (session, now - window, now + 30, max(1, min(limit, 5000))),
        )
        return [json.loads(row[0]) for row in rows]

    def graph(self, session: str | None) -> dict:
        records = self.recent(session, limit=500)
        nodes, edges = {}, []
        for row in records:
            evidence = "evidence:" + row["record_id"]
            subject = "subject:" + row["subject"]
            origin = "origin:" + row["origin"]
            nodes[evidence] = {"id": evidence, "type": "evidence", **row}
            nodes[subject] = {"id": subject, "type": "subject", "label": row["subject"]}
            nodes[origin] = {"id": origin, "type": "origin", "label": row["origin"]}
            edges.extend([{"source": origin, "target": evidence, "type": "PRODUCED"},
                          {"source": evidence, "target": subject, "type": "OBSERVED"}])
        return {"session_id": session, "nodes": list(nodes.values()), "edges": edges,
                "storage": "SQLITE", "limit": 500, "neo4j_integrated": False}

    def journal(self, kind: str, body: dict) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO journal(created,kind,body) VALUES(?,?,?)",
                              (time.time(), kind, json.dumps(body, default=str)))
            self.conn.execute(
                "DELETE FROM journal WHERE id IN "
                "(SELECT id FROM journal ORDER BY id DESC LIMIT -1 OFFSET 2000)"
            )

    def reserve_investigation(self, key: str, body: dict) -> bool:
        # Reserve before queueing: a crash may miss a snapshot, but cannot replay it.
        with self.conn:
            cursor = self.conn.execute("INSERT OR IGNORE INTO investigations VALUES(?,?,?)",
                                       (key, time.time(), json.dumps(body)))
            self.conn.execute(
                "DELETE FROM investigations WHERE key IN "
                "(SELECT key FROM investigations ORDER BY created DESC LIMIT -1 OFFSET 2000)"
            )
        return cursor.rowcount == 1
