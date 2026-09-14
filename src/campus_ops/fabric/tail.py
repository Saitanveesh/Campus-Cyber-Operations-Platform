"""Bounded JSONL reader with session isolation, partial-line and rotation handling."""
from __future__ import annotations

import json
from pathlib import Path


class JsonTail:
    def __init__(self, path: Path, max_line: int = 65536) -> None:
        self.path = Path(path)
        self.max_line = max_line
        self.offset = 0
        self.identity = None
        self.session = None
        self.discard = False
        self.errors = 0

    def read(self, session: str | None, limit: int = 100) -> list[dict]:
        # fstat the opened file so a concurrent rename cannot mix inode and offset.
        with self.path.open("rb") as handle:
            import os
            stat = os.fstat(handle.fileno())
            identity = (stat.st_dev, stat.st_ino)
            if self.identity is None or self.session != session or not session:
                self.identity, self.session, self.offset = identity, session, stat.st_size
                self.discard = False
                if self.offset:
                    handle.seek(self.offset - 1)
                    self.discard = handle.read(1) != b"\n"
                return []
            if identity != self.identity or stat.st_size < self.offset:
                self.identity, self.offset, self.discard = identity, 0, False
            handle.seek(self.offset)
            rows = []
            for _ in range(max(1, min(limit, 1000))):
                start = handle.tell()
                line = handle.readline(self.max_line + 1)
                if not line:
                    break
                complete = line.endswith(b"\n")
                if self.discard:
                    self.offset = handle.tell()
                    self.discard = not complete
                    continue
                if len(line) > self.max_line:
                    self.errors += 1
                    self.discard = not complete
                    self.offset = handle.tell()
                    continue
                if not complete:
                    self.offset = start
                    break
                self.offset = handle.tell()
                if not line.strip() or line.startswith(b"#"):
                    continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise TypeError("JSON object required")
                    rows.append(row)
                except (ValueError, UnicodeError, TypeError):
                    self.errors += 1
            return rows
