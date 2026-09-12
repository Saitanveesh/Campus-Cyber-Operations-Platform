from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class IocEntry:
    indicator_id: str
    kind: str
    value: str
    severity: str
    label: str = ""
    notes: str = ""
    enabled: bool = True
    created_at: str = field(default_factory=_now)


class IocStore:
    """Small local watchlist for operator-supplied defensive indicators."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (_root() / "ioc_watchlist.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, IocEntry] = {}
        self._load()

    @staticmethod
    def normalize(kind: str, value: str) -> tuple[str, str]:
        normalized_kind = kind.upper().strip()
        raw = value.strip()
        if normalized_kind == "IP":
            return normalized_kind, str(ipaddress.ip_address(raw))
        if normalized_kind == "DOMAIN":
            domain = raw.lower().rstrip(".")
            if not domain or " " in domain or "." not in domain:
                raise ValueError("invalid domain indicator")
            return normalized_kind, domain
        if normalized_kind == "SHA256":
            if not HASH_RE.fullmatch(raw):
                raise ValueError("SHA256 indicator must be 64 hexadecimal characters")
            return normalized_kind, raw.lower()
        raise ValueError("indicator kind must be IP, DOMAIN or SHA256")

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                entry = IocEntry(**item)
                self._items[entry.indicator_id] = entry
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            self._items = {}

    def _save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(
            json.dumps([asdict(item) for item in self._items.values()], indent=2),
            encoding="utf-8",
        )
        temp.replace(self.path)

    def add(
        self,
        *,
        kind: str,
        value: str,
        severity: str = "HIGH",
        label: str = "",
        notes: str = "",
    ) -> dict[str, object]:
        normalized_kind, normalized_value = self.normalize(kind, value)
        normalized_severity = severity.upper().strip()
        if normalized_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("invalid IOC severity")
        for entry in self._items.values():
            if entry.kind == normalized_kind and entry.value == normalized_value:
                raise ValueError("indicator already exists")
        entry = IocEntry(
            indicator_id=str(uuid4()),
            kind=normalized_kind,
            value=normalized_value,
            severity=normalized_severity,
            label=label.strip()[:160],
            notes=notes.strip()[:1000],
        )
        self._items[entry.indicator_id] = entry
        self._save()
        return asdict(entry)

    def remove(self, indicator_id: str) -> bool:
        if self._items.pop(indicator_id, None) is None:
            return False
        self._save()
        return True

    def list(self) -> list[dict[str, object]]:
        return [
            asdict(item)
            for item in sorted(
                self._items.values(),
                key=lambda item: (item.kind, item.value),
            )
        ]

    def enabled(self) -> list[dict[str, object]]:
        return [item for item in self.list() if item.get("enabled")]
