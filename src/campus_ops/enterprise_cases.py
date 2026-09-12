from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.admin_deep import _require_admin
from campus_ops.models import Event, EventKind, Severity


def _root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class CaseRecord:
    case_id: str
    title: str
    target: str
    severity: str
    status: str = "OPEN"
    owner: str = "admin"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    session_id: str | None = None
    notes: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    target: str = Field(min_length=1, max_length=160)
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")


class CaseUpdateRequest(BaseModel):
    status: str | None = Field(default=None, pattern="^(OPEN|INVESTIGATING|CONTAINED|CLOSED)$")
    note: str | None = Field(default=None, min_length=1, max_length=2000)


class CaseStore:
    """Durable case ledger with a tamper-evident append-only audit chain."""

    def __init__(self) -> None:
        self.path = _root() / "cases.json"
        self.audit_path = _root() / "case_audit.jsonl"
        self._cases: dict[str, CaseRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                case = CaseRecord(**item)
                self._cases[case.case_id] = case
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            self._cases = {}

    def _save(self) -> None:
        temp = self.path.with_suffix(".json.tmp")
        rows = [asdict(item) for item in sorted(self._cases.values(), key=lambda x: x.updated_at, reverse=True)]
        temp.write_text(json.dumps(rows, indent=2, sort_keys=True, default=str), encoding="utf-8")
        temp.replace(self.path)

    def _last_audit_hash(self) -> str:
        if not self.audit_path.exists():
            return "0" * 64
        try:
            lines = self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if not lines:
                return "0" * 64
            row = json.loads(lines[-1])
            value = str(row.get("hash") or "")
            return value if len(value) == 64 else "0" * 64
        except (OSError, json.JSONDecodeError):
            return "0" * 64

    def audit(self, action: str, case_id: str, operator: str, details: dict[str, Any]) -> dict[str, Any]:
        previous = self._last_audit_hash()
        body = {
            "timestamp": _now(),
            "action": action,
            "case_id": case_id,
            "operator": operator,
            "details": details,
            "previous_hash": previous,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        body["hash"] = hashlib.sha256(previous.encode() + canonical).hexdigest()
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True, default=str) + "\n")
        return body

    def create(self, body: CaseCreateRequest, session_id: str | None) -> dict[str, Any]:
        case = CaseRecord(
            case_id=f"CASE-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}",
            title=body.title,
            target=body.target,
            severity=body.severity,
            session_id=session_id,
        )
        self._cases[case.case_id] = case
        self._save()
        self.audit("CASE_CREATED", case.case_id, "admin", {"target": case.target, "severity": case.severity})
        return asdict(case)

    def update(self, case_id: str, body: CaseUpdateRequest) -> dict[str, Any]:
        case = self._cases.get(case_id)
        if case is None:
            raise KeyError(case_id)
        if body.status:
            case.status = body.status
        if body.note:
            case.notes.append({"timestamp": _now(), "operator": "admin", "text": body.note})
        case.updated_at = _now()
        self._save()
        self.audit(
            "CASE_UPDATED",
            case_id,
            "admin",
            {"status": body.status, "note_added": bool(body.note)},
        )
        return asdict(case)

    def attach_evidence(self, case_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        case = self._cases.get(case_id)
        if case is None:
            raise KeyError(case_id)
        item = {"attached_at": _now(), **evidence}
        case.evidence.append(item)
        case.updated_at = _now()
        self._save()
        self.audit("EVIDENCE_ATTACHED", case_id, "admin", item)
        return asdict(case)

    def list(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in sorted(self._cases.values(), key=lambda x: x.updated_at, reverse=True)]

    def get(self, case_id: str) -> dict[str, Any] | None:
        case = self._cases.get(case_id)
        return asdict(case) if case else None

    def verify_audit_chain(self) -> dict[str, Any]:
        if not self.audit_path.exists():
            return {"state": "EMPTY", "entries": 0, "valid": True}
        previous = "0" * 64
        entries = 0
        try:
            for line in self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                claimed = str(row.pop("hash", ""))
                if str(row.get("previous_hash") or "") != previous:
                    return {"state": "BROKEN", "entries": entries, "valid": False}
                canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str).encode()
                expected = hashlib.sha256(previous.encode() + canonical).hexdigest()
                if claimed != expected:
                    return {"state": "BROKEN", "entries": entries, "valid": False}
                previous = claimed
                entries += 1
        except (OSError, json.JSONDecodeError):
            return {"state": "BROKEN", "entries": entries, "valid": False}
        return {"state": "VALID", "entries": entries, "valid": True, "head_hash": previous}


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: PassiveSyslogReceiver) -> None:
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self.receiver.ingest(data, addr))


class PassiveSyslogReceiver:
    """Opt-in UDP syslog receiver. Disabled unless CAMPUS_OPS_SYSLOG_PORT is configured."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.host = os.environ.get("CAMPUS_OPS_SYSLOG_BIND", "127.0.0.1")
        raw_port = os.environ.get("CAMPUS_OPS_SYSLOG_PORT", "").strip()
        self.port = int(raw_port) if raw_port.isdigit() else None
        self.transport: asyncio.DatagramTransport | None = None
        self.received = 0
        self.errors = 0
        self.last_source: str | None = None

    async def start(self) -> None:
        if self.port is None or self.transport is not None:
            return
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self),
                local_addr=(self.host, self.port),
            )
            self.transport = transport
        except OSError:
            self.errors += 1

    async def stop(self) -> None:
        if self.transport:
            self.transport.close()
            self.transport = None

    async def ingest(self, data: bytes, addr: tuple[str, int]) -> None:
        text = data.decode("utf-8", errors="replace").strip()[:8192]
        if not text:
            return
        self.received += 1
        self.last_source = addr[0]
        session_id = self.app.state.orchestrator.session_id
        if not session_id:
            return
        upper = text.upper()
        evidence_class = "SYSLOG"
        event_type = "SYSLOG_MESSAGE"
        if "RADIUS" in upper:
            evidence_class = "RADIUS_SYSLOG"
            event_type = "RADIUS_EVENT"
        elif "802.1X" in upper or "DOT1X" in upper:
            evidence_class = "DOT1X_SYSLOG"
            event_type = "DOT1X_EVENT"
        elif "FIREWALL" in upper or "DENY" in upper or "BLOCK" in upper:
            evidence_class = "FIREWALL_SYSLOG"
            event_type = "FIREWALL_EVENT"
        await self.app.state.orchestrator.bus.publish(
            Event(
                source="syslog-receiver",
                kind=EventKind.OBSERVATION,
                severity=Severity.INFO,
                session_id=session_id,
                evidence_class=evidence_class,
                payload={
                    "type": event_type,
                    "source": addr[0],
                    "source_port": addr[1],
                    "message": text,
                },
            )
        )

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.port is not None,
            "state": "LISTENING" if self.transport else ("NOT_CONFIGURED" if self.port is None else "UNAVAILABLE"),
            "bind": self.host,
            "port": self.port,
            "received": self.received,
            "errors": self.errors,
            "last_source": self.last_source,
        }


def install_enterprise_cases(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_cases_installed", False):
        return app
    app.state.enterprise_cases_installed = True
    store = CaseStore()
    syslog = PassiveSyslogReceiver(app)
    app.state.case_store = store
    app.state.passive_syslog = syslog

    app.add_event_handler("startup", syslog.start)
    app.add_event_handler("shutdown", syslog.stop)

    @app.get("/api/v1/system/syslog")
    async def syslog_status() -> dict[str, Any]:
        return syslog.status()

    @app.get("/api/v1/admin/cases")
    async def list_cases(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return {"cases": store.list(), "audit": store.verify_audit_chain()}

    @app.post("/api/v1/admin/cases")
    async def create_case(
        body: CaseCreateRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return store.create(body, app.state.orchestrator.session_id)

    @app.get("/api/v1/admin/cases/{case_id}")
    async def get_case(
        case_id: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        row = store.get(case_id)
        if row is None:
            raise HTTPException(status_code=404, detail="case not found")
        return row

    @app.patch("/api/v1/admin/cases/{case_id}")
    async def update_case(
        case_id: str,
        body: CaseUpdateRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        try:
            return store.update(case_id, body)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc

    @app.post("/api/v1/admin/cases/{case_id}/evidence")
    async def attach_case_evidence(
        case_id: str,
        evidence: dict[str, Any],
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        try:
            return store.attach_evidence(case_id, evidence)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc

    @app.get("/api/v1/admin/case-audit/verify")
    async def verify_case_audit(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return store.verify_audit_chain()

    return app
