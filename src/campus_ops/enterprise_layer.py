from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time
from collections import defaultdict, deque
from contextlib import suppress
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.models import Event, EventKind, Severity
from campus_ops.workers.network_discovery import score_candidate


SEVERITY_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 4,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

TOOL_SPECS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("zeek", ("zeek.exe", "zeek"), "deep network metadata and protocol telemetry"),
    ("tcpdump", ("tcpdump.exe", "tcpdump"), "packet capture and filter diagnostics"),
    ("snmpwalk", ("snmpwalk.exe", "snmpwalk"), "authorized infrastructure inventory"),
    ("snmpget", ("snmpget.exe", "snmpget"), "authorized infrastructure polling"),
    ("arp-scan", ("arp-scan.exe", "arp-scan"), "authorized local asset verification"),
    ("velociraptor", ("velociraptor.exe", "velociraptor"), "managed endpoint DFIR collection"),
    ("sigma", ("sigma.exe", "sigma", "sigma-cli"), "portable detection-rule translation"),
)


def _host_from_payload(payload: dict[str, Any]) -> str | None:
    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    candidates = (
        payload.get("src_ip"),
        payload.get("source"),
        payload.get("host"),
        payload.get("target"),
        payload.get("ip"),
        evidence.get("source"),
        evidence.get("host"),
        evidence.get("target"),
    )
    for value in candidates:
        text = str(value or "").strip()
        if text and text not in {"0.0.0.0", "::"}:
            return text
    return None


def _event_summary(event: Event) -> dict[str, Any]:
    payload = dict(event.payload)
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "kind": event.kind.value,
        "severity": event.severity.value,
        "evidence_class": event.evidence_class,
        "type": payload.get("type") or payload.get("change") or payload.get("action"),
        "title": payload.get("title") or payload.get("message") or payload.get("type") or event.kind.value,
        "payload": payload,
    }


class EnterpriseFusionEngine:
    """Fuse current-session network, endpoint and detection evidence into host stories."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.host_events: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=250))
        self.host_risk: dict[str, int] = defaultdict(int)
        self.host_sources: dict[str, set[str]] = defaultdict(set)
        self.global_events: deque[dict[str, Any]] = deque(maxlen=500)
        self._task: asyncio.Task[None] | None = None
        self._subscription = None
        self._session_id: str | None = None
        self.processed = 0
        self.last_event_at: float | None = None

    def _reset_session(self, session_id: str | None) -> None:
        self._session_id = session_id
        self.host_events.clear()
        self.host_risk.clear()
        self.host_sources.clear()
        self.global_events.clear()
        self.processed = 0
        self.last_event_at = None
        self._publish_metrics()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        orch = self.app.state.orchestrator
        self._session_id = orch.session_id
        self._subscription = await orch.bus.subscribe("enterprise-fusion")
        self._task = asyncio.create_task(self.run(), name="enterprise-fusion")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        if self._subscription is not None:
            await self.app.state.orchestrator.bus.unsubscribe(self._subscription.name)
        self._subscription = None

    async def run(self) -> None:
        assert self._subscription is not None
        while True:
            event = await self._subscription.queue.get()
            current_session = self.app.state.orchestrator.session_id
            if current_session != self._session_id:
                self._reset_session(current_session)
            if not current_session:
                continue
            if event.session_id and event.session_id != current_session:
                continue
            if event.kind not in {
                EventKind.OBSERVATION,
                EventKind.ALERT,
                EventKind.INCIDENT,
                EventKind.ACTION,
                EventKind.NETWORK,
            }:
                continue
            row = _event_summary(event)
            self.global_events.appendleft(row)
            host = _host_from_payload(dict(event.payload))
            if host:
                self.host_events[host].appendleft(row)
                self.host_sources[host].add(event.source)
                if event.kind in {EventKind.ALERT, EventKind.INCIDENT}:
                    self.host_risk[host] = min(
                        100,
                        self.host_risk[host] + SEVERITY_WEIGHT.get(event.severity, 1),
                    )
            self.processed += 1
            self.last_event_at = time.time()
            if self.processed % 20 == 0:
                self._publish_metrics()

    def _publish_metrics(self) -> None:
        state = self.app.state.orchestrator.state
        ranked = sorted(self.host_risk.items(), key=lambda item: item[1], reverse=True)[:25]
        state.update_metrics(
            enterprise_fusion={
                "session_id": self._session_id,
                "processed_events": self.processed,
                "tracked_hosts": len(self.host_events),
                "last_event_at": self.last_event_at,
                "top_risk": [{"host": host, "risk": risk} for host, risk in ranked],
            }
        )

    def dossier(self, target: str) -> dict[str, Any]:
        snapshot = self.app.state.orchestrator.snapshot()
        live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
        events = list(self.host_events.get(target, ()))
        by_kind: dict[str, int] = defaultdict(int)
        by_source: dict[str, int] = defaultdict(int)
        for row in events:
            by_kind[str(row.get("kind") or "UNKNOWN")] += 1
            by_source[str(row.get("source") or "UNKNOWN")] += 1
        return {
            "target": target,
            "session_id": snapshot.get("session_id"),
            "risk": self.host_risk.get(target, 0),
            "evidence_sources": sorted(self.host_sources.get(target, set())),
            "counts_by_kind": dict(sorted(by_kind.items())),
            "counts_by_source": dict(sorted(by_source.items(), key=lambda item: item[1], reverse=True)),
            "timeline": events[:150],
            "asset": next(
                (
                    row
                    for row in live.get("assets", [])
                    if isinstance(row, dict)
                    and target in {str(row.get("ip") or ""), str(row.get("address") or "")}
                ),
                None,
            ),
            "truth_state": "EVIDENCE_PRESENT" if events else "NO_CURRENT_SESSION_EVIDENCE",
        }

    def snapshot(self) -> dict[str, Any]:
        ranked = sorted(self.host_risk.items(), key=lambda item: item[1], reverse=True)[:25]
        return {
            "state": "ACTIVE" if self._task and not self._task.done() else "STOPPED",
            "session_id": self._session_id,
            "processed_events": self.processed,
            "tracked_hosts": len(self.host_events),
            "last_event_at": self.last_event_at,
            "top_risk": [{"host": host, "risk": risk} for host, risk in ranked],
        }


class ZeekLogAdapter:
    """Read JSON Zeek logs when an operator or sensor provides a log directory."""

    FILES = ("conn.log", "dns.log", "ssl.log", "http.log", "notice.log", "files.log")

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        raw = os.environ.get("CAMPUS_OPS_ZEEK_LOG_DIR", "").strip()
        self.root = Path(raw) if raw else None
        self.offsets: dict[Path, int] = {}
        self._task: asyncio.Task[None] | None = None
        self.records = 0
        self.errors = 0

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self.run(), name="zeek-adapter")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def run(self) -> None:
        while True:
            if self.root and self.root.exists():
                for name in self.FILES:
                    await self._read_file(self.root / name, name)
            await asyncio.sleep(2.0)

    async def _read_file(self, path: Path, log_name: str) -> None:
        if not path.exists() or not path.is_file():
            return
        try:
            size = path.stat().st_size
            offset = self.offsets.get(path, 0)
            if size < offset:
                offset = 0
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                lines = handle.readlines()
                self.offsets[path] = handle.tell()
        except OSError:
            self.errors += 1
            return
        for line in lines[-500:]:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                self.errors += 1
                continue
            await self._publish(log_name, row)

    async def _publish(self, log_name: str, row: dict[str, Any]) -> None:
        orch = self.app.state.orchestrator
        session_id = orch.session_id
        if not session_id:
            return
        src = row.get("id.orig_h") or row.get("src")
        dst = row.get("id.resp_h") or row.get("dst")
        payload: dict[str, Any] = {
            "type": "ZEEK_OBSERVATION",
            "zeek_log": log_name,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": row.get("id.orig_p"),
            "dst_port": row.get("id.resp_p"),
            "proto": row.get("proto"),
            "service": row.get("service"),
            "dns_query": row.get("query"),
            "tls_sni": row.get("server_name"),
            "http_host": row.get("host"),
            "uid": row.get("uid"),
            "raw": row,
        }
        kind = EventKind.ALERT if log_name == "notice.log" else EventKind.OBSERVATION
        severity = Severity.MEDIUM if kind == EventKind.ALERT else Severity.INFO
        if kind == EventKind.ALERT:
            payload.update(
                {
                    "title": row.get("msg") or row.get("note") or "Zeek notice",
                    "confidence": 80,
                }
            )
        await orch.bus.publish(
            Event(
                source="zeek-adapter",
                kind=kind,
                severity=severity,
                session_id=session_id,
                evidence_class="ZEEK_SENSOR",
                payload=payload,
            )
        )
        self.records += 1

    def snapshot(self) -> dict[str, Any]:
        configured = bool(self.root)
        available = bool(self.root and self.root.exists())
        return {
            "configured": configured,
            "available": available,
            "log_dir": str(self.root) if self.root else None,
            "records": self.records,
            "errors": self.errors,
            "state": "ACTIVE" if available else ("UNAVAILABLE" if configured else "NOT_CONFIGURED"),
        }


class EnterpriseToolBroker:
    """Detect native and WSL/Linux analysis tools without silently executing active scans."""

    def __init__(self) -> None:
        self._cache: list[dict[str, Any]] = []
        self._last_scan = 0.0

    @staticmethod
    def _wsl_path(executables: tuple[str, ...]) -> str | None:
        if os.name != "nt" or shutil.which("wsl.exe") is None:
            return None
        for executable in executables:
            if executable.endswith(".exe"):
                continue
            try:
                proc = subprocess.run(
                    ["wsl.exe", "sh", "-lc", f"command -v {executable} 2>/dev/null || true"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError):
                return None
            value = (proc.stdout or "").strip().splitlines()
            if value:
                return value[0]
        return None

    def scan(self, force: bool = False) -> list[dict[str, Any]]:
        now = time.time()
        if self._cache and not force and now - self._last_scan < 30:
            return self._cache
        rows: list[dict[str, Any]] = []
        for key, executables, purpose in TOOL_SPECS:
            native = next((shutil.which(exe) for exe in executables if shutil.which(exe)), None)
            wsl = None if native else self._wsl_path(executables)
            rows.append(
                {
                    "key": key,
                    "purpose": purpose,
                    "available": bool(native or wsl),
                    "mode": "NATIVE" if native else ("WSL" if wsl else "UNAVAILABLE"),
                    "path": native or wsl,
                    "execution_policy": (
                        "OPERATOR_INITIATED"
                        if key in {"snmpwalk", "snmpget", "arp-scan"}
                        else "ANALYSIS_ONLY"
                    ),
                }
            )
        self._cache = rows
        self._last_scan = now
        return rows


class InterfaceDecision:
    @staticmethod
    def snapshot(app: FastAPI) -> dict[str, Any]:
        orch = app.state.orchestrator
        candidates = []
        for item in orch.network.candidates:
            score, reasons = score_candidate(item)
            candidates.append(
                {
                    "interface": item.name,
                    "score": score,
                    "reasons": list(reasons),
                    "default_route": item.default_route,
                    "gateway": item.gateway,
                    "category": item.category,
                    "ipv4": list(item.ipv4),
                    "ipv6": list(item.ipv6),
                    "is_up": item.is_up,
                }
            )
        candidates.sort(key=lambda row: int(row["score"]), reverse=True)
        selected = orch.get_network_context()
        selected_score = int(candidates[0]["score"]) if candidates else 0
        runner_score = int(candidates[1]["score"]) if len(candidates) > 1 else 0
        confidence = max(0, min(100, 55 + max(0, selected_score - runner_score))) if selected else 0
        return {
            "mode": "AUTOMATIC",
            "selected": selected,
            "confidence": confidence,
            "candidates": candidates,
            "fail_closed": selected is None,
        }


def install_enterprise_layer(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_layer_installed", False):
        return app
    app.state.enterprise_layer_installed = True

    fusion = EnterpriseFusionEngine(app)
    zeek = ZeekLogAdapter(app)
    tools = EnterpriseToolBroker()
    app.state.enterprise_fusion = fusion
    app.state.zeek_adapter = zeek
    app.state.enterprise_tool_broker = tools

    app.add_event_handler("startup", fusion.start)
    app.add_event_handler("shutdown", fusion.stop)

    @app.get("/api/v1/system/interface-decision")
    async def interface_decision() -> dict[str, Any]:
        return InterfaceDecision.snapshot(app)

    @app.get("/api/v1/system/enterprise-tools")
    async def enterprise_tools() -> dict[str, Any]:
        rows = tools.scan()
        return {
            "tools": rows,
            "available": sum(1 for row in rows if row["available"]),
            "total": len(rows),
        }

    @app.get("/api/v1/system/enterprise-fusion")
    async def enterprise_fusion() -> dict[str, Any]:
        return fusion.snapshot()

    @app.get("/api/v1/system/zeek")
    async def zeek_status() -> dict[str, Any]:
        return getattr(app.state.orchestrator, "zeek", zeek).snapshot()

    @app.get("/api/v1/admin/enterprise/{target}")
    async def enterprise_target(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return fusion.dossier(target)

    @app.get("/api/v1/admin/enterprise")
    async def enterprise_admin(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return {
            "fusion": fusion.snapshot(),
            "zeek": getattr(app.state.orchestrator, "zeek", zeek).snapshot(),
            "tools": tools.scan(),
            "interface": InterfaceDecision.snapshot(app),
        }

    return app
