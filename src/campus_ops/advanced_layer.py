from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil
from fastapi import FastAPI, Header, HTTPException, Request

from campus_ops.admin_deep import _require_admin


LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_PARENT_PAIRS = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("mshta.exe", "powershell.exe"),
}


def build_process_dossier(
    processes: list[dict[str, Any]], connections: list[dict[str, Any]]
) -> dict[str, Any]:
    by_pid: dict[int, dict[str, Any]] = {}
    children: dict[int, list[int]] = defaultdict(list)
    for row in processes:
        try:
            pid = int(row.get("pid") or 0)
            ppid = int(row.get("ppid") or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        item = dict(row)
        item["pid"] = pid
        item["ppid"] = ppid
        by_pid[pid] = item
        if ppid > 0:
            children[ppid].append(pid)

    connection_map: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in connections:
        try:
            pid = int(row.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if pid > 0:
            connection_map[pid].append(dict(row))

    findings: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    for pid, row in by_pid.items():
        name = str(row.get("name") or "").lower()
        parent = by_pid.get(int(row.get("ppid") or 0), {})
        parent_name = str(parent.get("name") or "").lower()
        cmdline = str(row.get("cmdline") or "")
        exe = str(row.get("exe") or "")
        node = {
            **row,
            "parent_name": parent.get("name") or "",
            "children": sorted(children.get(pid, [])),
            "connections": connection_map.get(pid, []),
            "connection_count": len(connection_map.get(pid, [])),
        }
        nodes.append(node)

        if (parent_name, name) in SUSPICIOUS_PARENT_PAIRS:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "UNUSUAL_PROCESS_LINEAGE",
                    "pid": pid,
                    "process": row.get("name"),
                    "parent": parent.get("name"),
                    "detail": "Office/script parent-child chain requires review",
                }
            )
        if name in LOLBINS and connection_map.get(pid):
            findings.append(
                {
                    "severity": "LOW",
                    "type": "LOLBIN_WITH_NETWORK_ACTIVITY",
                    "pid": pid,
                    "process": row.get("name"),
                    "detail": f"{row.get('name')} currently has network activity",
                    "connection_count": len(connection_map[pid]),
                }
            )
        lowered = (exe + " " + cmdline).lower()
        if any(token in lowered for token in ("\\temp\\", "\\appdata\\local\\temp\\")):
            findings.append(
                {
                    "severity": "LOW",
                    "type": "TEMP_EXECUTION_PATH",
                    "pid": pid,
                    "process": row.get("name"),
                    "detail": "Process executable or command line references a temporary directory",
                }
            )

    nodes.sort(
        key=lambda row: (
            len(row.get("connections", [])),
            len(row.get("children", [])),
            float(row.get("memory_percent") or 0),
        ),
        reverse=True,
    )
    return {
        "processes": nodes,
        "findings": findings,
        "roots": [row["pid"] for row in nodes if int(row.get("ppid") or 0) not in by_pid],
    }


def persistence_diff(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    def key(row: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(row.get("source") or ""),
            str(row.get("name") or ""),
            str(row.get("command") or ""),
        )

    old_map = {key(row): row for row in old}
    new_map = {key(row): row for row in new}
    return {
        "added": [new_map[item] for item in sorted(new_map.keys() - old_map.keys())],
        "removed": [old_map[item] for item in sorted(old_map.keys() - new_map.keys())],
    }


@dataclass(slots=True)
class AdvancedHostState:
    last_process_scan: float = 0.0
    last_persistence_scan: float = 0.0
    last_sysmon_scan: float = 0.0


class AdvancedHostEngine:
    """Local defensive process-lineage, persistence and Sysmon correlation engine."""

    def __init__(self) -> None:
        self.state = AdvancedHostState()
        self.process_report: dict[str, Any] = {"processes": [], "findings": [], "roots": []}
        self.persistence: list[dict[str, Any]] = []
        self.persistence_changes: deque[dict[str, Any]] = deque(maxlen=200)
        self.sysmon_events: deque[dict[str, Any]] = deque(maxlen=500)
        self._sysmon_seen: set[str] = set()
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self.last_error: str | None = None

    @staticmethod
    def _processes() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        attrs = [
            "pid",
            "ppid",
            "name",
            "username",
            "exe",
            "cmdline",
            "create_time",
            "cpu_percent",
            "memory_percent",
        ]
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
            cmdline = info.get("cmdline") or []
            rows.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "",
                    "user": info.get("username") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(str(item) for item in cmdline)[:4096],
                    "create_time": info.get("create_time"),
                    "cpu_percent": info.get("cpu_percent") or 0,
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                }
            )
        return rows

    @staticmethod
    def _connections() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return rows
        for conn in conns[:1000]:
            rows.append(
                {
                    "pid": conn.pid,
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                }
            )
        return rows

    @staticmethod
    def _powershell_json(script: str, timeout: float = 20.0) -> Any:
        if os.name != "nt":
            return []
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or "PowerShell failed").strip())
        raw = (completed.stdout or "").strip()
        return json.loads(raw) if raw else []

    @classmethod
    def _persistence_snapshot(cls) -> list[dict[str, Any]]:
        script = r"""
$items=@()
$keys=@(
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach($k in $keys){
 if(Test-Path $k){
   $p=Get-ItemProperty $k
   foreach($prop in $p.PSObject.Properties){
     if($prop.Name -notmatch '^PS'){ $items += [PSCustomObject]@{source=$k;name=$prop.Name;command=[string]$prop.Value;kind='REGISTRY_RUN'} }
   }
 }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Disabled'} | Select-Object -First 300 | ForEach-Object {
 $cmd=(($_.Actions | ForEach-Object {($_.Execute+' '+$_.Arguments).Trim()}) -join '; ')
 $items += [PSCustomObject]@{source=$_.TaskPath;name=$_.TaskName;command=$cmd;kind='SCHEDULED_TASK'}
}
$items | ConvertTo-Json -Depth 4 -Compress
"""
        data = cls._powershell_json(script)
        if isinstance(data, dict):
            data = [data]
        return [dict(item) for item in data if isinstance(item, dict)]

    @classmethod
    def _sysmon_snapshot(cls) -> list[dict[str, Any]]:
        script = r"""
$log='Microsoft-Windows-Sysmon/Operational'
if(-not (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue)){ @() | ConvertTo-Json -Compress; exit 0 }
$start=(Get-Date).AddMinutes(-3)
Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$start;Id=1,3,11,13} -ErrorAction SilentlyContinue | Select-Object -First 250 | ForEach-Object {
 [PSCustomObject]@{record_id=$_.RecordId;event_id=$_.Id;time=$_.TimeCreated.ToUniversalTime().ToString('o');message=$_.Message}
} | ConvertTo-Json -Depth 4 -Compress
"""
        data = cls._powershell_json(script)
        if isinstance(data, dict):
            data = [data]
        rows = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "record_id": item.get("record_id"),
                    "event_id": item.get("event_id"),
                    "time": item.get("time"),
                    "message": str(item.get("message") or "")[:12000],
                }
            )
        return rows

    async def _scan_processes(self) -> None:
        processes, connections = await asyncio.gather(
            asyncio.to_thread(self._processes),
            asyncio.to_thread(self._connections),
        )
        self.process_report = build_process_dossier(processes, connections)
        self.state.last_process_scan = time.time()

    async def _scan_persistence(self) -> None:
        current = await asyncio.to_thread(self._persistence_snapshot)
        if self.persistence:
            diff = persistence_diff(self.persistence, current)
            if diff["added"] or diff["removed"]:
                self.persistence_changes.appendleft(
                    {
                        "timestamp": time.time(),
                        "added": diff["added"],
                        "removed": diff["removed"],
                    }
                )
        self.persistence = current
        self.state.last_persistence_scan = time.time()

    async def _scan_sysmon(self) -> None:
        rows = await asyncio.to_thread(self._sysmon_snapshot)
        for row in reversed(rows):
            key = f"{row.get('record_id')}:{row.get('event_id')}"
            if key in self._sysmon_seen:
                continue
            self._sysmon_seen.add(key)
            self.sysmon_events.appendleft(row)
        if len(self._sysmon_seen) > 5000:
            self._sysmon_seen = {
                f"{row.get('record_id')}:{row.get('event_id')}" for row in list(self.sysmon_events)[:500]
            }
        self.state.last_sysmon_scan = time.time()

    async def run(self) -> None:
        next_persistence = 0.0
        next_sysmon = 0.0
        while not self._stop.is_set():
            try:
                await self._scan_processes()
                now = time.monotonic()
                if now >= next_persistence:
                    await self._scan_persistence()
                    next_persistence = now + 60.0
                if now >= next_sysmon:
                    await self._scan_sysmon()
                    next_sysmon = now + 10.0
                self.last_error = None
            except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=5.0)
            except TimeoutError:
                pass

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self.run(), name="advanced-host-engine")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": "DEGRADED" if self.last_error else "HEALTHY",
            "last_error": self.last_error,
            "last_process_scan": self.state.last_process_scan,
            "last_persistence_scan": self.state.last_persistence_scan,
            "last_sysmon_scan": self.state.last_sysmon_scan,
            "process": self.process_report,
            "persistence": self.persistence,
            "persistence_changes": list(self.persistence_changes),
            "sysmon_events": list(self.sysmon_events),
        }


def install_advanced_layer(app: FastAPI) -> FastAPI:
    if getattr(app.state, "advanced_layer_installed", False):
        return app
    app.state.advanced_layer_installed = True
    engine = AdvancedHostEngine()
    app.state.advanced_host_engine = engine
    app.add_event_handler("startup", engine.start)
    app.add_event_handler("shutdown", engine.stop)

    @app.get("/api/v1/admin/host-forensics")
    async def host_forensics(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return engine.snapshot()

    @app.get("/api/v1/admin/host-forensics/process/{pid}")
    async def host_process(
        pid: int,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        for row in engine.process_report.get("processes", []):
            if int(row.get("pid") or 0) == pid:
                return row
        raise HTTPException(status_code=404, detail="process not present in current host snapshot")

    @app.get("/api/v1/admin/host-forensics/persistence")
    async def host_persistence(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return {
            "items": engine.persistence,
            "changes": list(engine.persistence_changes),
            "last_scan": engine.state.last_persistence_scan,
        }

    @app.get("/api/v1/admin/host-forensics/sysmon")
    async def host_sysmon(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return {
            "events": list(engine.sysmon_events),
            "last_scan": engine.state.last_sysmon_scan,
            "available": bool(engine.sysmon_events) or engine.last_error is None,
        }

    return app
