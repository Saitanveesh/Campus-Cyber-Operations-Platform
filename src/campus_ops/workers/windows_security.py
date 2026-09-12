from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.base import BaseWorker


class WindowsSecurityTelemetryWorker(BaseWorker):
    """Read-only Windows Defender, firewall and Sysmon posture telemetry."""

    SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$defender = Get-MpComputerStatus
$firewall = @(Get-NetFirewallProfile | Select-Object Name,Enabled)
$sysmon = @(Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object Name,Status)
[PSCustomObject]@{
  defender = if ($defender) {
    [PSCustomObject]@{
      AntivirusEnabled = $defender.AntivirusEnabled
      RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
      BehaviorMonitorEnabled = $defender.BehaviorMonitorEnabled
      IoavProtectionEnabled = $defender.IoavProtectionEnabled
      NISEnabled = $defender.NISEnabled
      AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
    }
  } else { $null }
  firewall = $firewall
  sysmon = $sysmon
} | ConvertTo-Json -Depth 5 -Compress
"""

    def __init__(self, bus: EventBus, state: LiveState, interval: float = 30.0) -> None:
        super().__init__("windows-security-telemetry", bus)
        self.state = state
        self.interval = max(10.0, interval)
        self.last: dict[str, Any] = {}

    @staticmethod
    def _bool(value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
        return None

    @classmethod
    def normalize(cls, raw: object) -> dict[str, Any]:
        data = raw if isinstance(raw, dict) else {}
        defender = data.get("defender") if isinstance(data.get("defender"), dict) else {}
        firewall_raw = data.get("firewall")
        if isinstance(firewall_raw, dict):
            firewall_rows = [firewall_raw]
        elif isinstance(firewall_raw, list):
            firewall_rows = [item for item in firewall_raw if isinstance(item, dict)]
        else:
            firewall_rows = []
        firewall = {
            str(item.get("Name") or "unknown"): cls._bool(item.get("Enabled"))
            for item in firewall_rows
        }
        sysmon_raw = data.get("sysmon")
        if isinstance(sysmon_raw, dict):
            sysmon_rows = [sysmon_raw]
        elif isinstance(sysmon_raw, list):
            sysmon_rows = [item for item in sysmon_raw if isinstance(item, dict)]
        else:
            sysmon_rows = []
        sysmon = [
            {
                "name": str(item.get("Name") or "Sysmon"),
                "status": str(item.get("Status") or "UNKNOWN"),
            }
            for item in sysmon_rows
        ]
        return {
            "available": True,
            "defender": {
                "antivirus_enabled": cls._bool(defender.get("AntivirusEnabled")),
                "realtime_enabled": cls._bool(defender.get("RealTimeProtectionEnabled")),
                "behavior_monitor_enabled": cls._bool(defender.get("BehaviorMonitorEnabled")),
                "ioav_enabled": cls._bool(defender.get("IoavProtectionEnabled")),
                "nis_enabled": cls._bool(defender.get("NISEnabled")),
                "signature_updated": defender.get("AntivirusSignatureLastUpdated"),
            },
            "firewall": firewall,
            "sysmon": sysmon,
        }

    @classmethod
    def _probe(cls) -> dict[str, Any]:
        executable = resolve_executable("powershell") or resolve_executable("pwsh")
        if not executable:
            return {"available": False, "error": "PowerShell not available"}
        try:
            result = subprocess.run(
                [executable, "-NoProfile", "-Command", cls.SCRIPT],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"available": False, "error": str(exc)}
        if result.returncode != 0:
            return {
                "available": False,
                "error": (result.stderr or result.stdout or f"exit {result.returncode}").strip()[:1000],
            }
        try:
            decoded = json.loads((result.stdout or "{}").strip() or "{}")
        except json.JSONDecodeError as exc:
            return {"available": False, "error": f"invalid PowerShell JSON: {exc}"}
        return cls.normalize(decoded)

    async def run(self) -> None:
        while not self.stopping:
            current = await asyncio.to_thread(self._probe)
            self.last = current
            self.state.update_metrics(windows_security=current)
            if current.get("available"):
                self.health.state = WorkerState.HEALTHY
                defender = current.get("defender") if isinstance(current.get("defender"), dict) else {}
                firewall = current.get("firewall") if isinstance(current.get("firewall"), dict) else {}
                realtime = defender.get("realtime_enabled")
                enabled_profiles = sum(1 for value in firewall.values() if value is True)
                self.health.heartbeat(
                    f"defender_realtime={realtime} firewall_profiles={enabled_profiles}/{len(firewall)}"
                )
            else:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(str(current.get("error") or "Windows security telemetry unavailable"))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
