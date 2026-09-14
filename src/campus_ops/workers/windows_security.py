from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from datetime import UTC, datetime
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
$firewall = @(Get-NetFirewallProfile | ForEach-Object {
  $rawEnabled = $_.Enabled.ToString()
  $normalizedEnabled = $null
  if ($rawEnabled -eq 'True') { $normalizedEnabled = $true }
  elseif ($rawEnabled -eq 'False') { $normalizedEnabled = $false }
  [PSCustomObject]@{
    Name = $_.Name.ToString()
    Enabled = $normalizedEnabled
    EnabledRaw = $rawEnabled
  }
})
$sysmon = @(Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ Name = $_.Name.ToString(); Status = $_.Status.ToString() }
})
$signatureUpdated = $null
if ($defender -and $defender.AntivirusSignatureLastUpdated) {
  try { $signatureUpdated = $defender.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
  catch { $signatureUpdated = $defender.AntivirusSignatureLastUpdated.ToString() }
}
[PSCustomObject]@{
  defender = if ($defender) {
    [PSCustomObject]@{
      AntivirusEnabled = [bool]$defender.AntivirusEnabled
      RealTimeProtectionEnabled = [bool]$defender.RealTimeProtectionEnabled
      BehaviorMonitorEnabled = [bool]$defender.BehaviorMonitorEnabled
      IoavProtectionEnabled = [bool]$defender.IoavProtectionEnabled
      NISEnabled = [bool]$defender.NISEnabled
      AntivirusSignatureLastUpdated = $signatureUpdated
    }
  } else { $null }
  firewall = $firewall
  sysmon = $sysmon
} | ConvertTo-Json -Depth 5 -Compress
"""

    LEGACY_DATE = re.compile(r"^/Date\((?P<ms>-?\d+)(?:[+-]\d+)?\)/$")

    def __init__(self, bus: EventBus, state: LiveState, interval: float = 30.0) -> None:
        super().__init__("windows-security-telemetry", bus)
        self.state = state
        self.interval = max(10.0, interval)
        self.last: dict[str, Any] = {}

    @staticmethod
    def _bool(value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "on", "enabled"}:
                return True
            if lowered in {"false", "0", "off", "disabled"}:
                return False
        return None

    @classmethod
    def _timestamp(cls, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        match = cls.LEGACY_DATE.match(text)
        if match:
            try:
                milliseconds = int(match.group("ms"))
                return datetime.fromtimestamp(milliseconds / 1000, tz=UTC).isoformat()
            except (OverflowError, OSError, ValueError):
                return text
        return text

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
        firewall: dict[str, bool | None] = {}
        for item in firewall_rows:
            enabled = cls._bool(item.get("Enabled"))
            if enabled is None:
                enabled = cls._bool(item.get("EnabledRaw"))
            firewall[str(item.get("Name") or "unknown")] = enabled

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
                "signature_updated": cls._timestamp(defender.get("AntivirusSignatureLastUpdated")),
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
        if os.name != "nt":
            self.last = {"available": False, "state": "NOT_APPLICABLE"}
            self.state.update_metrics(windows_security=self.last)
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat("Windows security is not applicable on Ubuntu")
            await self._stop.wait()
            return
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
                known_profiles = sum(1 for value in firewall.values() if value in {True, False})
                self.health.heartbeat(
                    f"defender_realtime={realtime} firewall_profiles={enabled_profiles}/{len(firewall)} known={known_profiles}"
                )
            else:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(str(current.get("error") or "Windows security telemetry unavailable"))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
