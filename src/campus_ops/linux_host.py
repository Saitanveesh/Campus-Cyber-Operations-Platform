"""Read-only Ubuntu host discovery. Presence does not prove deployment compatibility."""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path


def default_routes() -> dict[str, tuple[bool, int | None, str | None]]:
    result = {}
    for family in ("-4", "-6"):
        try:
            proc = subprocess.run(
                ["ip", "-j", family, "route", "show", "default"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            rows = json.loads(proc.stdout) if proc.returncode == 0 else []
            for row in rows if isinstance(rows, list) else []:
                name = str(row.get("dev") or "")
                metric = int(row.get("metric") or 0)
                if not name:
                    continue
                previous = result.get(name)
                if previous and (family == "-6" or metric >= previous[1]):
                    continue
                result[name] = (True, metric, row.get("gateway"))
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            continue
    return result


def services() -> list[dict[str, str]]:
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager",
             "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    if proc.returncode == 0:
        for line in proc.stdout.splitlines()[:500]:
            fields = line.split(None, 4)
            if len(fields) >= 4:
                rows.append({"name": fields[0], "status": fields[2],
                             "display_name": fields[4] if len(fields) > 4 else fields[0]})
    return rows


def host_status() -> dict[str, object]:
    return {
        "platform": platform.system(), "kernel": platform.release(),
        "architecture": platform.machine(), "btf_present": Path("/sys/kernel/btf/vmlinux").exists(),
        "wsl": "microsoft" in platform.release().lower(),
        "interface_scope": ("Interfaces exposed to this WSL guest; host Wi-Fi radio may be hidden"
                            if "microsoft" in platform.release().lower() else "Linux host interfaces"),
        "systemd_present": Path("/run/systemd/system").exists(),
        "iproute2_present": bool(shutil.which("ip")),
        "sensor_compatibility": "NOT_VALIDATED",
        "linux_containment": "NOT_IMPLEMENTED",
    }
