"""Post-install checks for the native Windows MON runtime."""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import psutil

from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.windows_network import discover_candidates, elect_network

SERVICE_NAME = "MONWindows"
PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "MON"
DEPLOYMENT_FILE = PROGRAM_DATA / "deployment.json"


def _service_state() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["sc.exe", "query", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Windows service query failed: {exc}"
    text = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        return False, f"Windows service {SERVICE_NAME} is not installed"
    if "RUNNING" not in text.upper():
        return False, f"Windows service {SERVICE_NAME} is not running"
    return True, f"Windows service {SERVICE_NAME} is RUNNING"


def _deployment_status() -> dict[str, object]:
    if not DEPLOYMENT_FILE.exists():
        return {"installed": False, "profile": None}
    try:
        value = json.loads(DEPLOYMENT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"installed": False, "profile": None, "error": str(exc)}
    return value if isinstance(value, dict) else {"installed": False, "profile": None}


def _console_status() -> tuple[dict[str, object] | None, str | None]:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/api/v1/live/status", timeout=5) as response:
            value = json.load(response)
        if isinstance(value, dict):
            return value, None
        return None, "Console returned a non-object live status"
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return None, f"Console unavailable on 127.0.0.1:8765: {exc}"


def _tshark_interfaces(tshark: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [tshark, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    text = (result.stdout or "").strip()
    if result.returncode != 0:
        return False, (result.stderr or "TShark -D failed").strip()[-800:]
    if not text:
        return False, "TShark found no Npcap capture interfaces"
    return True, text


def _npcap_state() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Npcap service query failed: {exc}"
    text = ((result.stdout or "") + (result.stderr or "")).upper()
    if result.returncode != 0:
        return False, "Npcap driver/service is not installed"
    if "RUNNING" not in text:
        return False, "Npcap driver/service is installed but not running"
    return True, "Npcap service is RUNNING"


def _tshark_process_check(pid: object, capture_device: object) -> tuple[bool, str]:
    try:
        numeric_pid = int(pid or 0)
    except (TypeError, ValueError):
        return False, "runtime TShark PID is invalid"
    if numeric_pid <= 0:
        return False, "runtime TShark PID is missing"
    try:
        process = psutil.Process(numeric_pid)
        name = process.name().casefold()
        args = process.cmdline()
    except (psutil.Error, OSError) as exc:
        return False, f"runtime TShark PID {numeric_pid} is not alive: {exc}"
    if "tshark" not in name:
        return False, f"runtime PID {numeric_pid} is {name}, not TShark"
    expected = str(capture_device or "").strip()
    if expected and "-i" in args:
        index = args.index("-i")
        actual = args[index + 1] if index + 1 < len(args) else ""
        if actual != expected:
            return False, f"runtime TShark is bound to {actual or 'unknown'}, expected {expected}"
    return True, f"runtime TShark PID {numeric_pid} is alive"


def check() -> dict[str, object]:
    problems: list[str] = []
    if os.name != "nt":
        return {
            "state": "UNSUPPORTED",
            "profile": "windows-native-single-source",
            "problems": ["This product branch must run on native Windows, not WSL/Linux"],
        }

    deployment = _deployment_status()
    service_ok, service_detail = _service_state()
    if not service_ok:
        problems.append(service_detail)

    npcap_ok, npcap_detail = _npcap_state()
    if not npcap_ok:
        problems.append(npcap_detail)

    tshark = resolve_executable("tshark")
    tshark_interfaces_ok = False
    tshark_interfaces_detail = "TShark is missing"
    if tshark:
        tshark_interfaces_ok, tshark_interfaces_detail = _tshark_interfaces(tshark)
    else:
        problems.append("TShark is missing; install Wireshark with Npcap")
    if not tshark_interfaces_ok:
        problems.append("Npcap/TShark capture interfaces are unavailable: " + tshark_interfaces_detail)

    try:
        selected = elect_network(discover_candidates())
    except (OSError, RuntimeError, ValueError, psutil.Error) as exc:
        selected = None
        problems.append(f"Windows adapter discovery failed: {exc}")
    if selected is None:
        problems.append("No eligible active physical Windows adapter")

    status, console_error = _console_status()
    process_ok = False
    process_detail = "runtime TShark process not checked"
    if console_error:
        problems.append(console_error)
    elif status is not None:
        if str(status.get("runtime_profile") or "") != "windows-native-single-source":
            problems.append("MON is not running the Windows-native runtime profile")
        if str(status.get("ip_truth_policy") or "") != "current-session-packet-evidence-only":
            problems.append("MON IP truth policy is not the Windows packet-evidence policy")
        if not status.get("session_id"):
            problems.append("MON has no active monitoring session")
        network = status.get("network") if isinstance(status.get("network"), dict) else {}
        live = status.get("live") if isinstance(status.get("live"), dict) else {}
        capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
        selected_interface = str(network.get("interface") or "")
        capture_interface = str(capture.get("interface") or "")
        if not selected_interface:
            problems.append("MON has no selected Windows adapter")
        if str(capture.get("state") or "").upper() != "ACTIVE":
            problems.append("MON capture is not ACTIVE: " + str(capture.get("detail") or "unknown"))
        if str(capture.get("backend") or "") != "tshark":
            problems.append("MON capture backend is not TShark")
        if selected_interface and capture_interface and selected_interface.casefold() != capture_interface.casefold():
            problems.append(
                f"network/capture adapter mismatch: network={selected_interface} capture={capture_interface}"
            )
        process_ok, process_detail = _tshark_process_check(
            capture.get("process_pid"), capture.get("capture_device")
        )
        if not process_ok:
            problems.append(process_detail)

    if not deployment.get("installed"):
        problems.append("Windows deployment manifest is missing; run .\\bootstrap.ps1 as Administrator")
    elif deployment.get("profile") != "windows-native-single-source":
        problems.append("Deployment manifest profile is not windows-native-single-source")

    problems = list(dict.fromkeys(problems))
    return {
        "state": "READY" if not problems else "PARTIAL",
        "profile": "windows-native-single-source",
        "problems": problems,
        "windows_service": {"verified": service_ok, "detail": service_detail},
        "npcap": {"verified": npcap_ok, "detail": npcap_detail},
        "capture": {
            "engine": "TShark",
            "driver": "Npcap",
            "interfaces_verified": tshark_interfaces_ok,
            "runtime_process_verified": process_ok,
            "runtime_process_detail": process_detail,
        },
        "selected_adapter": selected.interface if selected else None,
        "deployment": deployment,
    }


def main() -> None:
    report = check()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report.get("state") == "READY" else 2)


if __name__ == "__main__":
    main()
