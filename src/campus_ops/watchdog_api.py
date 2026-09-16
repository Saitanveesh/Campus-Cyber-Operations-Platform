from __future__ import annotations

import os
from typing import Any

import psutil
from fastapi import FastAPI

SERVICE_NAME = "MONWindows"


def _anomaly_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    alerts = [item for item in live.get("alerts", []) if isinstance(item, dict)]
    incidents = [
        item
        for item in live.get("incidents", [])
        if isinstance(item, dict) and str(item.get("status") or "OPEN").upper() != "CLOSED"
    ]
    rows: list[dict[str, Any]] = []
    for item in alerts:
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        rows.append(
            {
                "kind": "ALERT",
                "severity": item.get("severity") or "INFO",
                "title": payload.get("title") or payload.get("message") or "Observed anomaly",
                "timestamp": item.get("timestamp"),
            }
        )
    for item in incidents:
        rows.append(
            {
                "kind": "INCIDENT",
                "severity": item.get("severity") or "INFO",
                "title": item.get("title") or "Correlated incident",
                "timestamp": item.get("last_seen") or item.get("first_seen"),
            }
        )
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    rows.sort(
        key=lambda item: (
            rank.get(str(item.get("severity") or "INFO").upper(), 0),
            str(item.get("timestamp") or ""),
        ),
        reverse=True,
    )
    return {"count": len(rows), "items": rows[:100]}


def _problem(
    problem: str,
    severity: str,
    evidence: str,
    cause: str,
    fix: str,
    verify: str,
) -> dict[str, str]:
    return {
        "problem": problem,
        "severity": severity,
        "evidence": evidence,
        "cause": cause,
        "fix": fix,
        "verify": verify,
    }


def _pid_is_tshark(pid: int) -> tuple[bool, str]:
    if pid <= 0:
        return False, "no PID"
    try:
        process = psutil.Process(pid)
        name = process.name()
        cmdline = " ".join(process.cmdline())
    except (psutil.Error, OSError) as exc:
        return False, str(exc)
    if "tshark" not in name.casefold():
        return False, f"PID {pid} belongs to {name}, not TShark"
    return True, cmdline


def _diagnostics(snapshot: dict[str, Any]) -> dict[str, Any]:
    problems: list[dict[str, str]] = []
    checks: list[dict[str, object]] = []
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    event_bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), dict) else {}

    native_windows = os.name == "nt"
    checks.append({"check": "native_windows", "ok": native_windows, "value": os.name})
    if not native_windows:
        problems.append(
            _problem(
                "MON is not running on native Windows",
                "HIGH",
                f"os.name={os.name}",
                "The Windows product build was started from WSL/Linux or another unsupported host.",
                "Close this instance and run MON from Windows PowerShell using .\\bootstrap.ps1.",
                "System diagnostics must report native_windows=OK.",
            )
        )

    session_id = snapshot.get("session_id")
    checks.append({"check": "monitoring_session", "ok": bool(session_id), "value": session_id})
    if not session_id:
        problems.append(
            _problem(
                "No active monitoring session",
                "HIGH",
                "session_id is empty",
                "Windows adapter discovery has not confirmed an eligible routed adapter or the selected network was lost.",
                "Run `Get-NetAdapter` and `Get-NetIPConfiguration` in PowerShell. Confirm the intended Wi-Fi/Ethernet adapter is Up and has an IPv4 address/default gateway.",
                "Open http://127.0.0.1:8765/api/v1/live/status and confirm session_id is non-empty.",
            )
        )

    interface = str(network.get("interface") or "")
    checks.append({"check": "selected_adapter", "ok": bool(interface), "value": interface or None})
    if not interface:
        problems.append(
            _problem(
                "No Windows capture adapter selected",
                "HIGH",
                "network.interface is empty",
                "MON did not find a confirmed active physical Wi-Fi/Ethernet adapter with usable routing.",
                "Run `Get-NetAdapter | Format-Table Name,Status,InterfaceDescription` and `Get-NetRoute -DestinationPrefix 0.0.0.0/0`. Restore the real adapter instead of forcing a virtual/loopback interface.",
                "The Network page must show one concrete Windows adapter such as Wi-Fi or Ethernet.",
            )
        )

    capture_state = str(capture.get("state") or "UNKNOWN").upper()
    capture_interface = str(capture.get("interface") or "")
    capture_device = str(capture.get("capture_device") or "")
    backend = str(capture.get("backend") or "")
    process_pid = int(capture.get("process_pid") or 0)
    pid_ok, pid_detail = _pid_is_tshark(process_pid)
    checks.extend(
        [
            {"check": "capture_active", "ok": capture_state == "ACTIVE", "value": capture_state},
            {"check": "capture_backend", "ok": backend == "tshark", "value": backend or None},
            {"check": "tshark_process", "ok": pid_ok, "value": process_pid or None},
            {"check": "npcap_device", "ok": bool(capture_device), "value": capture_device or None},
            {
                "check": "adapter_alignment",
                "ok": bool(
                    interface
                    and capture_interface
                    and interface.casefold() == capture_interface.casefold()
                ),
                "value": f"network={interface or '-'} capture={capture_interface or '-'}",
            },
        ]
    )

    if capture_state != "ACTIVE":
        detail = str(capture.get("detail") or capture_state)
        problems.append(
            _problem(
                "Packet capture is not active",
                "HIGH",
                f"capture.state={capture_state}; detail={detail}",
                "TShark could not bind the elected Windows adapter, Npcap is unavailable, or the TShark child process exited.",
                "In Administrator PowerShell run `& 'C:\\Program Files\\Wireshark\\tshark.exe' -D` and `Get-Service npcap -ErrorAction SilentlyContinue`. Then run `.\\scripts\\diagnose_windows.ps1` for the exact adapter/process failure.",
                "MON must show capture.state=ACTIVE, backend=tshark, and a positive process_pid.",
            )
        )
    if backend != "tshark":
        problems.append(
            _problem(
                "Unexpected capture backend",
                "HIGH",
                f"capture.backend={backend or 'missing'}",
                "The Windows single-source runtime contract was violated or stale files are running.",
                "Pull the Windows branch and rerun `.\\bootstrap.ps1` from Administrator PowerShell.",
                "Live status must report authoritative_packet_source=tshark and capture.backend=tshark.",
            )
        )
    if not pid_ok:
        problems.append(
            _problem(
                "Managed TShark process is not verified",
                "HIGH",
                f"process_pid={process_pid or 'missing'}; {pid_detail}",
                "MON has no live TShark process corresponding to its capture state.",
                "Run `.\\scripts\\diagnose_windows.ps1`; restart MONWindows only after fixing the first reported TShark/Npcap error.",
                "Watchdog must show a live TShark PID and capture.state=ACTIVE.",
            )
        )
    if interface and capture_interface and interface.casefold() != capture_interface.casefold():
        problems.append(
            _problem(
                "Selected adapter and capture adapter disagree",
                "HIGH",
                f"network.interface={interface}; capture.interface={capture_interface}",
                "Windows network selection changed but the managed capture was not rebound to the same confirmed adapter.",
                "Run `Restart-Service MONWindows` in Administrator PowerShell. If it returns, capture `.\\scripts\\diagnose_windows.ps1` output.",
                "The Network and Capture interface names must match exactly ignoring case.",
            )
        )

    for name, raw in workers.items():
        if not isinstance(raw, dict):
            continue
        state = str(raw.get("state") or "UNKNOWN").upper()
        checks.append({"check": f"worker:{name}", "ok": state == "HEALTHY", "value": state})
        if state not in {"FAILED", "DEGRADED"}:
            continue
        detail = str(raw.get("detail") or raw.get("last_error") or state)
        if name == "network-discovery":
            cause = "Native Windows adapter/routing discovery could not maintain a confirmed interface."
            fix = "Use `Get-NetAdapter` and `Get-NetIPConfiguration`, restore the real Wi-Fi/Ethernet adapter, then run `.\\scripts\\diagnose_windows.ps1`."
        elif name == "capture":
            cause = "The managed TShark/Npcap capture worker reported a process or adapter binding failure."
            fix = "Run `tshark.exe -D`, verify the Npcap service/driver, then run `.\\scripts\\diagnose_windows.ps1`."
        elif name == "evidence-store":
            cause = "The local metadata history database could not be opened or written."
            fix = "Check free disk space and permissions on `C:\\ProgramData\\MON`, then restart `MONWindows`."
        else:
            cause = "A packet-analysis worker reported an internal processing error or unhealthy dependency."
            fix = "Use the System diagnostics and Windows service status. Do not reinstall capture components unless the capture worker itself is failing."
        problems.append(
            _problem(
                f"Worker {name} is {state}",
                "HIGH" if state == "FAILED" else "MEDIUM",
                detail,
                cause,
                fix,
                f"System must show worker {name}=HEALTHY after correction.",
            )
        )

    for name, raw in event_bus.items():
        if not isinstance(raw, dict):
            continue
        dropped = int(raw.get("dropped") or 0)
        queued = int(raw.get("queued") or 0)
        capacity = max(1, int(raw.get("capacity") or 1))
        checks.append(
            {
                "check": f"event_bus:{name}",
                "ok": dropped == 0,
                "value": {"queued": queued, "dropped": dropped, "capacity": capacity},
            }
        )
        if dropped > 0:
            problems.append(
                _problem(
                    f"Event bus dropped data for {name}",
                    "MEDIUM",
                    f"dropped={dropped}; queued={queued}; capacity={capacity}",
                    "The analysis consumer could not keep up with its subscribed packet/event stream.",
                    "Run `.\\scripts\\diagnose_windows.ps1` and inspect the named worker. The session-manager control plane is isolated from packet-volume drops.",
                    "The dropped counter should remain stable at zero during the next controlled traffic test.",
                )
            )

    return {
        "state": "HEALTHY" if not problems else "ATTENTION",
        "problem_count": len(problems),
        "problems": problems,
        "checks": checks,
    }


def build_watchdog_status(snapshot: dict[str, Any]) -> dict[str, Any]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    diagnostics = _diagnostics(snapshot)
    anomalies = _anomaly_summary(snapshot)
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    return {
        "state": diagnostics["state"],
        "session_id": snapshot.get("session_id"),
        "interface": network.get("interface"),
        "capture": {
            "state": capture.get("state"),
            "backend": capture.get("backend"),
            "interface": capture.get("interface"),
            "capture_device": capture.get("capture_device"),
            "process_pid": capture.get("process_pid"),
            "traffic_activity": capture.get("traffic_activity"),
            "packets": capture.get("packets"),
            "last_packet_at": capture.get("last_packet_at"),
        },
        "diagnostics": diagnostics,
        "anomalies": {"count": anomalies["count"], "top": anomalies["items"][:10]},
        "claim": "WINDOWS_DETERMINISTIC_RUNTIME_DIAGNOSTICS",
    }


def install_watchdog_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "watchdog_api_installed", False):
        return app
    app.state.watchdog_api_installed = True

    @app.get("/api/v1/system/watchdog")
    async def watchdog_status() -> dict[str, Any]:
        return build_watchdog_status(app.state.orchestrator.snapshot())

    @app.get("/api/v1/system/diagnostics")
    async def diagnostics() -> dict[str, Any]:
        return _diagnostics(app.state.orchestrator.snapshot())

    return app
