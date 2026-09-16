from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI


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


def _diagnostics(snapshot: dict[str, Any]) -> dict[str, Any]:
    problems: list[dict[str, str]] = []
    checks: list[dict[str, object]] = []
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    event_bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), dict) else {}

    session_id = snapshot.get("session_id")
    checks.append({"check": "monitoring_session", "ok": bool(session_id), "value": session_id})
    if not session_id:
        problems.append(
            _problem(
                "No active monitoring session",
                "HIGH",
                "session_id is empty",
                "Network discovery has not confirmed a usable routed interface, or the selected network was lost.",
                "Check `ip -br addr` and `ip route`; then verify the intended interface is UP and has a route. MON will open a session automatically after confirmation.",
                "`curl -s http://127.0.0.1:8765/api/v1/live/status` should show a non-empty session_id.",
            )
        )

    interface = str(network.get("interface") or "")
    checks.append({"check": "selected_interface", "ok": bool(interface), "value": interface or None})
    if not interface:
        problems.append(
            _problem(
                "No selected capture interface",
                "HIGH",
                "network.interface is empty",
                "No eligible active routed interface has passed MON's network-selection confirmation.",
                "Run `ip -br addr` and `ip route`. Restore the intended network connection; do not force `any` or loopback.",
                "The Network page and live status should show one concrete interface such as eth0/enp*/wlp*.",
            )
        )

    capture_state = str(capture.get("state") or "UNKNOWN").upper()
    capture_interface = str(capture.get("interface") or "")
    backend = str(capture.get("backend") or "")
    process_pid = int(capture.get("process_pid") or 0)
    checks.extend(
        [
            {"check": "capture_active", "ok": capture_state == "ACTIVE", "value": capture_state},
            {"check": "capture_backend", "ok": backend == "tshark", "value": backend or None},
            {"check": "capture_pid", "ok": process_pid > 0, "value": process_pid or None},
            {
                "check": "interface_alignment",
                "ok": bool(interface and capture_interface and interface == capture_interface),
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
                "The managed TShark process is waiting, unavailable, failed to start, or exited.",
                "Run `sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check` and `sudo journalctl -u campus-ops.service -n 100 --no-pager`. Repair the first reported TShark/interface/permission error.",
                "Live status must show capture.state=ACTIVE and a positive process_pid.",
            )
        )
    if backend != "tshark":
        problems.append(
            _problem(
                "Unexpected capture backend",
                "HIGH",
                f"capture.backend={backend or 'missing'}",
                "The stable runtime contract was violated or stale code is installed.",
                "Pull monitor-v1 and run `bash bootstrap.sh` to recreate the managed environment from the current package.",
                "Live status must report authoritative_packet_source=tshark and capture.backend=tshark.",
            )
        )
    if process_pid <= 0:
        problems.append(
            _problem(
                "TShark process PID is missing",
                "HIGH",
                "capture.process_pid is empty or zero",
                "MON has no verified managed capture process.",
                "Restart only through the managed service: `sudo systemctl restart campus-ops.service`; if it remains missing, run the deployment check and inspect the service journal.",
                "Live status must show a positive TShark process_pid.",
            )
        )
    elif os.name == "posix" and not os.path.exists(f"/proc/{process_pid}"):
        problems.append(
            _problem(
                "Recorded TShark PID is not alive",
                "HIGH",
                f"/proc/{process_pid} does not exist",
                "The capture subprocess exited after MON recorded its PID.",
                "Inspect `sudo journalctl -u campus-ops.service -n 100 --no-pager`, then restart the managed service after correcting the reported capture error.",
                "The watchdog should show a live PID and capture.state=ACTIVE after restart.",
            )
        )
    if interface and capture_interface and interface != capture_interface:
        problems.append(
            _problem(
                "Network and capture interfaces disagree",
                "HIGH",
                f"network.interface={interface}; capture.interface={capture_interface}",
                "Network selection changed but the capture process did not bind to the same confirmed interface.",
                "Restart `campus-ops.service`. If the mismatch returns, capture the output of `bash scripts/diagnose_runtime.sh` before changing interface settings.",
                "The Network and Capture interface values must be identical.",
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
            cause = "The network-discovery worker could not maintain a confirmed usable interface."
            fix = "Check interface/route state with `ip -br addr` and `ip route`; then inspect the MON service journal for the exact discovery error."
        elif name == "capture":
            cause = "The managed TShark worker reported an acquisition/process failure."
            fix = "Run the deployment check and inspect the service journal; correct the TShark/interface/permission error before restarting MON."
        else:
            cause = "A stable analysis worker reported an internal processing error or unhealthy dependency."
            fix = "Inspect `sudo journalctl -u campus-ops.service -n 100 --no-pager` for this worker's exception. Do not reinstall capture tools unless the capture worker is the failing component."
        problems.append(
            _problem(
                f"Worker {name} is {state}",
                "HIGH" if state == "FAILED" else "MEDIUM",
                detail,
                cause,
                fix,
                f"The System page should show worker {name}=HEALTHY after correction.",
            )
        )

    for name, raw in event_bus.items():
        if not isinstance(raw, dict):
            continue
        dropped = int(raw.get("dropped") or 0)
        queued = int(raw.get("queued") or 0)
        capacity = max(1, int(raw.get("capacity") or 1))
        checks.append({"check": f"event_bus:{name}", "ok": dropped == 0, "value": {"queued": queued, "dropped": dropped, "capacity": capacity}})
        if dropped > 0:
            problems.append(
                _problem(
                    f"Event bus dropped data for {name}",
                    "MEDIUM",
                    f"dropped={dropped}; queued={queued}; capacity={capacity}",
                    "The consumer could not keep up with its subscribed event stream and the bounded queue discarded older events.",
                    "Capture `bash scripts/diagnose_runtime.sh` and inspect which worker is lagging. The session-manager control plane is filtered separately and should not be affected by packet-volume drops.",
                    "The dropped counter should remain stable at zero after restart/repair during the next traffic test.",
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
            "process_pid": capture.get("process_pid"),
            "traffic_activity": capture.get("traffic_activity"),
            "packets": capture.get("packets"),
            "last_packet_at": capture.get("last_packet_at"),
        },
        "diagnostics": diagnostics,
        "anomalies": {"count": anomalies["count"], "top": anomalies["items"][:10]},
        "claim": "DETERMINISTIC_RUNTIME_DIAGNOSTICS",
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
