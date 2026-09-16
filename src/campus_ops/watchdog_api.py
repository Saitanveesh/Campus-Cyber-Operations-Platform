from __future__ import annotations

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


def _diagnostics(snapshot: dict[str, Any]) -> dict[str, Any]:
    problems: list[dict[str, str]] = []
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}

    if not snapshot.get("session_id"):
        problems.append({"problem": "No active monitoring session", "severity": "HIGH"})
    if not network.get("interface"):
        problems.append({"problem": "No selected capture interface", "severity": "HIGH"})
    if str(capture.get("state") or "UNKNOWN").upper() != "ACTIVE":
        problems.append(
            {
                "problem": str(capture.get("detail") or "TShark capture is not active"),
                "severity": "HIGH",
            }
        )
    if str(capture.get("backend") or "") != "tshark":
        problems.append({"problem": "Capture backend is not TShark", "severity": "HIGH"})
    if not capture.get("process_pid"):
        problems.append({"problem": "TShark process PID is missing", "severity": "HIGH"})

    for name, raw in workers.items():
        if not isinstance(raw, dict):
            continue
        state = str(raw.get("state") or "UNKNOWN").upper()
        if state in {"FAILED", "DEGRADED"}:
            problems.append(
                {
                    "problem": f"{name}: {raw.get('detail') or state}",
                    "severity": "HIGH" if state == "FAILED" else "MEDIUM",
                }
            )

    return {
        "state": "HEALTHY" if not problems else "ATTENTION",
        "problem_count": len(problems),
        "problems": problems,
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
            "process_pid": capture.get("process_pid"),
            "traffic_activity": capture.get("traffic_activity"),
            "packets": capture.get("packets"),
            "last_packet_at": capture.get("last_packet_at"),
        },
        "diagnostics": diagnostics,
        "anomalies": {"count": anomalies["count"], "top": anomalies["items"][:10]},
        "claim": "STABLE_RUNTIME_OBSERVED_STATE_ONLY",
    }


def install_watchdog_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "watchdog_api_installed", False):
        return app
    app.state.watchdog_api_installed = True

    @app.get("/api/v1/system/watchdog")
    async def watchdog_status() -> dict[str, Any]:
        return build_watchdog_status(app.state.orchestrator.snapshot())

    return app
