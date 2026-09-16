from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from campus_ops.operational_core import build_anomaly_summary, build_system_diagnostics


def build_watchdog_status(snapshot: dict[str, Any]) -> dict[str, Any]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    diagnostics = build_system_diagnostics(snapshot)
    anomalies = build_anomaly_summary(snapshot)
    return {
        "state": "HEALTHY" if diagnostics["problem_count"] == 0 else "ATTENTION",
        "session_id": snapshot.get("session_id"),
        "interface": (snapshot.get("network") or {}).get("interface")
        if isinstance(snapshot.get("network"), dict)
        else None,
        "capture": {
            "state": capture.get("state"),
            "backend": capture.get("backend"),
            "process_pid": capture.get("process_pid"),
            "traffic_activity": capture.get("traffic_activity"),
            "packets": capture.get("packets"),
            "last_packet_at": capture.get("last_packet_at"),
        },
        "diagnostics": diagnostics,
        "anomalies": {
            "count": anomalies["count"],
            "top": anomalies["items"][:10],
        },
        "claim": "WATCHDOG_REPORTS_OBSERVED_PLATFORM_AND_SECURITY_STATE",
    }


def install_watchdog_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "watchdog_api_installed", False):
        return app
    app.state.watchdog_api_installed = True

    @app.get("/api/v1/system/watchdog")
    async def watchdog_status() -> dict[str, Any]:
        return build_watchdog_status(app.state.orchestrator.snapshot())

    return app
