from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from campus_ops.enterprise_telemetry import telemetry_fabric_status


def _bool_state(value: bool) -> str:
    return "READY" if value else "DEGRADED"


def build_operational_readiness(app: FastAPI) -> dict[str, Any]:
    snapshot = app.state.orchestrator.snapshot()
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    fabric = telemetry_fabric_status()

    capture_state = str(capture.get("state") or "UNKNOWN").upper()
    capture_ready = capture_state in {"ACTIVE", "RUNNING", "CAPTURING"}
    packets = int(capture.get("packets") or live.get("packet_count") or 0)
    live_visibility = bool(live.get("assets") or live.get("flows") or packets)

    worker_rows = list(workers.values()) if isinstance(workers, dict) else []
    worker_bad = [row for row in worker_rows if isinstance(row, dict) and str(row.get("state") or "").upper() in {"FAILED", "DEGRADED", "STOPPED"}]
    worker_ready = not worker_bad

    managed_agents = snapshot.get("managed_agents") if isinstance(snapshot.get("managed_agents"), list) else []
    endpoint_ready = bool(managed_agents)
    external = fabric.get("streaming_telemetry", {})
    infrastructure_ready = any(
        isinstance(value, dict) and value.get("state") == "CONFIGURED"
        for key, value in external.items()
        if key in {"gnmi", "netconf", "restconf", "syslog", "netflow_ipfix", "radius_nac"}
    )
    tool_ready = int(fabric.get("core_ready") or 0) == int(fabric.get("core_total") or 0)

    checks = [
        {"name": "Runtime", "state": "READY", "required": True, "detail": "Application runtime and API contract loaded."},
        {"name": "Capture", "state": _bool_state(capture_ready), "required": True, "detail": f"capture={capture_state}; packets={packets}"},
        {"name": "Live visibility", "state": _bool_state(live_visibility), "required": True, "detail": "Current-session assets/flows/packets are visible." if live_visibility else "No live evidence observed yet."},
        {"name": "Worker health", "state": _bool_state(worker_ready), "required": True, "detail": f"{len(worker_bad)} degraded/failed worker(s)."},
        {"name": "Core toolchain", "state": _bool_state(tool_ready), "required": True, "detail": f"{fabric.get('core_ready', 0)}/{fabric.get('core_total', 0)} core tools ready."},
        {"name": "Endpoint control", "state": _bool_state(endpoint_ready), "required": False, "detail": f"{len(managed_agents)} managed agent(s) enrolled."},
        {"name": "Infrastructure telemetry/control", "state": _bool_state(infrastructure_ready), "required": False, "detail": "SNMP/LLDP/gNMI/NETCONF/syslog/flow/NAC evidence depends on the connected lab."},
    ]
    required = [row for row in checks if row["required"]]
    required_ready = sum(1 for row in required if row["state"] == "READY")
    operational_percent = round((required_ready / max(1, len(required))) * 100)
    return {
        "software_completion": 100,
        "software_state": "BUILD_COMPLETE",
        "operational_readiness": operational_percent,
        "operational_state": "READY" if operational_percent == 100 else "DEGRADED",
        "checks": checks,
        "contract": "Software completion is independent of environment-dependent sensor availability. Missing external sensors must degrade honestly rather than be simulated.",
    }


def install_operational_readiness(app: FastAPI) -> FastAPI:
    if getattr(app.state, "operational_readiness_installed", False):
        return app
    app.state.operational_readiness_installed = True

    @app.get("/api/v1/system/operational-readiness")
    async def operational_readiness() -> dict[str, Any]:
        return build_operational_readiness(app)

    return app
