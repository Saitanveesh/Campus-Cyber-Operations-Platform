from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect

from campus_ops.stable_orchestrator import StableOrchestrator


def create_stable_app(orchestrator: StableOrchestrator | None = None) -> FastAPI:
    """Create the stable passive MON API.

    No endpoint-agent control, remote shell, active probe, quarantine, isolation,
    secondary sensor feed, voice or legacy tool-hub routes are mounted here.
    """
    orch = orchestrator or StableOrchestrator()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await orch.start()
        try:
            yield
        finally:
            await orch.stop()

    app = FastAPI(
        title="Campus Cyber Operations Platform",
        version="0.5.0",
        lifespan=lifespan,
    )
    app.state.orchestrator = orch

    @app.get("/api/v1/live/status")
    async def live_status() -> dict[str, object]:
        return orch.snapshot()

    @app.get("/api/v1/live/overview")
    async def live_overview() -> dict[str, object]:
        snapshot = orch.snapshot()
        live = snapshot["live"]
        assert isinstance(live, dict)
        return {
            "session_id": snapshot["session_id"],
            "overall": snapshot["overall"],
            "network": snapshot["network"],
            "capture": live["capture"],
            "metrics": live["metrics"],
            "counts": {
                "assets": len(live["assets"]),
                "flows": len(live["flows"]),
                "edges": len(live["topology_edges"]),
                "alerts": len(live["alerts"]),
                "incidents": len(live["incidents"]),
            },
            "visibility_mode": live["visibility_mode"],
        }

    @app.get("/api/v1/live/network")
    async def live_network() -> dict[str, object]:
        snapshot = orch.snapshot()
        workers = snapshot["workers"]
        assert isinstance(workers, dict)
        return {
            "session_id": snapshot["session_id"],
            "network": snapshot["network"],
            "candidates": snapshot["network_candidates"],
            "worker": workers.get("network-discovery"),
        }

    @app.get("/api/v1/live/assets")
    async def live_assets() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "assets": live["assets"]}

    @app.get("/api/v1/live/flows")
    async def live_flows() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "flows": live["flows"]}

    @app.get("/api/v1/live/topology")
    async def live_topology() -> dict[str, object]:
        live = orch.state.snapshot()
        return {
            "session_id": live["session_id"],
            "visibility_mode": live["visibility_mode"],
            "assets": live["assets"],
            "edges": live["topology_edges"],
        }

    @app.get("/api/v1/live/protocols")
    async def live_protocols() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "protocols": live["protocols"]}

    @app.get("/api/v1/live/performance")
    async def live_performance() -> dict[str, object]:
        live = orch.state.snapshot()
        return {
            "session_id": live["session_id"],
            "metrics": live["metrics"],
            "capture": live["capture"],
        }

    @app.get("/api/v1/live/alerts")
    async def live_alerts() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "alerts": live["alerts"]}

    @app.get("/api/v1/live/incidents")
    async def live_incidents() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "incidents": live["incidents"]}

    @app.get("/api/v1/live/events")
    async def live_events(limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "events": live["events"][:limit]}

    @app.get("/api/v1/live/packets")
    async def live_packets(limit: int = Query(default=100, ge=1, le=300)) -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "packets": live["packet_feed"][:limit]}

    @app.get("/api/v1/system/health")
    async def system_health() -> dict[str, object]:
        snapshot = orch.snapshot()
        return {
            "overall": snapshot["overall"],
            "session_id": snapshot["session_id"],
            "workers": snapshot["workers"],
            "event_bus": snapshot["event_bus"],
            "runtime_profile": snapshot["runtime_profile"],
        }

    @app.websocket("/api/v1/live/ws")
    async def live_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            while True:
                await websocket.send_json(orch.snapshot())
                await asyncio.sleep(1)
        except (WebSocketDisconnect, RuntimeError):
            return

    return app
