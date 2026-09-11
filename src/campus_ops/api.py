from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from campus_ops.orchestrator import Orchestrator


def create_app(orchestrator: Orchestrator | None = None) -> FastAPI:
    orch = orchestrator or Orchestrator()
    app = FastAPI(title="Campus Cyber Operations Platform", version="0.2.0")
    app.state.orchestrator = orch

    @app.on_event("startup")
    async def startup() -> None:
        await orch.start()

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await orch.stop()

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
            "worker": workers["network-discovery"],
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
            "claim": "OBSERVED_LIVE_COMMUNICATION_TOPOLOGY",
        }

    @app.get("/api/v1/live/protocols")
    async def live_protocols() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "protocols": live["protocols"]}

    @app.get("/api/v1/live/performance")
    async def live_performance() -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "metrics": live["metrics"], "capture": live["capture"]}

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

    @app.get("/api/v1/history/recent")
    async def history_recent(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, object]:
        return {
            "live_session_id": orch.session_id,
            "source": "HISTORICAL_ONLY",
            "events": orch.history.query_recent(limit),
        }

    @app.get("/api/v1/system/health")
    async def system_health() -> dict[str, object]:
        snapshot = orch.snapshot()
        return {
            "overall": snapshot["overall"],
            "session_id": snapshot["session_id"],
            "workers": snapshot["workers"],
            "event_bus": snapshot["event_bus"],
        }

    @app.get("/api/v1/system/tools")
    async def system_tools() -> dict[str, object]:
        return {"tools": orch.tools.statuses}

    @app.websocket("/api/v1/live/ws")
    async def live_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            while True:
                await websocket.send_json(orch.snapshot())
                await asyncio.sleep(1)
        except (WebSocketDisconnect, RuntimeError):
            return

    ui_path = Path(__file__).parent / "ui" / "index.html"

    @app.get("/", include_in_schema=False)
    async def root() -> FileResponse:
        return FileResponse(ui_path)

    return app
