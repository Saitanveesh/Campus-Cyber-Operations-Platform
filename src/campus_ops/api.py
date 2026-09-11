from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from campus_ops.orchestrator import Orchestrator


def create_app(orchestrator: Orchestrator | None = None) -> FastAPI:
    orch = orchestrator or Orchestrator()
    app = FastAPI(title="Campus Cyber Operations Platform", version="0.1.0")
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

    @app.get("/api/v1/live/network")
    async def live_network() -> dict[str, object]:
        snapshot = orch.snapshot()
        return {
            "session_id": snapshot["session_id"],
            "network": snapshot["network"],
            "worker": snapshot["workers"]["network-discovery"],
        }

    @app.get("/api/v1/system/tools")
    async def system_tools() -> dict[str, object]:
        return {"tools": orch.tools.statuses}

    ui_path = Path(__file__).parent / "ui" / "index.html"

    @app.get("/", include_in_schema=False)
    async def root() -> FileResponse:
        return FileResponse(ui_path)

    return app
