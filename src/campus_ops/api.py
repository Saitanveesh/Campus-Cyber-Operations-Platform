from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from campus_ops.control import EnrolledEndpoint
from campus_ops.evidence import sha256_file
from campus_ops.models import Event, EventKind
from campus_ops.orchestrator import Orchestrator


class EndpointEnrollRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    platform: Literal["windows", "linux", "other"] = "other"
    allow_rdp: bool = False
    allow_ssh: bool = False


class EndpointConnectRequest(BaseModel):
    protocol: Literal["rdp", "ssh"]


class IncidentActionRequest(BaseModel):
    action: Literal["acknowledge", "close", "reopen"]


class VoiceMuteRequest(BaseModel):
    seconds: int = Field(default=300, ge=1, le=86400)


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

    @app.post("/api/v1/live/incidents/{incident_id}/action")
    async def incident_action(
        incident_id: str,
        request: IncidentActionRequest,
    ) -> dict[str, object]:
        if orch.session_id is None:
            raise HTTPException(status_code=409, detail="no active session")
        current = orch.state.get_incident(incident_id)
        if not current:
            raise HTTPException(status_code=404, detail="incident not found")
        status_by_action = {
            "acknowledge": "ACKNOWLEDGED",
            "close": "CLOSED",
            "reopen": "OPEN",
        }
        status = status_by_action[request.action]
        updated = orch.state.update_incident(incident_id, status=status)
        await orch.bus.publish(
            Event(
                source="local-console",
                kind=EventKind.ACTION,
                session_id=orch.session_id,
                payload={
                    "action": f"INCIDENT_{request.action.upper()}",
                    "incident_id": incident_id,
                    "status": status,
                    "message": f"Incident {request.action}d",
                    "voice": f"Incident {request.action}d.",
                },
            )
        )
        return {"incident": updated}

    @app.post("/api/v1/live/incidents/{incident_id}/export")
    async def export_incident(incident_id: str) -> dict[str, object]:
        if orch.session_id is None:
            raise HTTPException(status_code=409, detail="no active session")
        try:
            result = await asyncio.to_thread(orch.evidence.export_incident, incident_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc
        await orch.bus.publish(
            Event(
                source="local-console",
                kind=EventKind.ACTION,
                session_id=orch.session_id,
                payload={
                    "action": "INCIDENT_EXPORTED",
                    "incident_id": incident_id,
                    "bundle_sha256": result["sha256"],
                    "message": "Incident evidence bundle exported",
                    "voice": "Incident evidence bundle exported.",
                },
            )
        )
        return {"bundle": result}

    @app.get("/api/v1/live/events")
    async def live_events(limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "events": live["events"][:limit]}

    @app.get("/api/v1/live/packets")
    async def live_packets(limit: int = Query(default=100, ge=1, le=300)) -> dict[str, object]:
        live = orch.state.snapshot()
        return {"session_id": live["session_id"], "packets": live["packet_feed"][:limit]}

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
            "voice": orch.voice.status(),
        }

    @app.get("/api/v1/system/tools")
    async def system_tools() -> dict[str, object]:
        return {"tools": orch.tools.statuses}

    @app.get("/api/v1/system/voice")
    async def voice_status() -> dict[str, object]:
        return orch.voice.status()

    @app.post("/api/v1/system/voice/mute")
    async def voice_mute(request: VoiceMuteRequest) -> dict[str, object]:
        orch.voice.mute_for(request.seconds)
        return orch.voice.status()

    @app.post("/api/v1/system/voice/unmute")
    async def voice_unmute() -> dict[str, object]:
        orch.voice.unmute()
        await orch.bus.publish(
            Event(
                source="local-console",
                kind=EventKind.ACTION,
                session_id=orch.session_id,
                payload={
                    "action": "VOICE_UNMUTED",
                    "message": "Voice notifications enabled",
                    "voice": "Voice notifications enabled.",
                },
            )
        )
        return orch.voice.status()

    @app.get("/api/v1/endpoints")
    async def endpoints() -> dict[str, object]:
        return {
            "endpoints": orch.control.list(),
            "control_scope": "EXPLICITLY_ENROLLED_ONLY",
        }

    @app.post("/api/v1/endpoints")
    async def enroll_endpoint(request: EndpointEnrollRequest) -> dict[str, object]:
        endpoint = EnrolledEndpoint(**request.model_dump())
        return {"endpoint": orch.control.enroll(endpoint)}

    @app.delete("/api/v1/endpoints/{endpoint_id}")
    async def remove_endpoint(endpoint_id: str) -> dict[str, object]:
        if not orch.control.remove(endpoint_id):
            raise HTTPException(status_code=404, detail="endpoint not enrolled")
        return {"removed": endpoint_id}

    @app.post("/api/v1/endpoints/{endpoint_id}/connect")
    async def connect_endpoint(
        endpoint_id: str,
        request: EndpointConnectRequest,
    ) -> dict[str, object]:
        try:
            return await orch.control.connect(endpoint_id, request.protocol)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/api/v1/files/status")
    async def file_status() -> dict[str, object]:
        return {
            "staging": str(orch.malware.staging),
            "yara_rules": str(orch.malware.rules),
            "evidence_pcap": str(orch.forensic_capture.root),
            "incident_bundles": str(orch.evidence.root),
        }

    @app.get("/api/v1/evidence/pcap")
    async def evidence_pcap() -> dict[str, object]:
        root = orch.forensic_capture.root
        files = []
        for path in sorted(root.glob("*.pcapng"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append(
                {
                    "name": path.name,
                    "size": stat.st_size,
                    "modified_ns": stat.st_mtime_ns,
                }
            )
        return {"root": str(root), "files": files[:100]}

    @app.get("/api/v1/evidence/incidents")
    async def evidence_incidents() -> dict[str, object]:
        root = orch.evidence.root
        files = []
        for path in sorted(root.glob("incident-*.zip"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                stat = path.stat()
                digest = await asyncio.to_thread(sha256_file, path)
            except OSError:
                continue
            files.append(
                {
                    "name": path.name,
                    "size": stat.st_size,
                    "sha256": digest,
                    "modified_ns": stat.st_mtime_ns,
                }
            )
        return {"root": str(root), "files": files[:100]}

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
