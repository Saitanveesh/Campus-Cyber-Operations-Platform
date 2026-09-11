from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from campus_ops.control import EnrolledEndpoint
from campus_ops.evidence import sha256_file
from campus_ops.models import Event, EventKind
from campus_ops.orchestrator import Orchestrator
from campus_ops.policy import Role


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


class AgentEnrollRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=128)
    platform: Literal["windows", "linux", "other"] = "other"
    host: str = Field(default="", max_length=255)


class AgentHeartbeatRequest(BaseModel):
    host: str = Field(default="", max_length=255)
    version: str = Field(default="", max_length=64)
    telemetry: dict[str, Any] = Field(default_factory=dict)


class AgentJobResultRequest(BaseModel):
    status: Literal["SUCCEEDED", "FAILED", "REJECTED"]
    result: dict[str, Any] = Field(default_factory=dict)


class ResponseActionRequest(BaseModel):
    action: Literal["COLLECT_SNAPSHOT", "STOP_PROCESS", "QUARANTINE_FILE", "BLOCK_REMOTE_IP"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    role: Role = Role.PLATFORM_ADMINISTRATOR
    operator: str = Field(default="local-console", min_length=1, max_length=128)
    incident_id: str | None = Field(default=None, max_length=128)


class ScheduledActionRequest(ResponseActionRequest):
    execute_at: datetime


def _bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing agent authorization")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="invalid agent authorization")
    return token


def create_app(orchestrator: Orchestrator | None = None) -> FastAPI:
    orch = orchestrator or Orchestrator()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await orch.start()
        try:
            yield
        finally:
            await orch.stop()

    app = FastAPI(title="Campus Cyber Operations Platform", version="0.3.0", lifespan=lifespan)
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
                "agents": len(snapshot["managed_agents"]),
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
            "risk_graph": live["metrics"].get("risk_graph", {}),
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
        return {
            "session_id": live["session_id"],
            "incidents": live["incidents"],
            "timeline": live["metrics"].get("attack_timeline", []),
            "risk_graph": live["metrics"].get("risk_graph", {}),
        }

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
                    "message": f"Incident marked {status.lower()}",
                    "voice": f"Incident marked {status.lower()}.",
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

    @app.post("/api/v1/system/voice/test")
    async def voice_test() -> dict[str, object]:
        return await orch.voice.test()

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
        return {"endpoints": orch.control.list()}

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

    @app.get("/api/v1/agents")
    async def agents() -> dict[str, object]:
        return {"agents": orch.agents.list(), "jobs": orch.agents.jobs(limit=200)}

    @app.post("/api/v1/agents/enroll")
    async def enroll_agent(request: AgentEnrollRequest) -> dict[str, object]:
        try:
            agent = orch.agents.enroll(**request.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"agent": agent, "token_notice": "Save the enrollment token; it is returned once."}

    @app.delete("/api/v1/agents/{endpoint_id}")
    async def remove_agent(endpoint_id: str) -> dict[str, object]:
        if not orch.agents.remove(endpoint_id):
            raise HTTPException(status_code=404, detail="agent not enrolled")
        return {"removed": endpoint_id}

    @app.post("/api/v1/agents/{endpoint_id}/heartbeat")
    async def agent_heartbeat(
        endpoint_id: str,
        request: AgentHeartbeatRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        token = _bearer(authorization)
        try:
            agent = orch.agents.heartbeat(
                endpoint_id,
                token,
                host=request.host,
                version=request.version,
                telemetry=request.telemetry,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        await orch.bus.publish(
            Event(
                source="endpoint-agent",
                kind=EventKind.OBSERVATION,
                session_id=orch.session_id,
                evidence_class="AUTHENTICATED_ENDPOINT_AGENT",
                payload={
                    "type": "ENDPOINT_TELEMETRY",
                    "endpoint_id": endpoint_id,
                    "host": request.host,
                    "version": request.version,
                    "cpu_percent": request.telemetry.get("cpu_percent"),
                    "memory_percent": request.telemetry.get("memory_percent"),
                    "disk_percent": request.telemetry.get("disk_percent"),
                },
            )
        )
        return {"agent": agent}

    @app.get("/api/v1/agents/{endpoint_id}/jobs")
    async def agent_jobs(
        endpoint_id: str,
        limit: int = Query(default=10, ge=1, le=25),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        token = _bearer(authorization)
        try:
            jobs = orch.agents.claim_jobs(endpoint_id, token, limit)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {"jobs": jobs}

    @app.post("/api/v1/agents/{endpoint_id}/jobs/{job_id}/result")
    async def agent_job_result(
        endpoint_id: str,
        job_id: str,
        request: AgentJobResultRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        token = _bearer(authorization)
        try:
            job = orch.agents.report_job(
                endpoint_id,
                token,
                job_id,
                request.status,
                request.result,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        await orch.response.record_result(job)
        return {"job": job}

    @app.post("/api/v1/response/{endpoint_id}")
    async def queue_response(endpoint_id: str, request: ResponseActionRequest) -> dict[str, object]:
        try:
            job = await orch.response.queue(
                endpoint_id=endpoint_id,
                action=request.action,
                arguments=request.arguments,
                role=request.role,
                operator=request.operator,
                incident_id=request.incident_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"job": job}

    @app.get("/api/v1/response/jobs")
    async def response_jobs(limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, object]:
        return {"jobs": orch.agents.jobs(limit=limit)}

    @app.post("/api/v1/response/schedule/{endpoint_id}")
    async def schedule_response(
        endpoint_id: str,
        request: ScheduledActionRequest,
    ) -> dict[str, object]:
        try:
            item = orch.scheduler.schedule(
                execute_at=request.execute_at,
                endpoint_id=endpoint_id,
                action=request.action,
                arguments=request.arguments,
                role=request.role,
                operator=request.operator,
                incident_id=request.incident_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"scheduled": item}

    @app.get("/api/v1/response/schedule")
    async def scheduled_actions(limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, object]:
        return {"scheduled": orch.scheduler.list(limit)}

    @app.delete("/api/v1/response/schedule/{schedule_id}")
    async def cancel_scheduled_action(schedule_id: str) -> dict[str, object]:
        if not orch.scheduler.cancel(schedule_id):
            raise HTTPException(status_code=404, detail="scheduled action not found or not pending")
        return {"cancelled": schedule_id}

    @app.get("/api/v1/cyberbit/status")
    async def cyberbit_status() -> dict[str, object]:
        return await asyncio.to_thread(orch.cyberbit.status)

    @app.get("/api/v1/cyberbit/hosts")
    async def cyberbit_hosts() -> dict[str, object]:
        return {"hosts": await asyncio.to_thread(orch.cyberbit.hosts)}

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
            files.append({"name": path.name, "size": stat.st_size, "modified_ns": stat.st_mtime_ns})
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
