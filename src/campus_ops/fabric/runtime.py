"""Connect export readers, event bus, evidence journal and governed snapshot collection."""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.admin_deep import _require_admin
from campus_ops.linux_host import host_status
from campus_ops.models import EventKind, WorkerState
from campus_ops.platform_paths import data_root
from campus_ops.workers.base import BaseWorker

from .records import fresh, normalize, sensor_event
from .risk import RiskPolicy, decisions
from .store import EvidenceStore
from .tail import JsonTail

EXPORT_TOOLS = ("tetragon", "falco", "wazuh", "opencanary", "hubble")


class ValidationRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    origin: str = Field(min_length=1, max_length=64)
    rule: str = Field(min_length=1, max_length=255)
    window_seconds: int = Field(default=120, ge=1, le=300)


class OperationsFabric(BaseWorker):
    def __init__(self, orch, path: Path | None = None) -> None:
        super().__init__("operations-fabric", orch.bus)
        self.orch = orch
        self.path = path or data_root() / "operations-fabric.db"
        self.store = EvidenceStore(self.path)
        self.closed = False
        self.subscription = None
        self.mode = os.environ.get("CAMPUS_OPS_AUTONOMY_MODE", "observe").lower()
        if self.mode not in {"observe", "investigate"}:
            raise ValueError("autonomy mode must be observe or investigate")
        policy_path = os.environ.get("CAMPUS_OPS_RISK_POLICY")
        self.policy = RiskPolicy(**json.loads(Path(policy_path).read_text())) if policy_path else RiskPolicy()
        self.tails = {
            tool: JsonTail(Path(raw))
            for tool in EXPORT_TOOLS
            if (raw := os.environ.get(f"CAMPUS_OPS_{tool.upper()}_LOG", "").strip())
        }
        self.metrics = {tool: {"accepted": 0, "errors": 0, "last_received": None}
                        for tool in self.tails}
        self.errors = 0
        self.validation_runs: dict[str, dict] = {}

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        if self.closed:
            self.store = EvidenceStore(self.path)
            self.closed = False
        self.subscription = await self.bus.subscribe(self.name)
        await super().start()

    async def stop(self) -> None:
        await super().stop()
        await self.bus.unsubscribe(self.name)
        self.subscription = None
        if not self.closed:
            self.store.close()
            self.closed = True

    def pipeline_healthy(self) -> bool:
        core_ok = all(
            worker.health.state not in {WorkerState.FAILED, WorkerState.DEGRADED}
            for worker in getattr(self.orch, "workers", [])
            if worker.name not in getattr(self.orch, "OPTIONAL_DEGRADED_WORKERS", set())
        )
        return (core_ok and not self.closed and self.health.state == WorkerState.HEALTHY
                and self.errors == 0
                and all(m["errors"] == 0 for m in self.metrics.values())
                and all(row["dropped"] == 0 for row in self.bus.stats().values()))

    def recommendations(self) -> list[dict]:
        if self.closed:
            return []
        return decisions(
            self.store.recent(self.orch.session_id, window=self.policy.window_seconds),
            self.orch.agents.list(), healthy=self.pipeline_healthy(), policy=self.policy,
        )

    def snapshot(self) -> dict:
        rows = self.recommendations()
        return {
            "state": str(self.health.state), "mode": self.mode.upper(),
            "session_id": self.orch.session_id, "automatic_containment_enabled": False,
            "decision_count": len(rows), "decisions": rows, "policy": asdict(self.policy),
            "exports": {tool: {"configured": True, **m} for tool, m in self.metrics.items()},
            "pipeline_healthy": self.pipeline_healthy(), "errors": self.errors,
            "host": host_status(), "storage": "SQLITE", "confidence_is_probability": False,
        }

    async def poll_exports(self) -> None:
        session = self.orch.session_id
        for tool, tail in self.tails.items():
            metric = self.metrics[tool]
            old_errors = tail.errors
            try:
                rows = tail.read(session, limit=50)
                metric["errors"] += tail.errors - old_errors
                for row in rows:
                    event = sensor_event(tool, "local", row, session)
                    if event is None:
                        metric["errors"] += 1
                        continue
                    if not fresh(event.payload["observed_at"]):
                        continue
                    await self.bus.publish(event)
                    metric["accepted"] += 1
                    metric["last_received"] = time.time()
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                metric["errors"] += 1
                self.health.last_error = f"{tool}: {type(exc).__name__}: {exc}"

    def drain(self) -> None:
        if self.subscription is None:
            return
        for _ in range(500):
            try:
                event = self.subscription.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if not self.orch.session_id or event.session_id != self.orch.session_id:
                continue
            if event.kind == EventKind.OBSERVATION and not (
                event.source.startswith("sensor:") or event.source in {"zeek-feed", "suricata-feed"}
            ):
                continue
            record = normalize(event)
            if record:
                self.store.add(record)

    async def investigate(self) -> None:
        rows = self.recommendations()
        self.store.journal("DECISIONS", {"session_id": self.orch.session_id, "decisions": rows})
        if self.mode != "investigate" or not self.pipeline_healthy():
            return
        for row in rows:
            if row["automation_gate"] != "INVESTIGATE_ELIGIBLE":
                continue
            endpoint = row["endpoint_id"]
            # A fixed session/window key bounds retries across process restarts.
            key = f"{self.orch.session_id}:{endpoint}:{int(time.time() // 300)}"
            if not self.store.reserve_investigation(key, row):
                continue
            agent = self.orch.agents.get(endpoint)
            if not agent or agent.get("status") != "ONLINE":
                self.store.journal("INVESTIGATION_SKIPPED", {"key": key, "reason": "endpoint offline"})
                continue
            job = await self.orch.response.queue(
                endpoint_id=endpoint, action="COLLECT_SNAPSHOT",
                operator="operations-fabric", arguments={},
            )
            self.store.journal("INVESTIGATION_QUEUED", {"key": key, "job": job})

    async def run(self) -> None:
        last_decision = 0.0
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            try:
                await self.poll_exports()
                self.drain()
                self.health.state = (WorkerState.DEGRADED if self.errors or any(
                    m["errors"] for m in self.metrics.values()) else WorkerState.HEALTHY)
                if time.monotonic() - last_decision >= 5:
                    await self.investigate()
                    last_decision = time.monotonic()
                self.health.heartbeat("current-session evidence fabric")
            except Exception as exc:  # noqa: BLE001 - isolate ingestion/control failures
                self.errors += 1
                self.health.state = WorkerState.DEGRADED
                self.health.last_error = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(1)

    def start_validation(self, body: ValidationRequest) -> dict:
        if not self.orch.session_id:
            raise ValueError("active session required")
        row = {"run_id": str(uuid4()), **body.model_dump(),
               "session_id": self.orch.session_id, "started_at": time.time()}
        self.store.journal("VALIDATION_STARTED", row)
        self.validation_runs[row["run_id"]] = row
        while len(self.validation_runs) > 100:
            del self.validation_runs[next(iter(self.validation_runs))]
        return self.validation(row["run_id"])

    def validation(self, run_id: str) -> dict:
        run = self.validation_runs[run_id]
        end = run["started_at"] + run["window_seconds"]
        matches = [
            row["record_id"] for row in self.store.recent(run["session_id"])
            if row["kind"] == "ALERT" and row["source_time_known"]
            and row["subject"] == run["subject"] and row["origin"] == run["origin"]
            and row["rule"] == run["rule"] and run["started_at"] <= row["observed_at"] <= end
        ]
        state = ("SESSION_ENDED" if self.orch.session_id != run["session_id"] else
                 "MATCHED_ALERT" if matches else "WINDOW_EXPIRED" if time.time() > end else "WAITING")
        return {**run, "state": state, "matching_evidence": matches,
                "validation_semantics": "TEMPORAL_MATCH_NOT_CAUSAL_PROOF",
                "attack_executed": False, "coverage_measured": False}


def install_operations_fabric(app: FastAPI) -> FastAPI:
    if getattr(app.state, "operations_fabric", None):
        return app
    fabric = OperationsFabric(app.state.orchestrator)
    app.state.operations_fabric = fabric
    app.state.orchestrator.workers.insert(0, fabric)

    @app.get("/api/v1/system/operations-fabric")
    async def fabric_status() -> dict:
        return fabric.snapshot()

    @app.get("/api/v1/system/evidence-graph")
    async def evidence_graph(request: Request, x_campus_admin: str | None = Header(default=None)):
        _require_admin(app, request, x_campus_admin)
        return fabric.store.graph(fabric.orch.session_id)

    @app.post("/api/v1/admin/validation-runs")
    async def start_validation(body: ValidationRequest, request: Request,
                               x_campus_admin: str | None = Header(default=None)):
        _require_admin(app, request, x_campus_admin)
        try:
            return fabric.start_validation(body)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/v1/admin/validation-runs/{run_id}")
    async def get_validation(run_id: str, request: Request,
                             x_campus_admin: str | None = Header(default=None)):
        _require_admin(app, request, x_campus_admin)
        if run_id not in fabric.validation_runs:
            raise HTTPException(404, "validation run not found")
        return fabric.validation(run_id)

    return app
