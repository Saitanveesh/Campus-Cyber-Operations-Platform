from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.admin_deep import _require_admin
from campus_ops.enterprise_detection import command_center
from campus_ops.enterprise_forensics import evidence_manifest
from campus_ops.platform_paths import data_root
from campus_ops.policy import Role


class SoarExecuteRequest(BaseModel):
    playbook: Literal["TRIAGE", "CONTAIN"] = "TRIAGE"
    confirm: bool = False
    reason: str = Field(default="operator-requested", min_length=3, max_length=240)


def _root() -> Path:
    root = data_root()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _payload(row: object) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    value = row.get("payload")
    return value if isinstance(value, dict) else {}


def identity_context(app: FastAPI) -> dict[str, Any]:
    """Build evidence-backed identity context from passive NAC/RADIUS/802.1X telemetry."""
    live = app.state.orchestrator.state.snapshot()
    identities: dict[str, dict[str, Any]] = {}
    sources: set[str] = set()
    rows: list[dict[str, Any]] = []
    for key in ("events", "alerts"):
        value = live.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))

    for row in rows:
        source = str(row.get("source") or "").lower()
        evidence_class = str(row.get("evidence_class") or "").upper()
        payload = _payload(row)
        event_type = str(payload.get("type") or "").upper()
        identity_evidence = (
            "RADIUS" in source
            or "NAC" in source
            or "802.1X" in source
            or "RADIUS" in evidence_class
            or "NAC" in evidence_class
            or "802.1X" in evidence_class
            or event_type in {"RADIUS_ACCOUNTING", "RADIUS_AUTH", "NAC_SESSION", "DOT1X_SESSION"}
        )
        if not identity_evidence:
            continue
        host = str(
            payload.get("ip")
            or payload.get("framed_ip")
            or payload.get("host")
            or payload.get("calling_station_ip")
            or ""
        ).strip()
        mac = str(
            payload.get("mac")
            or payload.get("calling_station_id")
            or payload.get("calling_station_mac")
            or ""
        ).strip()
        username = str(payload.get("username") or payload.get("user_name") or payload.get("user") or "").strip()
        key = host or mac or username
        if not key:
            continue
        sources.add(str(row.get("source") or "unknown"))
        current = identities.setdefault(
            key,
            {
                "key": key,
                "ip": host or None,
                "mac": mac or None,
                "username": username or None,
                "nas": None,
                "switch_port": None,
                "vlan": None,
                "auth_method": None,
                "status": None,
                "last_seen": None,
                "evidence_sources": set(),
            },
        )
        current["ip"] = host or current.get("ip")
        current["mac"] = mac or current.get("mac")
        current["username"] = username or current.get("username")
        current["nas"] = payload.get("nas_ip") or payload.get("nas") or current.get("nas")
        current["switch_port"] = payload.get("port") or payload.get("nas_port_id") or current.get("switch_port")
        current["vlan"] = payload.get("vlan") or payload.get("tunnel_private_group_id") or current.get("vlan")
        current["auth_method"] = payload.get("auth_method") or payload.get("eap_type") or current.get("auth_method")
        current["status"] = payload.get("status") or payload.get("result") or current.get("status")
        current["last_seen"] = row.get("timestamp") or current.get("last_seen")
        current["evidence_sources"].add(str(row.get("source") or "unknown"))

    output = []
    for item in identities.values():
        row = dict(item)
        row["evidence_sources"] = sorted(item["evidence_sources"])
        output.append(row)
    output.sort(key=lambda item: str(item.get("last_seen") or ""), reverse=True)
    return {
        "state": "EVIDENCE_PRESENT" if output else "NO_NAC_RADIUS_EVIDENCE",
        "identities": output,
        "count": len(output),
        "sources": sorted(sources),
        "truth_note": "Identity is reported only when NAC/RADIUS/802.1X evidence is present.",
    }


def identity_for_target(app: FastAPI, target: str) -> dict[str, Any]:
    report = identity_context(app)
    matches = [
        row
        for row in report["identities"]
        if target in {
            str(row.get("key") or ""),
            str(row.get("ip") or ""),
            str(row.get("mac") or ""),
            str(row.get("username") or ""),
        }
    ]
    return {
        "target": target,
        "state": "MATCHED" if matches else "NO_IDENTITY_EVIDENCE",
        "matches": matches,
    }


def _target_agent(app: FastAPI, target: str) -> dict[str, Any] | None:
    for agent in app.state.orchestrator.agents.list():
        if target in {
            str(agent.get("host") or ""),
            str(agent.get("endpoint_id") or ""),
            str(agent.get("name") or ""),
        }:
            return agent
    return None


def soar_plan(app: FastAPI, target: str, playbook: str = "TRIAGE") -> dict[str, Any]:
    center = command_center(app, target)
    agent = _target_agent(app, target)
    risk = int(center.get("risk") or 0)
    confidence = int(center.get("confidence") or 0)
    steps: list[dict[str, Any]] = [
        {
            "order": 1,
            "action": "COLLECT_SNAPSHOT",
            "mode": "AGENT",
            "requires_managed_agent": True,
            "disruptive": False,
            "reason": "preserve current endpoint state before response",
        }
    ]
    if playbook.upper() == "CONTAIN":
        steps.extend(
            [
                {
                    "order": 2,
                    "action": "ISOLATE_HOST",
                    "mode": "AGENT",
                    "requires_managed_agent": True,
                    "disruptive": True,
                    "reason": "operator-requested containment after evidence capture",
                },
                {
                    "order": 3,
                    "action": "RESTORE_NETWORK",
                    "mode": "AGENT",
                    "requires_managed_agent": True,
                    "disruptive": True,
                    "reason": "explicit recovery action; never automatic",
                    "automatic": False,
                },
            ]
        )
    return {
        "target": target,
        "playbook": playbook.upper(),
        "risk": risk,
        "confidence": confidence,
        "managed_agent": agent,
        "executable": bool(agent),
        "steps": steps,
        "guardrails": [
            "local authenticated admin session required",
            "managed agent required for endpoint control",
            "containment requires explicit operator confirmation",
            "restore is never executed automatically",
        ],
    }


async def execute_soar(app: FastAPI, target: str, request: SoarExecuteRequest) -> dict[str, Any]:
    if not request.confirm:
        raise HTTPException(status_code=409, detail="explicit confirmation is required")
    agent = _target_agent(app, target)
    if not agent:
        raise HTTPException(status_code=409, detail="target is not backed by a managed endpoint agent")
    endpoint_id = str(agent["endpoint_id"])
    jobs = []
    snapshot = await app.state.orchestrator.response.queue(
        endpoint_id=endpoint_id,
        action="COLLECT_SNAPSHOT",
        arguments={"reason": request.reason, "playbook": request.playbook},
        role=Role.PLATFORM_ADMINISTRATOR,
        operator="admin-soar",
    )
    jobs.append(snapshot)
    if request.playbook == "CONTAIN":
        isolation = await app.state.orchestrator.response.queue(
            endpoint_id=endpoint_id,
            action="ISOLATE_HOST",
            arguments={"reason": request.reason, "playbook": request.playbook},
            role=Role.PLATFORM_ADMINISTRATOR,
            operator="admin-soar",
        )
        jobs.append(isolation)
    return {
        "target": target,
        "playbook": request.playbook,
        "queued_jobs": jobs,
        "restore_queued": False,
        "note": "Restore remains an explicit separate operator action.",
    }


def export_evidence(app: FastAPI, target: str) -> dict[str, Any]:
    center = command_center(app, target)
    identity = identity_for_target(app, target)
    manifest = evidence_manifest(app, target)
    body = {
        "schema": "CCOP-EVIDENCE-BUNDLE-1",
        "generated_at": _now(),
        "target": target,
        "session_id": app.state.orchestrator.session_id,
        "command_center": center,
        "identity": identity,
        "manifest": manifest,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    safe_target = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in target)[:80]
    case_dir = _root() / "evidence" / str(app.state.orchestrator.session_id or "no-session")
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_dir / f"{safe_target}-{digest[:12]}.json"
    body["bundle_sha256"] = digest
    body["integrity_scope"] = "BUNDLE_CONTENT_EXCLUDING_BUNDLE_SHA256_FIELD"
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(body, indent=2, sort_keys=True, default=str), encoding="utf-8")
    temp.replace(path)
    return {
        "target": target,
        "path": str(path),
        "sha256": digest,
        "bytes": path.stat().st_size,
        "session_id": app.state.orchestrator.session_id,
    }


def resilience_status(app: FastAPI) -> dict[str, Any]:
    snapshot = app.state.orchestrator.snapshot()
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    failed = [name for name, row in workers.items() if isinstance(row, dict) and row.get("state") == "FAILED"]
    degraded = [name for name, row in workers.items() if isinstance(row, dict) and row.get("state") == "DEGRADED"]
    writable = False
    error = None
    probe = _root() / ".write-test"
    try:
        probe.write_text(_now(), encoding="utf-8")
        probe.unlink(missing_ok=True)
        writable = True
    except OSError as exc:
        error = str(exc)
    return {
        "state": "READY" if not failed and writable else "ATTENTION",
        "overall": snapshot.get("overall"),
        "failed_workers": failed,
        "degraded_workers": degraded,
        "storage_writable": writable,
        "storage_error": error,
        "session_id": snapshot.get("session_id"),
        "capture": (snapshot.get("live") or {}).get("capture") if isinstance(snapshot.get("live"), dict) else {},
        "truth_note": "Resilience state reports current runtime health; it does not imply Windows service installation.",
    }


def install_enterprise_operations(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_operations_installed", False):
        return app
    app.state.enterprise_operations_installed = True

    @app.get("/api/v1/system/identity-context")
    async def system_identity_context() -> dict[str, Any]:
        return identity_context(app)

    @app.get("/api/v1/system/resilience")
    async def system_resilience() -> dict[str, Any]:
        return resilience_status(app)

    @app.get("/api/v1/admin/identity/{target}")
    async def admin_identity(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return identity_for_target(app, target)

    @app.get("/api/v1/admin/soar/{target}")
    async def admin_soar_plan(
        target: str,
        request: Request,
        playbook: Literal["TRIAGE", "CONTAIN"] = "TRIAGE",
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return soar_plan(app, target, playbook)

    @app.post("/api/v1/admin/soar/{target}/execute")
    async def admin_soar_execute(
        target: str,
        body: SoarExecuteRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return await execute_soar(app, target, body)

    @app.post("/api/v1/admin/evidence-export/{target}")
    async def admin_evidence_export(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return export_evidence(app, target)

    return app
