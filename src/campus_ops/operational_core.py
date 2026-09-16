from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from campus_ops.investigation import build_investigation
from campus_ops.policy import Role
from campus_ops.truth import assess_target_truth


class IsolationRequest(BaseModel):
    confirm: bool = False
    operator: str = Field(default="local-console", min_length=1, max_length=128)


def _age_seconds(value: object) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - parsed.astimezone(UTC)).total_seconds())


def _management_ip(snapshot: dict[str, Any]) -> str | None:
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    raw = network.get("ipv4")
    values = raw if isinstance(raw, list) else [raw] if raw else []
    for value in values:
        candidate = str(value or "").strip()
        if candidate and candidate != "127.0.0.1":
            return candidate
    return None


def build_investigation_report(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    truth = assess_target_truth(snapshot, target)
    if not truth["observed"]:
        return {
            "target": truth["target"],
            "session_id": snapshot.get("session_id"),
            "truth": truth,
            "assessment": "NOT_OBSERVED",
            "assessment_text": "Target has not been observed in the current monitoring session.",
            "risk": {
                "score": None,
                "assessment": "NOT OBSERVED",
                "reasons": [],
                "claim": "NO_SECURITY_VERDICT_WITHOUT_EVIDENCE",
            },
            "summary": {
                "flow_count": 0,
                "peer_count": 0,
                "alert_count": 0,
                "incident_count": 0,
                "open_incident_count": 0,
                "packets": 0,
                "bytes": 0,
                "observed_bps": 0.0,
                "top_peers": [],
                "top_services": [],
                "top_applications": [],
            },
            "flows": [],
            "topology_edges": [],
            "alerts": [],
            "incidents": [],
            "recent_packets": [],
        }

    report = build_investigation(snapshot, truth["target"])
    risk = report.get("risk") if isinstance(report.get("risk"), dict) else {}
    score = int(risk.get("score") or 0)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    alert_count = int(summary.get("alert_count") or 0)
    open_incidents = int(summary.get("open_incident_count") or 0)

    if score >= 70 or open_incidents > 0:
        assessment = "HIGH_PRIORITY_INVESTIGATION"
        text = "Evidence indicates activity that requires prioritized analyst review."
    elif score >= 20 or alert_count > 0:
        assessment = "ANOMALOUS_ACTIVITY_OBSERVED"
        text = "Current-session evidence contains one or more anomaly indicators."
    elif int(truth.get("evidence_sources") or 0) < 2:
        assessment = "INSUFFICIENT_EVIDENCE"
        text = "The target is observed, but there is not enough evidence for a meaningful assessment."
    else:
        assessment = "OBSERVED_NO_CURRENT_ANOMALY"
        text = "The target is observed and MON has no current anomaly indicator for it."

    risk["assessment"] = assessment.replace("_", " ")
    risk["claim"] = "EVIDENCE_BASED_PRIORITY_NOT_MALICIOUS_OR_SAFE_VERDICT"
    report["risk"] = risk
    report["truth"] = truth
    report["assessment"] = assessment
    report["assessment_text"] = text
    return report


def build_anomaly_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    alerts = [item for item in live.get("alerts", []) if isinstance(item, dict)]
    incidents = [item for item in live.get("incidents", []) if isinstance(item, dict)]
    items: list[dict[str, Any]] = []

    for alert in alerts:
        payload = alert.get("payload") if isinstance(alert.get("payload"), dict) else {}
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        target = (
            evidence.get("source")
            or evidence.get("target")
            or evidence.get("destination")
            or evidence.get("dst")
        )
        items.append(
            {
                "id": alert.get("event_id"),
                "kind": "ALERT",
                "title": payload.get("title") or payload.get("message") or "Observed anomaly",
                "severity": alert.get("severity") or "INFO",
                "confidence": payload.get("confidence"),
                "target": target,
                "evidence_class": alert.get("evidence_class"),
                "evidence": evidence,
                "timestamp": alert.get("timestamp"),
                "claim": "INDICATOR_NOT_ATTACK_VERDICT",
            }
        )

    for incident in incidents:
        if str(incident.get("status") or "OPEN").upper() == "CLOSED":
            continue
        items.append(
            {
                "id": incident.get("id") or incident.get("incident_id"),
                "kind": "INCIDENT",
                "title": incident.get("title") or "Correlated incident",
                "severity": incident.get("severity") or "INFO",
                "confidence": incident.get("confidence"),
                "target": incident.get("source"),
                "evidence_class": "CORRELATED_INCIDENT",
                "evidence": incident.get("latest_evidence") or {},
                "timestamp": incident.get("last_seen") or incident.get("first_seen"),
                "claim": "CORRELATED_EVIDENCE_NOT_AUTOMATIC_MALICIOUS_VERDICT",
            }
        )

    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    items.sort(
        key=lambda item: (
            rank.get(str(item.get("severity") or "INFO").upper(), 0),
            int(item.get("confidence") or 0),
            str(item.get("timestamp") or ""),
        ),
        reverse=True,
    )
    return {
        "session_id": snapshot.get("session_id"),
        "count": len(items),
        "items": items[:200],
        "source": "DETERMINISTIC_MON_WORKERS",
    }


def build_system_diagnostics(snapshot: dict[str, Any]) -> dict[str, Any]:
    problems: list[dict[str, Any]] = []
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    event_bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else None

    if not snapshot.get("session_id"):
        problems.append(
            {
                "id": "no-session",
                "severity": "HIGH",
                "problem": "No active monitoring session",
                "evidence": "Network discovery has not established a stable active interface.",
                "probable_cause": "No eligible routed interface, link loss, or address/route discovery failure.",
                "fix": ["Check the host network connection.", "Run: ip -br addr", "Run: ip route"],
                "verify": ["Confirm a default route exists.", "Confirm /api/v1/live/status has a session_id."],
                "auto_fixable": False,
            }
        )
    elif not network:
        problems.append(
            {
                "id": "network-context-missing",
                "severity": "HIGH",
                "problem": "Session exists without network context",
                "evidence": "session_id is present but network context is empty",
                "probable_cause": "Internal network-discovery state inconsistency.",
                "fix": ["Restart campus-ops.service after recording diagnostics."],
                "verify": ["Confirm network.interface is populated in /api/v1/live/status."],
                "auto_fixable": True,
            }
        )

    state = str(capture.get("state") or "UNKNOWN").upper()
    detail = str(capture.get("detail") or "")
    if state in {"ERROR", "UNAVAILABLE", "CAPTURE_ERROR"}:
        lowered = detail.lower()
        if "permission" in lowered or "operation not permitted" in lowered:
            cause = "Packet capture permissions or Linux capabilities are missing."
            fix = [
                "Run: sudo setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)",
                "Run: sudo systemctl restart campus-ops.service",
            ]
            verify = ["Run: getcap $(command -v dumpcap)", "Confirm capture.state becomes ACTIVE."]
        elif "not found" in lowered or "unavailable" in lowered:
            cause = "TShark/Wireshark capture tooling is unavailable."
            fix = ["Run: sudo apt update && sudo apt install -y tshark", "Restart campus-ops.service."]
            verify = ["Run: tshark --version", "Confirm capture.state becomes ACTIVE."]
        else:
            cause = "The TShark capture process exited or could not open the selected interface."
            fix = ["Inspect: journalctl -u campus-ops.service -n 100 --no-pager", "Verify the selected interface exists and is up."]
            verify = ["Confirm the TShark process PID is present and capture.state is ACTIVE."]
        problems.append(
            {
                "id": "capture-failure",
                "severity": "HIGH",
                "problem": "Packet capture unavailable",
                "evidence": detail or state,
                "probable_cause": cause,
                "fix": fix,
                "verify": verify,
                "auto_fixable": False,
            }
        )

    for name, raw in workers.items():
        if not isinstance(raw, dict):
            continue
        worker_state = str(raw.get("state") or "UNKNOWN").upper()
        if worker_state not in {"FAILED", "DEGRADED"}:
            age = _age_seconds(raw.get("last_heartbeat"))
            if worker_state == "HEALTHY" and age is not None and age > 60:
                worker_state = "STALE"
            else:
                continue
        problems.append(
            {
                "id": f"worker:{name}",
                "severity": "HIGH" if worker_state in {"FAILED", "STALE"} else "MEDIUM",
                "problem": f"{name} worker {worker_state.lower()}",
                "evidence": raw.get("last_error") or raw.get("detail") or raw.get("last_heartbeat"),
                "probable_cause": "Worker-specific processing failure or stalled event consumption.",
                "fix": ["Inspect the worker evidence above.", "Inspect campus-ops.service journal before restarting."],
                "verify": [f"Confirm workers.{name}.state returns HEALTHY and heartbeat advances."],
                "auto_fixable": False,
            }
        )

    dropped = 0
    pressure: list[str] = []
    for name, raw in event_bus.items():
        if not isinstance(raw, dict):
            continue
        dropped += int(raw.get("dropped") or 0)
        queued = int(raw.get("queued") or 0)
        capacity = int(raw.get("capacity") or 0)
        if capacity and queued / capacity >= 0.75:
            pressure.append(f"{name}={queued}/{capacity}")
    if dropped or pressure:
        problems.append(
            {
                "id": "event-pipeline-pressure",
                "severity": "HIGH" if dropped else "MEDIUM",
                "problem": "Event processing pipeline is under pressure",
                "evidence": f"dropped={dropped}; pressure={', '.join(pressure[:8]) or 'none'}",
                "probable_cause": "Consumers are not keeping up with the event rate.",
                "fix": ["Inspect CPU/RAM usage and failed workers.", "Keep only required MON workers enabled."],
                "verify": ["Confirm dropped count stops increasing and queue utilization falls below 75%."],
                "auto_fixable": False,
            }
        )

    return {
        "state": "HEALTHY" if not problems else "ATTENTION",
        "session_id": snapshot.get("session_id"),
        "capture_state": state,
        "problem_count": len(problems),
        "problems": problems,
        "claim": "DETERMINISTIC_DIAGNOSTICS_FROM_OBSERVED_STATE",
    }


def isolation_capability(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    truth = assess_target_truth(snapshot, target)
    reasons: list[str] = []
    agent = truth.get("managed_agent") if isinstance(truth.get("managed_agent"), dict) else None
    platform = str((agent or {}).get("platform") or "").lower()

    if not truth["observed"]:
        reasons.append("target is not observed in the current session")
    if not truth["local_scope"]:
        reasons.append("target is not inside the selected local network scope")
    if not truth["confirmed_local_asset"]:
        reasons.append("target is not a confirmed local asset")
    if truth["is_monitor_host"]:
        reasons.append("MON will not isolate its own monitoring address")
    if truth["is_gateway"]:
        reasons.append("MON will not isolate the active default gateway")
    if agent is None:
        reasons.append("no authenticated endpoint agent provides a control path")
    elif not truth.get("managed_agent_online"):
        reasons.append("endpoint agent is offline; no live authenticated control path")
    elif platform != "windows":
        reasons.append("current endpoint isolation backend supports Windows agents only")

    available = not reasons
    return {
        "target": truth["target"],
        "available": available,
        "control_method": "WINDOWS_FIREWALL_ENDPOINT_AGENT" if available else "NONE",
        "truth": truth,
        "reasons": reasons,
        "claim": "ISOLATION_REQUIRES_CONFIRMED_TARGET_AND_REAL_CONTROL_PATH",
    }


def install_operational_core(app: FastAPI) -> FastAPI:
    """Install backend-only MON truth, investigation, diagnostics and isolation APIs.

    This installer intentionally does not modify the UI and does not alter the capture
    worker. TShark remains the single authoritative packet source.
    """
    if getattr(app.state, "operational_core_installed", False):
        return app
    app.state.operational_core_installed = True

    @app.get("/api/v1/investigate/{target}")
    async def investigate(target: str) -> dict[str, Any]:
        try:
            return build_investigation_report(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/anomalies")
    async def anomalies() -> dict[str, Any]:
        return build_anomaly_summary(app.state.orchestrator.snapshot())

    @app.get("/api/v1/system/diagnostics")
    async def diagnostics() -> dict[str, Any]:
        return build_system_diagnostics(app.state.orchestrator.snapshot())

    @app.get("/api/v1/isolation/{target}")
    async def isolation_status(target: str) -> dict[str, Any]:
        try:
            return isolation_capability(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/isolation/{target}")
    async def isolate(target: str, request: IsolationRequest) -> dict[str, Any]:
        if not request.confirm:
            raise HTTPException(status_code=400, detail="explicit isolation confirmation is required")
        orchestrator = app.state.orchestrator
        try:
            capability = isolation_capability(orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not capability["available"]:
            raise HTTPException(
                status_code=409,
                detail={"state": "ISOLATION_UNAVAILABLE", "reasons": capability["reasons"]},
            )
        agent = capability["truth"]["managed_agent"]
        endpoint_id = str(agent["endpoint_id"])
        management_ip = _management_ip(orchestrator.snapshot())
        if not management_ip:
            raise HTTPException(status_code=409, detail="management address unavailable; isolation refused")
        job = await orchestrator.response.queue(
            endpoint_id=endpoint_id,
            action="ISOLATE_HOST",
            arguments={"management_ip": management_ip},
            role=Role.LAB_ADMINISTRATOR,
            operator=request.operator,
        )
        return {
            "state": "ISOLATION_QUEUED",
            "target": capability["target"],
            "control_method": capability["control_method"],
            "management_ip": management_ip,
            "job": job,
        }

    @app.post("/api/v1/isolation/{target}/restore")
    async def restore(target: str, request: IsolationRequest) -> dict[str, Any]:
        if not request.confirm:
            raise HTTPException(status_code=400, detail="explicit restore confirmation is required")
        orchestrator = app.state.orchestrator
        try:
            capability = isolation_capability(orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not capability["available"]:
            raise HTTPException(
                status_code=409,
                detail={"state": "RESTORE_UNAVAILABLE", "reasons": capability["reasons"]},
            )
        agent = capability["truth"]["managed_agent"]
        job = await orchestrator.response.queue(
            endpoint_id=str(agent["endpoint_id"]),
            action="RESTORE_NETWORK",
            role=Role.LAB_ADMINISTRATOR,
            operator=request.operator,
        )
        return {
            "state": "RESTORE_QUEUED",
            "target": capability["target"],
            "control_method": capability["control_method"],
            "job": job,
        }

    return app
