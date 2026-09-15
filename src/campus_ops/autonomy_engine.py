from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI


def _severity_weight(value: object) -> int:
    return {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 65}.get(str(value or "").upper(), 0)


def _confidence_weight(value: object) -> int:
    return {"LOW": 0, "MEDIUM": 10, "HIGH": 20, "VERIFIED": 30, "EVIDENCE_BACKED": 25}.get(
        str(value or "").upper(), 0
    )


def _live(snapshot: dict[str, Any]) -> dict[str, Any]:
    value = snapshot.get("live")
    return value if isinstance(value, dict) else {}


def _managed_ips(snapshot: dict[str, Any]) -> set[str]:
    rows = snapshot.get("managed_agents")
    if not isinstance(rows, list):
        return set()
    out: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("host", "ip", "address"):
            value = str(row.get(key) or "").strip()
            if value:
                out.add(value)
    return out


def build_autonomy_state(app: FastAPI) -> dict[str, Any]:
    """Build governed response recommendations from current-session evidence.

    This engine deliberately separates detection confidence from disruptive action.
    It never treats a single heuristic or open port as sufficient authority to isolate a host.
    """
    fabric = getattr(app.state, "operations_fabric", None)
    if fabric is not None:
        return fabric.snapshot()
    snapshot = app.state.orchestrator.snapshot()
    live = _live(snapshot)
    managed = _managed_ips(snapshot)
    incidents = live.get("incidents") if isinstance(live.get("incidents"), list) else []
    alerts = live.get("alerts") if isinstance(live.get("alerts"), list) else []

    per_target: dict[str, dict[str, Any]] = {}

    def row_for(target: str) -> dict[str, Any]:
        return per_target.setdefault(
            target,
            {
                "target": target,
                "risk": 0,
                "independent_sources": set(),
                "reasons": [],
                "high_confidence_events": 0,
            },
        )

    for item in incidents + alerts:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        target = str(
            item.get("target")
            or item.get("source")
            or evidence.get("source")
            or evidence.get("src_ip")
            or payload.get("src_ip")
            or payload.get("ip")
            or ""
        ).strip()
        if not target or target == "0.0.0.0":
            continue
        row = row_for(target)
        severity = item.get("severity") or payload.get("severity")
        confidence = item.get("confidence") or payload.get("confidence")
        row["risk"] += _severity_weight(severity) + _confidence_weight(confidence)
        source = str(item.get("source") or item.get("engine") or item.get("evidence_class") or "unknown")
        row["independent_sources"].add(source)
        title = str(item.get("title") or payload.get("title") or item.get("type") or "security evidence")
        row["reasons"].append(title)
        if str(confidence or "").upper() in {"HIGH", "VERIFIED", "EVIDENCE_BACKED"}:
            row["high_confidence_events"] += 1

    decisions: list[dict[str, Any]] = []
    automatic_enabled = os.environ.get("CAMPUS_OPS_AUTONOMOUS_CONTAINMENT", "").lower() in {"1", "true", "yes"}

    for target, row in per_target.items():
        independent = len(row["independent_sources"])
        score = min(100, int(row["risk"]) + max(0, independent - 1) * 5)
        enrolled = target in managed
        if score >= 85 and independent >= 3 and row["high_confidence_events"] >= 2:
            recommendation = "ISOLATE"
            gate = "ELIGIBLE" if enrolled else "NO_MANAGED_CONTROL"
        elif score >= 65 and independent >= 2:
            recommendation = "COLLECT_AND_RESTRICT"
            gate = "REVIEW_REQUIRED"
        elif score >= 40:
            recommendation = "INVESTIGATE"
            gate = "OBSERVE"
        else:
            recommendation = "MONITOR"
            gate = "OBSERVE"
        decisions.append(
            {
                "target": target,
                "risk_score": score,
                "independent_sources": independent,
                "high_confidence_events": row["high_confidence_events"],
                "managed": enrolled,
                "recommendation": recommendation,
                "automation_gate": gate,
                "automatic_containment_enabled": automatic_enabled,
                "reasons": row["reasons"][:8],
            }
        )

    decisions.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "state": "ACTIVE",
        "mode": "GOVERNED_AUTONOMY",
        "automatic_containment_enabled": automatic_enabled,
        "decision_count": len(decisions),
        "decisions": decisions[:100],
        "policy": {
            "isolation_threshold": 85,
            "minimum_independent_sources": 3,
            "minimum_high_confidence_events": 2,
            "managed_endpoint_required": True,
            "automatic_rule_promotion": False,
            "rollback_required": True,
        },
        "design_note": (
            "The engine may recommend or authorize response, but disruptive containment is gated by "
            "multi-source evidence and managed-control availability. Detection rules are never auto-promoted "
            "to production without validation."
        ),
    }


def install_autonomy_engine(app: FastAPI) -> FastAPI:
    if getattr(app.state, "autonomy_engine_installed", False):
        return app
    app.state.autonomy_engine_installed = True

    @app.get("/api/v1/system/autonomy")
    async def autonomy_state() -> dict[str, Any]:
        return build_autonomy_state(app)

    return app
