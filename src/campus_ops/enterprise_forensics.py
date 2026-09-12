from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Query, Request

from campus_ops.admin_deep import _require_admin


_FIELD_RE = re.compile(r"^([^:\r\n]+):\s?(.*)$")


def parse_sysmon_message(message: str) -> dict[str, str]:
    """Parse the stable `Field: value` portion of a Sysmon event message."""
    fields: dict[str, str] = {}
    for raw_line in str(message or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _FIELD_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower().replace(" ", "_")
        value = match.group(2).strip()
        if key and value:
            fields[key] = value
    return fields


def structured_sysmon(events: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events[: max(1, limit)]:
        fields = parse_sysmon_message(str(event.get("message") or ""))
        rows.append(
            {
                "record_id": event.get("record_id"),
                "event_id": event.get("event_id"),
                "time": event.get("time"),
                "computer": fields.get("computer") or fields.get("computer_name"),
                "user": fields.get("user"),
                "process_id": fields.get("processid") or fields.get("process_id"),
                "parent_process_id": fields.get("parentprocessid") or fields.get("parent_process_id"),
                "image": fields.get("image"),
                "parent_image": fields.get("parentimage") or fields.get("parent_image"),
                "command_line": fields.get("commandline") or fields.get("command_line"),
                "source_ip": fields.get("sourceip") or fields.get("source_ip"),
                "source_port": fields.get("sourceport") or fields.get("source_port"),
                "destination_ip": fields.get("destinationip") or fields.get("destination_ip"),
                "destination_port": fields.get("destinationport") or fields.get("destination_port"),
                "target_filename": fields.get("targetfilename") or fields.get("target_filename"),
                "target_object": fields.get("targetobject") or fields.get("target_object"),
                "hashes": fields.get("hashes"),
                "fields": fields,
            }
        )
    return rows


def _host_from_endpoint(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("[") and "]:" in text:
        return text[1:].split("]:", 1)[0]
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _flow_endpoint(flow: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = str(flow.get(key) or "").strip()
        if value and _is_ip(value):
            return value
    return None


def segmentation_snapshot(app: FastAPI) -> dict[str, Any]:
    orch = app.state.orchestrator
    live = orch.state.snapshot()
    network = orch.get_network_context() or {}
    prefixes = [str(item) for item in network.get("prefixes", [])]
    networks = []
    for raw in prefixes:
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue

    internal_pairs: Counter[str] = Counter()
    external_pairs: Counter[str] = Counter()
    unclassified = 0
    for flow in live.get("flows", []):
        if not isinstance(flow, dict):
            continue
        src = _flow_endpoint(flow, "src_ip", "source", "src")
        dst = _flow_endpoint(flow, "dst_ip", "destination", "dst")
        if not src or not dst:
            unclassified += 1
            continue
        try:
            src_ip = ipaddress.ip_address(src.split("%", 1)[0])
            dst_ip = ipaddress.ip_address(dst.split("%", 1)[0])
        except ValueError:
            unclassified += 1
            continue
        src_local = any(src_ip in subnet for subnet in networks)
        dst_local = any(dst_ip in subnet for subnet in networks)
        key = f"{src}->{dst}"
        if src_local and dst_local:
            internal_pairs[key] += 1
        elif src_local or dst_local:
            external_pairs[key] += 1
        else:
            unclassified += 1

    return {
        "truth_model": "OBSERVED_SUBNET_RELATIONSHIPS_ONLY",
        "vlan_claims": "UNAVAILABLE_WITHOUT_LLDP_SNMP_OR_CONTROLLER_EVIDENCE",
        "prefixes": prefixes,
        "internal_flow_pairs": sum(internal_pairs.values()),
        "external_flow_pairs": sum(external_pairs.values()),
        "unclassified_flows": unclassified,
        "top_internal_pairs": [
            {"pair": pair, "flows": count} for pair, count in internal_pairs.most_common(25)
        ],
        "top_external_pairs": [
            {"pair": pair, "flows": count} for pair, count in external_pairs.most_common(25)
        ],
    }


def _process_matches_target(process: dict[str, Any], target: str) -> bool:
    for conn in process.get("connections", []):
        if not isinstance(conn, dict):
            continue
        remote = _host_from_endpoint(conn.get("remote"))
        local = _host_from_endpoint(conn.get("local"))
        if target in {remote, local}:
            return True
    return False


def build_attack_story(app: FastAPI, target: str) -> dict[str, Any]:
    fusion = getattr(app.state, "enterprise_fusion", None)
    fusion_dossier = fusion.dossier(target) if fusion else {"timeline": [], "risk": 0}
    advanced = getattr(app.state, "advanced_host_engine", None)
    advanced_snapshot = advanced.snapshot() if advanced else {}

    processes = (
        advanced_snapshot.get("process", {}).get("processes", [])
        if isinstance(advanced_snapshot.get("process"), dict)
        else []
    )
    related_processes = [
        row for row in processes if isinstance(row, dict) and _process_matches_target(row, target)
    ][:50]

    sysmon_rows = structured_sysmon(
        advanced_snapshot.get("sysmon_events", [])
        if isinstance(advanced_snapshot.get("sysmon_events"), list)
        else [],
        limit=300,
    )
    related_sysmon = [
        row
        for row in sysmon_rows
        if target in {str(row.get("source_ip") or ""), str(row.get("destination_ip") or "")}
    ][:100]

    timeline = []
    for row in fusion_dossier.get("timeline", []):
        if isinstance(row, dict):
            timeline.append(
                {
                    "time": row.get("timestamp"),
                    "source": row.get("source"),
                    "type": row.get("type") or row.get("kind"),
                    "title": row.get("title"),
                    "severity": row.get("severity"),
                    "evidence_class": row.get("evidence_class"),
                }
            )
    for row in related_sysmon:
        timeline.append(
            {
                "time": row.get("time"),
                "source": "sysmon",
                "type": f"SYSMON_{row.get('event_id')}",
                "title": row.get("image") or row.get("target_filename") or "Sysmon event",
                "severity": "INFO",
                "evidence_class": "SYSMON_EVENT",
            }
        )
    timeline.sort(key=lambda item: str(item.get("time") or ""), reverse=True)

    confidence = min(
        100,
        20
        + 10 * len(set(fusion_dossier.get("evidence_sources", [])))
        + (20 if related_processes else 0)
        + (20 if related_sysmon else 0),
    )
    return {
        "target": target,
        "session_id": app.state.orchestrator.session_id,
        "risk": int(fusion_dossier.get("risk") or 0),
        "confidence": confidence,
        "truth_state": fusion_dossier.get("truth_state", "NO_CURRENT_SESSION_EVIDENCE"),
        "evidence_sources": fusion_dossier.get("evidence_sources", []),
        "asset": fusion_dossier.get("asset"),
        "related_processes": related_processes,
        "related_sysmon": related_sysmon,
        "timeline": timeline[:200],
        "assessment": (
            "CORRELATED_ENDPOINT_AND_NETWORK_EVIDENCE"
            if related_processes or related_sysmon
            else "NETWORK_EVIDENCE_ONLY"
        ),
    }


def evidence_manifest(app: FastAPI, target: str) -> dict[str, Any]:
    story = build_attack_story(app, target)
    body = {
        "schema": "CCOP-EVIDENCE-MANIFEST-1",
        "generated_at": datetime.now(UTC).isoformat(),
        "session_id": app.state.orchestrator.session_id,
        "target": target,
        "story": story,
        "segmentation": segmentation_snapshot(app),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    body["sha256"] = hashlib.sha256(canonical).hexdigest()
    body["integrity_scope"] = "MANIFEST_CONTENT_ONLY"
    return body


def install_enterprise_forensics(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_forensics_installed", False):
        return app
    app.state.enterprise_forensics_installed = True

    @app.get("/api/v1/system/segmentation")
    async def segmentation() -> dict[str, Any]:
        return segmentation_snapshot(app)

    @app.get("/api/v1/admin/sysmon/structured")
    async def sysmon_structured(
        request: Request,
        limit: int = Query(default=200, ge=1, le=1000),
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        advanced = getattr(app.state, "advanced_host_engine", None)
        events = advanced.snapshot().get("sysmon_events", []) if advanced else []
        return {"events": structured_sysmon(events, limit=limit), "count": min(len(events), limit)}

    @app.get("/api/v1/admin/attack-story/{target}")
    async def attack_story(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return build_attack_story(app, target)

    @app.get("/api/v1/admin/evidence-manifest/{target}")
    async def manifest(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return evidence_manifest(app, target)

    return app
