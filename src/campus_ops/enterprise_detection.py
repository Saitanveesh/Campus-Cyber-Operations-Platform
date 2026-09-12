from __future__ import annotations

import ipaddress
import json
import math
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.enterprise_forensics import build_attack_story, evidence_manifest
from campus_ops.network_depth_layer import build_target_network_dossier


def _live(app: FastAPI) -> dict[str, Any]:
    snapshot = app.state.orchestrator.snapshot()
    live = snapshot.get("live")
    return live if isinstance(live, dict) else {}


def _payload(row: object) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    value = row.get("payload")
    return value if isinstance(value, dict) else {}


def _current_events(app: FastAPI) -> list[dict[str, Any]]:
    live = _live(app)
    rows: list[dict[str, Any]] = []
    for key in ("events", "alerts", "packet_feed"):
        value = live.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    return rows


def _ip(value: object) -> ipaddress._BaseAddress | None:
    text = str(value or "").strip().split("%", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _flow_endpoints(flow: dict[str, Any]) -> tuple[str, str]:
    src = str(flow.get("src_ip") or flow.get("source") or flow.get("src") or "").strip()
    dst = str(flow.get("dst_ip") or flow.get("destination") or flow.get("dst") or "").strip()
    return src, dst


def _load_policy() -> dict[str, Any]:
    raw = os.environ.get("CAMPUS_OPS_SEGMENT_POLICY", "").strip()
    path = os.environ.get("CAMPUS_OPS_SEGMENT_POLICY_FILE", "").strip()
    if path:
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError:
            return {"state": "INVALID", "error": f"cannot read policy file: {path}"}
    if not raw:
        return {"state": "NOT_CONFIGURED", "zones": {}, "allow": []}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"state": "INVALID", "error": f"invalid JSON: {exc}"}
    if not isinstance(parsed, dict):
        return {"state": "INVALID", "error": "policy must be a JSON object"}
    return parsed


def segmentation_policy_report(app: FastAPI) -> dict[str, Any]:
    policy = _load_policy()
    if policy.get("state") in {"INVALID", "NOT_CONFIGURED"}:
        return {
            **policy,
            "violations": [],
            "checked_flows": 0,
            "truth_note": "No segmentation verdict is produced without an explicit policy.",
        }

    raw_zones = policy.get("zones") if isinstance(policy.get("zones"), dict) else {}
    zones: dict[str, list[ipaddress._BaseNetwork]] = {}
    for name, cidrs in raw_zones.items():
        values = cidrs if isinstance(cidrs, list) else [cidrs]
        networks = []
        for raw in values:
            try:
                networks.append(ipaddress.ip_network(str(raw), strict=False))
            except ValueError:
                continue
        if networks:
            zones[str(name)] = networks

    allow_rows = policy.get("allow") if isinstance(policy.get("allow"), list) else []
    allowed = {
        (str(row.get("src")), str(row.get("dst")))
        for row in allow_rows
        if isinstance(row, dict) and row.get("src") and row.get("dst")
    }

    def zone_for(value: str) -> str:
        parsed = _ip(value)
        if parsed is None:
            return "UNKNOWN"
        for zone, networks in zones.items():
            if any(parsed.version == net.version and parsed in net for net in networks):
                return zone
        return "UNMAPPED"

    violations: list[dict[str, Any]] = []
    checked = 0
    for flow in _live(app).get("flows", []):
        if not isinstance(flow, dict):
            continue
        src, dst = _flow_endpoints(flow)
        if not src or not dst:
            continue
        src_zone = zone_for(src)
        dst_zone = zone_for(dst)
        if "UNKNOWN" in {src_zone, dst_zone}:
            continue
        checked += 1
        if src_zone == dst_zone or (src_zone, dst_zone) in allowed or (src_zone, "*") in allowed:
            continue
        if len(violations) < 250:
            violations.append(
                {
                    "src": src,
                    "dst": dst,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "protocol": flow.get("protocol") or flow.get("proto"),
                    "service": flow.get("service") or flow.get("application"),
                    "evidence": "CURRENT_SESSION_FLOW",
                }
            )

    return {
        "state": "ACTIVE",
        "zones": {name: [str(net) for net in nets] for name, nets in zones.items()},
        "allow": sorted([{"src": src, "dst": dst} for src, dst in allowed], key=str),
        "checked_flows": checked,
        "violation_count": len(violations),
        "violations": violations,
        "truth_note": "Violations are evaluated only against operator-supplied zone policy.",
    }


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def dns_tls_anomaly_report(app: FastAPI) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in _current_events(app):
        payload = _payload(row)
        domain = str(payload.get("dns_query") or payload.get("query") or "").strip().lower()
        if domain:
            labels = [item for item in domain.split(".") if item]
            longest = max((len(label) for label in labels), default=0)
            score = 0
            reasons = []
            if len(domain) >= 60:
                score += 25
                reasons.append("long-domain")
            if longest >= 32:
                score += 20
                reasons.append("long-label")
            if len(labels) >= 6:
                score += 15
                reasons.append("deep-subdomain")
            if _entropy(domain.replace(".", "")) >= 4.0 and len(domain) >= 24:
                score += 25
                reasons.append("high-entropy")
            rcode = str(payload.get("rcode_name") or payload.get("rcode") or "").upper()
            if "NXDOMAIN" in rcode or rcode == "3":
                score += 15
                reasons.append("nxdomain")
            key = ("DNS", domain)
            if score >= 25 and key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": "DNS_ANOMALY",
                        "value": domain,
                        "score": min(score, 100),
                        "reasons": reasons,
                        "evidence": "OBSERVED_DNS",
                    }
                )

        sni = str(payload.get("tls_sni") or payload.get("server_name") or payload.get("sni") or "").strip()
        tls_version = str(payload.get("tls_version") or payload.get("version") or "").upper()
        issuer = str(payload.get("certificate_issuer") or payload.get("tls_issuer") or "")
        tls_score = 0
        tls_reasons = []
        if tls_version in {"TLSV1", "TLS1.0", "TLSV1.0", "SSLV3", "SSLV2"}:
            tls_score += 50
            tls_reasons.append("legacy-tls")
        if payload.get("certificate_expired") is True:
            tls_score += 40
            tls_reasons.append("expired-certificate")
        if payload.get("certificate_self_signed") is True:
            tls_score += 25
            tls_reasons.append("self-signed")
        if sni and tls_score:
            key = ("TLS", sni)
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": "TLS_ANOMALY",
                        "value": sni,
                        "issuer": issuer or None,
                        "score": min(tls_score, 100),
                        "reasons": tls_reasons,
                        "evidence": "OBSERVED_TLS",
                    }
                )

    findings.sort(key=lambda item: int(item.get("score") or 0), reverse=True)
    return {
        "state": "OBSERVED" if findings else "NO_CURRENT_ANOMALIES",
        "findings": findings[:200],
        "count": len(findings),
        "truth_note": "Heuristics indicate investigation candidates, not confirmed compromise.",
    }


def sigma_status() -> dict[str, Any]:
    rule_dir = os.environ.get("CAMPUS_OPS_SIGMA_RULE_DIR", "").strip()
    cli = shutil.which("sigma") or shutil.which("sigma-cli") or shutil.which("sigma.exe")
    path = Path(rule_dir) if rule_dir else None
    rule_count = 0
    if path and path.exists():
        rule_count = sum(1 for item in path.rglob("*.yml")) + sum(1 for item in path.rglob("*.yaml"))
    return {
        "cli_available": bool(cli),
        "cli_path": cli,
        "rule_dir": str(path) if path else None,
        "rule_dir_available": bool(path and path.exists()),
        "rule_count": rule_count,
        "state": "READY" if cli and path and path.exists() else "NOT_CONFIGURED",
        "execution_policy": "DETECTION_TRANSLATION_ONLY",
    }


def command_center(app: FastAPI, target: str) -> dict[str, Any]:
    story = build_attack_story(app, target)
    network = build_target_network_dossier(app, target)
    advanced = getattr(app.state, "advanced_host_engine", None)
    host = advanced.snapshot() if advanced else {}
    matching_processes = []
    process_block = host.get("process") if isinstance(host, dict) else {}
    for row in process_block.get("processes", []) if isinstance(process_block, dict) else []:
        if not isinstance(row, dict):
            continue
        for conn in row.get("connections", []):
            if isinstance(conn, dict) and target in str(conn.get("remote") or ""):
                matching_processes.append(row)
                break
    agents = app.state.orchestrator.agents.list()
    managed = [row for row in agents if target in {str(row.get("host") or ""), str(row.get("endpoint_id") or "")}]
    return {
        "target": target,
        "session_id": app.state.orchestrator.session_id,
        "risk": story.get("risk", 0),
        "confidence": story.get("confidence", 0),
        "truth_state": story.get("truth_state"),
        "attack_story": story,
        "network": network,
        "host_process_matches": matching_processes[:100],
        "managed_agents": managed,
        "containment_ready": bool(managed),
        "segmentation_policy": segmentation_policy_report(app),
        "dns_tls_anomalies": dns_tls_anomaly_report(app),
        "sigma": sigma_status(),
        "evidence_manifest": evidence_manifest(app, target),
    }


def install_enterprise_detection(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_detection_installed", False):
        return app
    app.state.enterprise_detection_installed = True

    @app.get("/api/v1/system/segmentation-policy")
    async def segmentation_policy() -> dict[str, Any]:
        return segmentation_policy_report(app)

    @app.get("/api/v1/system/dns-tls-anomalies")
    async def dns_tls_anomalies() -> dict[str, Any]:
        return dns_tls_anomaly_report(app)

    @app.get("/api/v1/system/sigma")
    async def sigma() -> dict[str, Any]:
        return sigma_status()

    @app.get("/api/v1/admin/command-center/{target}")
    async def admin_command_center(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return command_center(app, target)

    return app
