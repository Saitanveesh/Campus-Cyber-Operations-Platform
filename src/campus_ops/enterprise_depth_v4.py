from __future__ import annotations

import ipaddress
import os
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin
from campus_ops.depth_engines import engine_suite
from campus_ops.depth_engines_v2 import depth_engines_v2


def _live(app: FastAPI) -> dict[str, Any]:
    snap = app.state.orchestrator.snapshot()
    live = snap.get("live")
    return live if isinstance(live, dict) else {}


def _flows(app: FastAPI) -> list[dict[str, Any]]:
    return [row for row in _live(app).get("flows", []) if isinstance(row, dict)]


def _events(app: FastAPI) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("events", "alerts", "incidents", "packet_feed"):
        rows = _live(app).get(key)
        if isinstance(rows, list):
            out.extend(row for row in rows if isinstance(row, dict))
    return out


def _ends(flow: dict[str, Any]) -> tuple[str, str]:
    return (
        str(flow.get("src_ip") or flow.get("source") or flow.get("src") or "").strip(),
        str(flow.get("dst_ip") or flow.get("destination") or flow.get("dst") or "").strip(),
    )


def _valid_host(value: object) -> str | None:
    text = str(value or "").strip().split("%", 1)[0]
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text if len(text) <= 255 else None
    if addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr)


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("payload")
    return value if isinstance(value, dict) else {}


def _severity_weight(value: object) -> int:
    weights = {"INFO": 3, "LOW": 8, "MEDIUM": 18, "HIGH": 32, "CRITICAL": 45}
    return weights.get(str(value or "INFO").upper(), 3)


@dataclass
class InfrastructureMemory:
    session_id: str | None = None
    observations: int = 0
    gateways: Counter[str] = field(default_factory=Counter)
    dns: Counter[str] = field(default_factory=Counter)
    dhcp: Counter[str] = field(default_factory=Counter)

    def update(self, app: FastAPI) -> dict[str, Any]:
        session = str(app.state.orchestrator.session_id)
        if session != self.session_id:
            self.session_id = session
            self.observations = 0
            self.gateways.clear()
            self.dns.clear()
            self.dhcp.clear()

        current_gateway: Counter[str] = Counter()
        current_dns: Counter[str] = Counter()
        current_dhcp: Counter[str] = Counter()
        for row in _events(app):
            payload = _payload(row)
            text = " ".join(
                str(payload.get(key) or "")
                for key in ("type", "protocol", "message", "summary")
            ).upper()
            if "DHCP" in text:
                value = _valid_host(
                    payload.get("server_ip")
                    or payload.get("dhcp_server")
                    or payload.get("src_ip")
                )
                if value:
                    current_dhcp[value] += 1
            if "DNS" in text:
                value = _valid_host(
                    payload.get("dns_server")
                    or payload.get("server_ip")
                    or payload.get("dst_ip")
                )
                if value:
                    current_dns[value] += 1
            if "GATEWAY" in text or "ROUTER ADVERT" in text:
                value = _valid_host(
                    payload.get("gateway")
                    or payload.get("router")
                    or payload.get("src_ip")
                )
                if value:
                    current_gateway[value] += 1

        old_gateways = set(self.gateways)
        old_dns = set(self.dns)
        old_dhcp = set(self.dhcp)
        self.gateways.update(current_gateway)
        self.dns.update(current_dns)
        self.dhcp.update(current_dhcp)
        self.observations += 1
        learning = self.observations <= 2
        return {
            "engine": "INFRASTRUCTURE_BASELINE_MEMORY",
            "state": "LEARNING" if learning else "ACTIVE",
            "gateway_changes": [] if learning else sorted(set(current_gateway) - old_gateways),
            "new_dns_servers": [] if learning else sorted(set(current_dns) - old_dns),
            "new_dhcp_servers": [] if learning else sorted(set(current_dhcp) - old_dhcp),
            "known_gateways": self.gateways.most_common(20),
            "known_dns": self.dns.most_common(20),
            "known_dhcp": self.dhcp.most_common(20),
            "truth_note": (
                "Changes are session-baseline deviations and require infrastructure validation "
                "before escalation."
            ),
        }


def sensor_trust(app: FastAPI) -> dict[str, Any]:
    live = _live(app)
    capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
    workers = live.get("workers") if isinstance(live.get("workers"), list) else []
    score = 100
    reasons: list[str] = []
    state = str(capture.get("state") or "UNKNOWN").upper()
    if state not in {"ACTIVE", "RUNNING", "READY"}:
        score -= 45
        reasons.append("packet-capture-not-active")
    if not live.get("flows"):
        score -= 20
        reasons.append("no-flow-evidence")
    if not live.get("assets"):
        score -= 10
        reasons.append("no-asset-evidence")

    failed = 0
    degraded = 0
    for row in workers:
        if not isinstance(row, dict):
            continue
        worker_state = str(row.get("state") or row.get("status") or "").upper()
        failed += int(worker_state in {"FAILED", "ERROR", "STOPPED"})
        degraded += int(worker_state == "DEGRADED")
    score -= min(30, failed * 15 + degraded * 5)
    score = max(0, score)
    return {
        "engine": "SENSOR_TRUST",
        "score": score,
        "state": "TRUSTED" if score >= 80 else ("DEGRADED" if score >= 45 else "LOW_VISIBILITY"),
        "failed_workers": failed,
        "degraded_workers": degraded,
        "reasons": reasons,
        "truth_note": "Sensor trust measures telemetry reliability, not security posture.",
    }


def risk_propagation(app: FastAPI) -> dict[str, Any]:
    crown = {
        item.strip()
        for item in os.environ.get("CAMPUS_OPS_CROWN_JEWELS", "").split(",")
        if item.strip()
    }
    adjacency: dict[str, set[str]] = defaultdict(set)
    for flow in _flows(app):
        src, dst = _ends(flow)
        if src and dst:
            adjacency[src].add(dst)
            adjacency[dst].add(src)

    base: Counter[str] = Counter()
    for row in _events(app):
        payload = _payload(row)
        severity = _severity_weight(row.get("severity") or payload.get("severity"))
        for key in ("src_ip", "dst_ip", "ip", "target", "host"):
            value = _valid_host(payload.get(key) or row.get(key))
            if value:
                base[value] += severity

    results: list[dict[str, Any]] = []
    for host, direct_score in base.items():
        visited = {host}
        queue = deque([(host, 0)])
        crown_reach: list[dict[str, Any]] = []
        exposure = direct_score
        while queue:
            node, depth = queue.popleft()
            if depth >= 3:
                continue
            for peer in adjacency.get(node, set()):
                if peer in visited:
                    continue
                visited.add(peer)
                next_depth = depth + 1
                queue.append((peer, next_depth))
                exposure += max(1, int(direct_score * (0.35**next_depth)))
                if peer in crown:
                    crown_reach.append({"asset": peer, "hops": next_depth})
        results.append(
            {
                "target": host,
                "direct_risk": min(100, direct_score),
                "propagated_risk": min(100, exposure),
                "reachable_nodes": len(visited) - 1,
                "crown_jewel_paths": crown_reach[:20],
            }
        )
    results.sort(
        key=lambda item: (item["propagated_risk"], len(item["crown_jewel_paths"])),
        reverse=True,
    )
    return {
        "engine": "RISK_PROPAGATION",
        "state": "OBSERVED" if results else "NO_RISK_SIGNALS",
        "findings": results[:100],
        "truth_note": "Propagation reflects observed communication reach, not exploitability.",
    }


def attack_chain(app: FastAPI) -> dict[str, Any]:
    techniques: dict[str, set[str]] = defaultdict(set)
    for row in _events(app):
        payload = _payload(row)
        text = " ".join(
            str(value)
            for value in [row.get("title"), row.get("summary"), row.get("source"), *payload.values()]
        ).upper()
        target = _valid_host(
            payload.get("src_ip")
            or payload.get("host")
            or payload.get("target")
            or payload.get("dst_ip")
        )
        if not target:
            continue
        if "SCAN" in text or "RECON" in text:
            techniques[target].add("TA0043 Reconnaissance")
        if any(value in text for value in ("RDP", "SMB", "WINRM", "SSH FANOUT", "LATERAL")):
            techniques[target].add("TA0008 Lateral Movement")
        if any(value in text for value in ("POWERSHELL", "SCRIPT", "COMMAND")):
            techniques[target].add("TA0002 Execution")
        if any(value in text for value in ("PERSIST", "RUNONCE", "SCHEDULED TASK")):
            techniques[target].add("TA0003 Persistence")
        if any(value in text for value in ("IOC", "MALWARE", "YARA")):
            techniques[target].add("TA0005 Defense Evasion / Malicious Artifact Signal")
        if any(value in text for value in ("EXFIL", "EGRESS", "BEACON")):
            techniques[target].add("TA0010 Exfiltration / C2 Signal")

    order = [
        "TA0043 Reconnaissance",
        "TA0002 Execution",
        "TA0003 Persistence",
        "TA0008 Lateral Movement",
        "TA0005 Defense Evasion / Malicious Artifact Signal",
        "TA0010 Exfiltration / C2 Signal",
    ]
    chains: list[dict[str, Any]] = []
    for target, seen in techniques.items():
        sequence = [item for item in order if item in seen]
        if sequence:
            chains.append(
                {
                    "target": target,
                    "technique_count": len(sequence),
                    "chain": sequence,
                    "confidence": min(95, 25 + len(sequence) * 12),
                }
            )
    chains.sort(key=lambda item: (item["technique_count"], item["confidence"]), reverse=True)
    return {
        "engine": "ATTACK_CHAIN_CORRELATION",
        "state": "OBSERVED" if chains else "NO_CHAIN_EVIDENCE",
        "chains": chains[:100],
        "truth_note": "ATT&CK labels are behavior mappings, not attribution or compromise proof.",
    }


def _accumulate_findings(
    evidence: defaultdict[str, dict[str, Any]],
    engine: dict[str, Any],
    fallback_name: str,
) -> None:
    if not isinstance(engine, dict):
        return
    name = str(engine.get("engine") or fallback_name)
    findings = engine.get("findings")
    if not isinstance(findings, list):
        return
    for item in findings:
        if not isinstance(item, dict):
            continue
        target = _valid_host(
            item.get("host") or item.get("source") or item.get("target") or item.get("src")
        )
        if not target:
            continue
        evidence[target]["engines"].add(name)
        evidence[target]["score"] += min(30, int(item.get("score") or 12))
        evidence[target]["reasons"].append(name)


def incident_promotion(app: FastAPI) -> dict[str, Any]:
    v1 = engine_suite(app)
    v2 = depth_engines_v2(app)
    propagation = risk_propagation(app)
    chain = attack_chain(app)
    trust = sensor_trust(app)
    evidence: defaultdict[str, dict[str, Any]] = defaultdict(
        lambda: {"engines": set(), "score": 0, "reasons": []}
    )
    for engine in v1.get("engines", []):
        _accumulate_findings(evidence, engine, "V1")
    for engine in v2.get("engines", []):
        _accumulate_findings(evidence, engine, "V2")
    for item in propagation.get("findings", []):
        target = item.get("target")
        if target:
            evidence[target]["engines"].add("RISK_PROPAGATION")
            evidence[target]["score"] += min(30, int(item.get("propagated_risk") or 0) // 3)
    for item in chain.get("chains", []):
        target = item.get("target")
        if target:
            evidence[target]["engines"].add("ATTACK_CHAIN_CORRELATION")
            evidence[target]["score"] += int(item.get("technique_count") or 0) * 8

    candidates: list[dict[str, Any]] = []
    trust_factor = max(0.35, trust["score"] / 100)
    for target, row in evidence.items():
        independent = len(row["engines"])
        risk = min(100, int(row["score"]) + independent * 8)
        confidence = int(min(100, (25 + independent * 15) * trust_factor))
        if independent < 2 or risk < 45:
            continue
        severity = "CRITICAL" if risk >= 85 and independent >= 4 else (
            "HIGH" if risk >= 65 else "MEDIUM"
        )
        candidates.append(
            {
                "target": target,
                "severity": severity,
                "risk": risk,
                "confidence": confidence,
                "independent_engines": independent,
                "evidence_sources": sorted(row["engines"]),
                "recommended_action": (
                    "CREATE_CASE_AND_TRIAGE"
                    if severity in {"HIGH", "CRITICAL"}
                    else "ANALYST_REVIEW"
                ),
            }
        )
    candidates.sort(
        key=lambda item: (item["risk"], item["confidence"], item["independent_engines"]),
        reverse=True,
    )
    return {
        "engine": "INCIDENT_PROMOTION",
        "state": "CANDIDATES" if candidates else "NO_PROMOTION_CANDIDATES",
        "candidates": candidates[:100],
        "sensor_trust": trust,
        "truth_note": (
            "Promotion candidates require multiple independent engines; no disruptive response "
            "is automatic."
        ),
    }


def depth_v4(app: FastAPI) -> dict[str, Any]:
    infrastructure = app.state.infrastructure_memory.update(app)
    engines = [
        infrastructure,
        sensor_trust(app),
        risk_propagation(app),
        attack_chain(app),
        incident_promotion(app),
    ]
    return {
        "state": "ACTIVE",
        "session_id": app.state.orchestrator.session_id,
        "engine_count": len(engines),
        "engines": engines,
        "contract": "MULTI_SIGNAL_DEFENSIVE_CORRELATION",
    }


def install_enterprise_depth_v4(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_depth_v4_installed", False):
        return app
    app.state.enterprise_depth_v4_installed = True
    app.state.infrastructure_memory = InfrastructureMemory()

    @app.get("/api/v1/system/depth-engines-v4")
    async def system_depth_v4() -> dict[str, Any]:
        return depth_v4(app)

    @app.get("/api/v1/system/incidents/promotion-candidates")
    async def promotion_candidates() -> dict[str, Any]:
        return incident_promotion(app)

    @app.get("/api/v1/admin/depth-engines-v4")
    async def admin_depth_v4(
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return depth_v4(app)

    return app
