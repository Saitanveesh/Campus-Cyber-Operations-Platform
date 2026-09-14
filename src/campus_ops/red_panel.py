from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from fastapi import FastAPI, Header, Request

from campus_ops.admin_deep import _require_admin

_ADMIN_PORTS = {
    22: "SSH",
    23: "TELNET",
    3389: "RDP",
    445: "SMB",
    5985: "WINRM",
    5986: "WINRM_TLS",
    5900: "VNC",
}

_HIGH_VALUE_PORTS = {
    22: "REMOTE_SHELL",
    23: "LEGACY_REMOTE_SHELL",
    53: "DNS",
    80: "HTTP",
    88: "KERBEROS",
    135: "RPC",
    139: "NETBIOS",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    5985: "WINRM",
    5986: "WINRM_TLS",
    6379: "REDIS",
    8080: "HTTP_ALT",
    8443: "HTTPS_ALT",
}


def _target_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def _flow_port(flow: dict[str, Any], target: str) -> tuple[int | None, str | None]:
    src = str(flow.get("src") or flow.get("src_ip") or "")
    dst = str(flow.get("dst") or flow.get("dst_ip") or "")
    if dst == target:
        port = flow.get("dst_port") or flow.get("dport")
        return (int(port) if str(port).isdigit() else None, src or None)
    if src == target:
        port = flow.get("src_port") or flow.get("sport")
        return (int(port) if str(port).isdigit() else None, dst or None)
    return None, None


def _score(*, peer_count: int, admin_services: int, signals: int, managed: bool, flow_count: int) -> int:
    score = 8
    score += min(24, peer_count // 3)
    score += min(26, admin_services * 6)
    score += min(28, signals * 7)
    score += min(10, flow_count // 40)
    if managed:
        score -= 6
    return max(0, min(100, score))


def _confidence(*, flow_count: int, signals: int, exposure_count: int) -> int:
    value = 15
    value += min(40, flow_count // 8)
    value += min(25, signals * 8)
    value += min(20, exposure_count * 2)
    return max(0, min(100, value))


def _purple_team_model(
    exposures: list[dict[str, Any]],
    peer_count: int,
    signals: int,
    managed: bool,
) -> dict[str, Any]:
    ports = {int(item["port"]) for item in exposures if isinstance(item.get("port"), int)}
    rows: list[dict[str, Any]] = []

    def add(technique: str, name: str, evidence: str, telemetry: str) -> None:
        if signals and managed:
            coverage = 85
            detection = "DETECTION_AND_ENDPOINT"
        elif signals:
            coverage = 68
            detection = "DETECTION_PRESENT"
        elif managed:
            coverage = 52
            detection = "ENDPOINT_TELEMETRY_ONLY"
        else:
            coverage = 32
            detection = "NETWORK_TELEMETRY_ONLY"
        rows.append(
            {
                "technique": technique,
                "name": name,
                "evidence": evidence,
                "telemetry": telemetry,
                "detection_state": detection,
                "coverage": None,
                "readiness_heuristic": coverage,
                "validation_state": "NOT_MEASURED",
                "gap": "UNASSESSED",
                "control_state": "ENDPOINT_AND_NETWORK" if managed else "NETWORK_ONLY",
            }
        )

    if 3389 in ports:
        add("T1021.001", "Remote Desktop Protocol", "RDP traffic observed on TCP/3389", "flow + endpoint" if managed else "flow")
    if 445 in ports:
        add("T1021.002", "SMB / Windows Admin Shares", "SMB traffic observed on TCP/445", "flow + endpoint" if managed else "flow")
    if 22 in ports:
        add("T1021.004", "SSH", "SSH traffic observed on TCP/22", "flow + endpoint" if managed else "flow")
    if {5985, 5986} & ports:
        add("T1021.006", "Windows Remote Management", "WinRM traffic observed", "flow + endpoint" if managed else "flow")
    if peer_count >= 12:
        add("T1018", "Remote System Discovery", f"Target has {peer_count} observed peers", "network relationships")
    if len(exposures) >= 8:
        add("T1046", "Network Service Discovery", f"{len(exposures)} service classes observed", "service/flow metadata")

    if not rows:
        rows.append(
            {
                "technique": "BASELINE",
                "name": "No ATT&CK behavior candidate",
                "evidence": "Current telemetry does not support a specific technique mapping.",
                "telemetry": "current session",
                "detection_state": "NO_CANDIDATE",
                "coverage": None,
                "readiness_heuristic": 0,
                "validation_state": "NOT_MEASURED",
                "gap": "UNASSESSED",
                "control_state": "UNASSESSED",
            }
        )

    scored = [row["readiness_heuristic"] for row in rows if row["technique"] != "BASELINE"]
    coverage_score = round(sum(scored) / len(scored)) if scored else 0
    exercises = [
        "Validate that authorized remote-service activity produces expected network and endpoint telemetry.",
        "Confirm east-west segmentation policy for the target and its highest-frequency peers.",
        "Capture a managed-endpoint snapshot before and after a controlled lab exercise.",
        "Verify alert-to-case correlation and analyst evidence retention for the exercise.",
    ]
    if managed:
        exercises.append("Validate isolate and restore workflow with explicit operator confirmation in the lab.")

    return {
        "coverage_score": None,
        "readiness_heuristic": coverage_score,
        "validation_state": "NOT_MEASURED",
        "detection_gap_score": None,
        "techniques": rows,
        "exercise_queue": exercises,
        "truth_note": "Technique rows are evidence-backed validation candidates, not proof that the technique was executed maliciously.",
    }


def build_red_panel(app: FastAPI, target: str) -> dict[str, Any]:
    target = _target_ip(target)
    live = app.state.orchestrator.state.snapshot()
    assets = [row for row in live.get("assets", []) if isinstance(row, dict)]
    flows = [row for row in live.get("flows", []) if isinstance(row, dict)]
    alerts = [row for row in live.get("alerts", []) if isinstance(row, dict)]
    incidents = [row for row in live.get("incidents", []) if isinstance(row, dict)]

    asset = next((row for row in assets if str(row.get("ip") or row.get("id") or "") == target), None)
    target_flows = [
        row
        for row in flows
        if target
        in {
            str(row.get("src") or row.get("src_ip") or ""),
            str(row.get("dst") or row.get("dst_ip") or ""),
        }
    ]
    ports: Counter[int] = Counter()
    peers: Counter[str] = Counter()
    for flow in target_flows:
        port, peer = _flow_port(flow, target)
        if port is not None:
            ports[port] += 1
        if peer:
            peers[peer] += 1

    signal_rows: list[dict[str, Any]] = []
    for row in [*alerts, *incidents]:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        text = " ".join(
            str(value)
            for value in [row.get("title"), row.get("summary"), row.get("source"), *payload.values()]
        )
        if target in text:
            signal_rows.append(row)

    exposures = []
    for port, count in ports.most_common(30):
        exposures.append(
            {
                "port": port,
                "service_hint": _HIGH_VALUE_PORTS.get(port, _ADMIN_PORTS.get(port, "OBSERVED_SERVICE")),
                "flow_count": count,
                "administrative": port in _ADMIN_PORTS,
                "high_value": port in _HIGH_VALUE_PORTS,
            }
        )

    managed = False
    try:
        managed = any(
            str(row.get("host") or row.get("endpoint_id") or "") == target
            for row in app.state.orchestrator.agents.list()
        )
    except Exception:
        managed = False

    admin_count = sum(1 for item in exposures if item["administrative"])
    risk = _score(
        peer_count=len(peers),
        admin_services=admin_count,
        signals=len(signal_rows),
        managed=managed,
        flow_count=len(target_flows),
    )
    confidence = _confidence(
        flow_count=len(target_flows),
        signals=len(signal_rows),
        exposure_count=len(exposures),
    )
    blast_radius = min(100, int((min(len(peers), 60) / 60) * 70 + min(admin_count, 5) * 6))

    hypotheses: list[dict[str, str]] = []
    if admin_count:
        hypotheses.append(
            {
                "area": "REMOTE_ACCESS",
                "finding": f"{admin_count} administrative service class(es) are visible in observed traffic; validate authentication and network policy.",
            }
        )
    if len(peers) >= 12:
        hypotheses.append(
            {
                "area": "LATERAL_MOVEMENT",
                "finding": f"Target communicates with {len(peers)} peers; validate whether this fan-out matches its expected role.",
            }
        )
    if signal_rows:
        hypotheses.append(
            {
                "area": "DETECTION",
                "finding": f"{len(signal_rows)} current-session security signal(s) reference this target.",
            }
        )
    if any(item["port"] in {445, 3389, 5985, 5986} for item in exposures) and len(peers) >= 8:
        hypotheses.append(
            {
                "area": "BLAST_RADIUS",
                "finding": "Administrative east-west reach plus broad peer fan-out creates a larger containment boundary if the host is compromised.",
            }
        )
    if not hypotheses:
        hypotheses.append(
            {
                "area": "BASELINE",
                "finding": "No strong adversary-emulation hypothesis is supported by current evidence. Start with passive validation.",
            }
        )

    top_peer_nodes = [peer for peer, _ in peers.most_common(12)]
    attack_path = {
        "nodes": [
            {"id": target, "kind": "TARGET", "label": target},
            *[{"id": peer, "kind": "PEER", "label": peer} for peer in top_peer_nodes],
            *[
                {
                    "id": f"svc:{item['port']}",
                    "kind": "SERVICE",
                    "label": f"{item['port']} {item['service_hint']}",
                }
                for item in exposures[:10]
            ],
        ],
        "edges": [
            *[
                {"source": target, "target": peer, "kind": "OBSERVED_RELATIONSHIP"}
                for peer in top_peer_nodes
            ],
            *[
                {
                    "source": target,
                    "target": f"svc:{item['port']}",
                    "kind": "OBSERVED_SERVICE",
                }
                for item in exposures[:10]
            ],
        ],
    }

    validation_plan = [
        {
            "phase": "1",
            "name": "Confirm Identity",
            "action": "Correlate hostname, MAC, user, endpoint-agent and infrastructure context.",
        },
        {
            "phase": "2",
            "name": "Validate Surface",
            "action": "Verify observed services only within explicitly authorized scope.",
        },
        {
            "phase": "3",
            "name": "Trace Reach",
            "action": "Review east-west peers, administrative protocols and segmentation boundaries.",
        },
        {
            "phase": "4",
            "name": "Collect Evidence",
            "action": "Capture packet, process, event and file evidence before disruptive response.",
        },
        {
            "phase": "5",
            "name": "Contain if Required",
            "action": "Use managed-host isolation only after operator confirmation and evidence review.",
        },
    ]

    purple_team = _purple_team_model(exposures, len(peers), len(signal_rows), managed)

    return {
        "target": target,
        "asset": asset,
        "observed_flows": len(target_flows),
        "peer_count": len(peers),
        "top_peers": peers.most_common(20),
        "exposures": exposures,
        "security_signals": len(signal_rows),
        "hypotheses": hypotheses,
        "managed_endpoint": managed,
        "risk_score": risk,
        "confidence": confidence,
        "blast_radius": blast_radius,
        "attack_path": attack_path,
        "validation_plan": validation_plan,
        "purple_team": purple_team,
        "allowed_validation": [
            "Passive evidence pivot",
            "Authorized service verification",
            "Forensic snapshot on managed endpoints",
            "Containment on managed endpoints after operator confirmation",
        ],
        "guardrails": [
            "RED-PANEL is for authorized validation and adversary-emulation planning.",
            "It does not auto-exploit, brute-force credentials, or run destructive actions.",
            "Active probes require explicit operator confirmation and private/authorized scope.",
        ],
    }


def install_red_panel(app: FastAPI) -> FastAPI:
    if getattr(app.state, "red_panel_installed", False):
        return app
    app.state.red_panel_installed = True

    @app.get("/api/v1/admin/red-panel/{target}")
    async def red_panel(
        target: str,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        return build_red_panel(app, target)

    return app
