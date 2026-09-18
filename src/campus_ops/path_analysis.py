from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from campus_ops.truth import assess_target_truth


def _contains_ip(value: object, target: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_ip(item, target) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_ip(item, target) for item in value)
    return str(value or "").strip() == target


def _target_anomalies(snapshot: dict[str, Any], target: str) -> list[dict[str, Any]]:
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    rows: list[dict[str, Any]] = []
    for alert in live.get("alerts", []):
        if isinstance(alert, dict) and _contains_ip(alert, target):
            rows.append(
                {
                    "kind": "ALERT",
                    "severity": alert.get("severity"),
                    "timestamp": alert.get("timestamp"),
                    "evidence": alert.get("payload") or {},
                }
            )
    for incident in live.get("incidents", []):
        if isinstance(incident, dict) and _contains_ip(incident, target):
            rows.append(
                {
                    "kind": "INCIDENT",
                    "severity": incident.get("severity"),
                    "timestamp": incident.get("last_seen") or incident.get("first_seen"),
                    "evidence": incident.get("latest_evidence") or {},
                }
            )
    return rows[:50]


def build_path_report(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    """Describe only packet-observed communication relationships for one real target."""
    truth = assess_target_truth(snapshot, target)
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    edges = [
        item
        for item in live.get("topology_edges", [])
        if isinstance(item, dict) and str(item.get("evidence") or "") == "TSHARK_PACKET_OBSERVED"
    ]

    if not truth["observed"]:
        return {
            "target": truth["target"],
            "truth": truth,
            "relationships": [],
            "known_boundary": network.get("gateway"),
            "physical_hops_verified": False,
            "physical_hops": [],
            "statement": (
                "Target was not observed in the current TShark capture. "
                "MON will not construct a path for an unseen IP."
            ),
            "claim": "NO_PATH_WITHOUT_PACKET_EVIDENCE",
        }

    relationships: list[dict[str, Any]] = []
    for edge in edges:
        source = str(edge.get("source") or "")
        destination = str(edge.get("target") or "")
        if truth["target"] not in {source, destination}:
            continue
        peer = destination if source == truth["target"] else source
        relationships.append(
            {
                "direction": "OUTBOUND" if source == truth["target"] else "INBOUND",
                "peer": peer,
                "peer_role": edge.get("target_role") if source == truth["target"] else edge.get("source_role"),
                "packets": int(edge.get("packets") or 0),
                "bytes": int(edge.get("bytes") or 0),
                "pps_ewma": edge.get("pps_ewma"),
                "bps_ewma": edge.get("bps_ewma"),
                "protocol": edge.get("last_protocol") or edge.get("last_transport"),
                "application": edge.get("last_application") or edge.get("last_tls_sni") or edge.get("last_dns_query") or edge.get("last_http_host"),
                "destination_port": edge.get("last_dst_port"),
                "first_seen": edge.get("first_seen"),
                "last_seen": edge.get("last_seen"),
                "evidence": "TSHARK_PACKET_OBSERVED",
                "anomalies": _target_anomalies(snapshot, peer),
            }
        )

    relationships.sort(
        key=lambda item: (int(item.get("bytes") or 0), int(item.get("packets") or 0)),
        reverse=True,
    )
    gateway = str(network.get("gateway") or "").strip() or None
    return {
        "target": truth["target"],
        "truth": truth,
        "relationships": relationships[:200],
        "known_boundary": gateway,
        "boundary_meaning": (
            "Configured Windows default gateway for the selected adapter; it is a routing boundary, "
            "not a claimed packet-by-packet physical hop."
            if gateway
            else "No default gateway is currently known for the selected adapter."
        ),
        "physical_hops_verified": False,
        "physical_hops": [],
        "statement": (
            "Every relationship below came from the current TShark packet stream. "
            "MON does not invent switches, routers, endpoints, or hop-by-hop paths."
        ),
        "claim": "CURRENT_SESSION_TSHARK_RELATIONSHIPS_ONLY",
    }


def install_path_analysis(app: FastAPI) -> FastAPI:
    if getattr(app.state, "path_analysis_installed", False):
        return app
    app.state.path_analysis_installed = True

    @app.get("/api/v1/pathspace/{target}")
    async def pathspace_target(target: str) -> dict[str, Any]:
        try:
            report = build_path_report(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not report.get("truth", {}).get("observed"):
            raise HTTPException(status_code=404, detail=report["statement"])
        return report

    @app.get("/api/v1/system/physical-topology-evidence")
    async def physical_topology_evidence() -> dict[str, object]:
        return {
            "links": [],
            "physical_hops_verified": False,
            "statement": (
                "Native Windows MON currently has packet evidence and Windows routing context only; "
                "it does not claim switch/router hop discovery."
            ),
        }

    return app
