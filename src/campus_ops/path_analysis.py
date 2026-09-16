from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from campus_ops.operational_core import build_anomaly_summary
from campus_ops.truth import assess_target_truth


def build_path_report(snapshot: dict[str, Any], target: str) -> dict[str, Any]:
    truth = assess_target_truth(snapshot, target)
    live = snapshot.get("live") if isinstance(snapshot.get("live"), dict) else {}
    network = snapshot.get("network") if isinstance(snapshot.get("network"), dict) else {}
    edges = [item for item in live.get("topology_edges", []) if isinstance(item, dict)]
    anomalies = build_anomaly_summary(snapshot).get("items", [])

    if not truth["observed"]:
        return {
            "target": truth["target"],
            "truth": truth,
            "relationships": [],
            "known_boundary": network.get("gateway"),
            "physical_hops_verified": False,
            "physical_hops": [],
            "statement": "Target is not observed in the current session; no communication path can be asserted.",
        }

    relationships: list[dict[str, Any]] = []
    for edge in edges:
        source = str(edge.get("source") or "")
        destination = str(edge.get("target") or "")
        if truth["target"] not in {source, destination}:
            continue
        peer = destination if source == truth["target"] else source
        related_anomalies = [
            item
            for item in anomalies
            if str(item.get("target") or "") in {truth["target"], peer}
        ]
        relationships.append(
            {
                "direction": "OUTBOUND" if source == truth["target"] else "INBOUND",
                "peer": peer,
                "packets": int(edge.get("packets") or 0),
                "bytes": int(edge.get("bytes") or 0),
                "pps_ewma": edge.get("pps_ewma"),
                "bps_ewma": edge.get("bps_ewma"),
                "protocol": edge.get("last_protocol") or edge.get("last_transport"),
                "application": edge.get("last_application"),
                "destination_port": edge.get("last_dst_port"),
                "first_seen": edge.get("first_seen"),
                "last_seen": edge.get("last_seen"),
                "evidence": edge.get("evidence") or "OBSERVED_COMMUNICATION",
                "anomaly_count": len(related_anomalies),
                "anomalies": related_anomalies[:10],
            }
        )

    relationships.sort(
        key=lambda item: (int(item.get("bytes") or 0), int(item.get("packets") or 0)),
        reverse=True,
    )
    gateway = str(network.get("gateway") or "") or None
    return {
        "target": truth["target"],
        "truth": truth,
        "relationships": relationships[:200],
        "known_boundary": gateway,
        "physical_hops_verified": False,
        "physical_hops": [],
        "statement": (
            "MON can assert packet-observed communication relationships and the selected gateway boundary. "
            "Physical switch/router hops are not claimed without infrastructure telemetry."
        ),
        "claim": "COMMUNICATION_PATH_NOT_PHYSICAL_HOP_INFERENCE",
    }


def install_path_analysis(app: FastAPI) -> FastAPI:
    if getattr(app.state, "path_analysis_installed", False):
        return app
    app.state.path_analysis_installed = True

    @app.get("/api/v1/pathspace/{target}")
    async def pathspace_target(target: str) -> dict[str, Any]:
        try:
            return build_path_report(app.state.orchestrator.snapshot(), target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app
