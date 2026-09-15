from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Query

from campus_ops.capabilities import capability_status


PAGES = {
    "overview",
    "network",
    "topology",
    "assets",
    "traffic",
    "security",
    "endpoints",
    "response",
    "evidence",
    "system",
    "history",
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: object) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _rate(bits_per_second: object) -> str:
    value = _number(bits_per_second)
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f} gigabits per second"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f} megabits per second"
    if value >= 1_000:
        return f"{value / 1_000:.1f} kilobits per second"
    return f"{value:.0f} bits per second"


def _open_incidents(live: dict[str, Any]) -> list[dict[str, Any]]:
    incidents = [item for item in _list(live.get("incidents")) if isinstance(item, dict)]
    open_items = [
        item
        for item in incidents
        if str(item.get("status") or "OPEN").upper() != "CLOSED"
    ]
    return sorted(
        open_items,
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("severity") or "INFO").upper(), 0),
            _number(item.get("confidence")),
            str(item.get("last_seen") or ""),
        ),
        reverse=True,
    )


def _incident_detail(incident: dict[str, Any]) -> str:
    title = str(incident.get("title") or "unnamed incident")
    severity = str(incident.get("severity") or "unknown").lower()
    source = str(incident.get("source") or "unknown source")
    confidence = int(_number(incident.get("confidence")))
    alert_count = int(_number(incident.get("alert_count")))
    signal_types = len([item for item in _list(incident.get("alert_types")) if item])
    evidence = _dict(incident.get("latest_evidence"))

    detail = f"{title}, {severity} severity, source {source}, confidence {confidence} percent"
    if signal_types:
        detail += f", with {signal_types} correlated signal type{'s' if signal_types != 1 else ''}"
    elif alert_count:
        detail += f", with {alert_count} retained evidence event{'s' if alert_count != 1 else ''}"
    target = evidence.get("target") or evidence.get("destination") or evidence.get("dst")
    if target and str(target) != source:
        detail += f", targeting {target}"
    fanout = (
        evidence.get("unique_destinations")
        or evidence.get("destination_count")
        or evidence.get("distinct_destinations")
    )
    if fanout:
        detail += f", touching {fanout} destinations"
    return detail


def _incident_summary(live: dict[str, Any], limit: int = 2) -> str:
    incidents = _open_incidents(live)
    if not incidents:
        return "There are no open incidents."
    lead = (
        f"There {'is' if len(incidents) == 1 else 'are'} {len(incidents)} open "
        f"incident{'s' if len(incidents) != 1 else ''}."
    )
    details = "; ".join(_incident_detail(item) for item in incidents[:limit])
    if len(incidents) > limit:
        details += (
            f"; and {len(incidents) - limit} more open "
            f"incident{'s' if len(incidents) - limit != 1 else ''}"
        )
    return f"{lead} Highest priority: {details}."


def _top_flow(live: dict[str, Any]) -> dict[str, Any] | None:
    flows = [item for item in _list(live.get("flows")) if isinstance(item, dict)]
    if not flows:
        return None
    return max(flows, key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))))


def _top_edge(live: dict[str, Any]) -> dict[str, Any] | None:
    edges = [item for item in _list(live.get("topology_edges")) if isinstance(item, dict)]
    if not edges:
        return None
    return max(edges, key=lambda item: (_number(item.get("bps_ewma")), _number(item.get("packets"))))


def _top_risk(metrics: dict[str, Any]) -> dict[str, Any] | None:
    graph = _dict(metrics.get("risk_graph"))
    nodes = [item for item in _list(graph.get("nodes")) if isinstance(item, dict)]
    nodes = [item for item in nodes if _number(item.get("risk")) > 0]
    if not nodes:
        return None
    return max(nodes, key=lambda item: _number(item.get("risk")))


def page_briefing(snapshot: dict[str, Any], view: str) -> str:
    if view not in PAGES:
        raise ValueError(f"unknown console view: {view}")

    live = _dict(snapshot.get("live"))
    capture = _dict(live.get("capture"))
    metrics = _dict(live.get("metrics"))
    network = _dict(snapshot.get("network"))
    workers = _dict(snapshot.get("workers"))
    interface = str(network.get("interface") or "the selected interface")
    capture_state = str(capture.get("state") or "unknown").replace("_", " ").lower()
    assets = [item for item in _list(live.get("assets")) if isinstance(item, dict)]
    flows = [item for item in _list(live.get("flows")) if isinstance(item, dict)]
    edges = [item for item in _list(live.get("topology_edges")) if isinstance(item, dict)]

    if view == "overview":
        return (
            f"Overview. Monitoring {interface}; capture is {capture_state}. "
            f"{len(assets)} assets and {len(flows)} active flows. {_incident_summary(live, limit=1)}"
        )

    if view == "network":
        unhealthy = [
            name
            for name, raw in workers.items()
            if isinstance(raw, dict)
            and not bool(raw.get("optional"))
            and str(raw.get("state") or "").upper() not in {"HEALTHY", "RUNNING"}
        ]
        text = (
            f"Network. {interface}; capture {capture_state}. Receive {_rate(metrics.get('rx_bps'))}, "
            f"transmit {_rate(metrics.get('tx_bps'))}. "
            f"{int(_number(capture.get('packets')))} packets observed."
        )
        if unhealthy:
            text += f" Attention: {', '.join(unhealthy[:3])}."
        return text

    if view == "topology":
        node_ids = {
            str(value)
            for edge in edges
            for value in (edge.get("source"), edge.get("target"))
            if value
        }
        node_ids.update(str(item.get("ip")) for item in assets if item.get("ip"))
        edge = _top_edge(live)
        text = f"Topology. {len(node_ids)} observed nodes and {len(edges)} communication relationships."
        if edge:
            text += (
                f" Busiest visible link: {edge.get('source')} to {edge.get('target')} at "
                f"{_rate(edge.get('bps_ewma'))}."
            )
        return text

    if view == "assets":
        local = sum(
            1
            for asset in assets
            if str(asset.get("classification") or asset.get("role") or "")
            in {"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"}
        )
        public = sum(
            1
            for asset in assets
            if str(asset.get("classification") or asset.get("role") or "") == "PUBLIC_PEER"
        )
        return f"Assets. {len(assets)} observed assets; {local} local or infrastructure, {public} public peers."

    if view == "traffic":
        total_bps = sum(_number(item.get("bps_ewma")) for item in flows)
        total_pps = sum(_number(item.get("pps_ewma")) for item in flows)
        flow = _top_flow(live)
        text = (
            f"Traffic. {len(flows)} active flows at about {_rate(total_bps)} and "
            f"{total_pps:.1f} packets per second."
        )
        if flow:
            text += f" Busiest flow: {flow.get('src')} to {flow.get('dst')}."
        return text

    if view == "security":
        alerts = _list(live.get("alerts"))
        risk = _top_risk(metrics)
        text = f"Security. {_incident_summary(live, limit=1)} {len(alerts)} current alert records."
        if risk:
            text += (
                f" Highest risk entity is {risk.get('id')} at "
                f"{int(_number(risk.get('risk')))} out of 100."
            )
        return text

    if view == "endpoints":
        agents = [item for item in _list(snapshot.get("managed_agents")) if isinstance(item, dict)]
        online = sum(1 for item in agents if str(item.get("status") or "").upper() == "ONLINE")
        enrolled = _list(snapshot.get("enrolled_endpoints"))
        return f"Endpoints. {online} of {len(agents)} managed agents online; {len(enrolled)} remote-console endpoints enrolled."

    if view == "response":
        jobs = [item for item in _list(snapshot.get("response_jobs")) if isinstance(item, dict)]
        queued = sum(1 for item in jobs if str(item.get("status") or "").upper() == "QUEUED")
        active = sum(1 for item in jobs if str(item.get("status") or "").upper() == "CLAIMED")
        failed = sum(
            1
            for item in jobs
            if str(item.get("status") or "").upper() in {"FAILED", "REJECTED"}
        )
        return f"Response. {queued} queued, {active} in progress, {failed} failed or rejected jobs."

    if view == "evidence":
        file_events = [
            item
            for item in _list(live.get("events"))
            if isinstance(item, dict) and _dict(item.get("payload")).get("type") == "FILE_ANALYSIS"
        ]
        return (
            f"Evidence. {int(_number(capture.get('packets')))} packets observed and "
            f"{len(file_events)} file-analysis records."
        )

    if view == "system":
        unhealthy = [
            name
            for name, raw in workers.items()
            if isinstance(raw, dict)
            and not bool(raw.get("optional"))
            and str(raw.get("state") or "").upper() not in {"HEALTHY", "RUNNING"}
        ]
        tools = [item for item in _list(snapshot.get("tools")) if isinstance(item, dict)]
        available_tools = sum(1 for item in tools if bool(item.get("available")))
        capabilities = capability_status(snapshot)
        text = (
            f"System. {len(workers) - len(unhealthy)} of {len(workers)} workers ready. "
            f"{available_tools} of {len(tools)} tools available. "
            f"Capability readiness {capabilities.get('score', 0)} percent."
        )
        if unhealthy:
            text += f" Attention: {', '.join(unhealthy[:3])}."
        return text

    return "History. Stored events are separate from the current live session."


def install_context_assistant(app: FastAPI) -> FastAPI:
    if getattr(app.state, "context_assistant_installed", False):
        return app
    app.state.context_assistant_installed = True

    @app.post("/api/v1/system/assistant/stop")
    async def context_stop() -> dict[str, object]:
        orchestrator = app.state.orchestrator
        await orchestrator.voice.cancel_speech(clear_queue=True)
        return {"stopped": True, "voice": orchestrator.voice.status()}

    @app.post("/api/v1/system/assistant/context/{view}")
    async def context_brief(
        view: str,
        speak: bool = Query(default=True),
    ) -> dict[str, object]:
        if view not in PAGES:
            raise HTTPException(status_code=404, detail="Unknown console view")
        orchestrator = app.state.orchestrator
        snapshot = orchestrator.snapshot()
        text = page_briefing(snapshot, view)
        voice_status = orchestrator.voice.status()
        muted = bool(voice_status.get("muted"))
        backend_ready = bool(voice_status.get("available")) and not muted

        if not speak:
            await orchestrator.voice.cancel_speech(clear_queue=True)
            queued = False
        elif backend_ready:
            queued = await orchestrator.voice.replace_speech(text, priority=18)
        else:
            await orchestrator.voice.cancel_speech(clear_queue=True)
            queued = False

        return {
            "view": view,
            "text": text,
            "queued": bool(queued),
            "muted": muted,
            "speak": speak,
            "voice": orchestrator.voice.status(),
        }

    return app
