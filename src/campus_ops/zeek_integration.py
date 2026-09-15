from __future__ import annotations

from fastapi import FastAPI

from campus_ops.workers.zeek_feed import ZeekFeedWorker


def install_zeek_integration(app: FastAPI) -> FastAPI:
    if getattr(app.state, "zeek_integration_installed", False):
        return app
    app.state.zeek_integration_installed = True
    orchestrator = app.state.orchestrator
    if any(worker.name == "zeek-feed" for worker in orchestrator.workers):
        return app
    worker = ZeekFeedWorker(orchestrator.bus, orchestrator.get_session_id)
    orchestrator.zeek = worker
    insert_at = next(
        (
            index
            for index, existing in enumerate(orchestrator.workers)
            if existing.name == "suricata-feed"
        ),
        len(orchestrator.workers),
    )
    orchestrator.workers.insert(insert_at, worker)
    orchestrator.OPTIONAL_DEGRADED_WORKERS = orchestrator.OPTIONAL_DEGRADED_WORKERS | {
        "zeek-feed"
    }
    return app
