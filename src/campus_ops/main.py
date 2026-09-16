from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn

from campus_ops.api import create_app
from campus_ops.config import DEFAULT_SETTINGS
from campus_ops.link_state import install_link_state
from campus_ops.operational_core import install_operational_core
from campus_ops.stable_orchestrator import StableOrchestrator
from campus_ops.stable_ui import install_stable_ui
from campus_ops.version_api import install_version_api


def _open_console() -> None:
    if os.environ.get("CAMPUS_OPS_NO_BROWSER", "").lower() in {"1", "true", "yes"}:
        return
    webbrowser.open(f"http://{DEFAULT_SETTINGS.host}:{DEFAULT_SETTINGS.port}")


def build_app():
    """Build the stable monitor-v1 runtime.

    TShark remains the single authoritative packet source. Operational truth,
    investigation, anomaly correlation, diagnostics and isolation APIs are mounted as
    backend-only capabilities; the capture worker and current UI are left unchanged.
    """
    app = create_app(StableOrchestrator())
    app = install_link_state(app)
    app = install_version_api(app)
    app = install_operational_core(app)
    app = install_stable_ui(app)
    return app


def main() -> None:
    threading.Timer(1.2, _open_console).start()
    uvicorn.run(
        build_app(),
        host=DEFAULT_SETTINGS.host,
        port=DEFAULT_SETTINGS.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
