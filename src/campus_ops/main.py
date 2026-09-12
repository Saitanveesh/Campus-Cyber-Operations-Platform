from __future__ import annotations

import inspect
import os
import threading
import webbrowser
from contextlib import asynccontextmanager

import uvicorn

from campus_ops.advanced_layer import install_advanced_layer
from campus_ops.api import create_app
from campus_ops.config import DEFAULT_SETTINGS
from campus_ops.correlation_fabric import install_correlation_fabric
from campus_ops.depth_engines import install_depth_engines
from campus_ops.depth_engines_v2 import install_depth_engines_v2
from campus_ops.enterprise_cases import install_enterprise_cases
from campus_ops.enterprise_depth_v3 import install_enterprise_depth_v3
from campus_ops.enterprise_detection import install_enterprise_detection
from campus_ops.enterprise_forensics import install_enterprise_forensics
from campus_ops.enterprise_layer import install_enterprise_layer
from campus_ops.enterprise_operations import install_enterprise_operations
from campus_ops.enterprise_soc import install_enterprise_soc
from campus_ops.enterprise_telemetry import install_enterprise_telemetry
from campus_ops.link_state import install_link_state
from campus_ops.network_depth_layer import install_network_depth_layer
from campus_ops.operator_refinement import install_operator_refinement
from campus_ops.red_panel import install_red_panel
from campus_ops.runtime_ui import install_runtime_extensions


def _open_console() -> None:
    if os.environ.get("CAMPUS_OPS_NO_BROWSER", "").lower() in {"1", "true", "yes"}:
        return
    webbrowser.open(f"http://{DEFAULT_SETTINGS.host}:{DEFAULT_SETTINGS.port}")


async def _run_handler(handler) -> None:
    result = handler()
    if inspect.isawaitable(result):
        await result


def build_app():
    app = install_runtime_extensions(create_app())
    startup_handlers = []
    shutdown_handlers = []
    if not hasattr(app, "add_event_handler"):
        def add_event_handler(event_type: str, handler) -> None:
            if event_type == "startup":
                startup_handlers.append(handler)
            elif event_type == "shutdown":
                shutdown_handlers.append(handler)
            else:
                raise ValueError(f"unsupported lifecycle event: {event_type}")
        app.add_event_handler = add_event_handler  # type: ignore[attr-defined]
    app = install_advanced_layer(app)
    app = install_enterprise_layer(app)
    app = install_enterprise_forensics(app)
    app = install_network_depth_layer(app)
    app = install_enterprise_detection(app)
    app = install_depth_engines(app)
    app = install_correlation_fabric(app)
    app = install_depth_engines_v2(app)
    app = install_enterprise_depth_v3(app)
    app = install_enterprise_operations(app)
    app = install_enterprise_cases(app)
    app = install_enterprise_soc(app)
    app = install_operator_refinement(app)
    app = install_enterprise_telemetry(app)
    app = install_link_state(app)
    app = install_red_panel(app)
    if startup_handlers or shutdown_handlers:
        original_lifespan = app.router.lifespan_context
        @asynccontextmanager
        async def combined_lifespan(app_instance):
            async with original_lifespan(app_instance):
                for handler in startup_handlers:
                    await _run_handler(handler)
                try:
                    yield
                finally:
                    for handler in reversed(shutdown_handlers):
                        await _run_handler(handler)
        app.router.lifespan_context = combined_lifespan
    return app


def main() -> None:
    threading.Timer(1.2, _open_console).start()
    uvicorn.run(build_app(), host=DEFAULT_SETTINGS.host, port=DEFAULT_SETTINGS.port, log_level="warning")


if __name__ == "__main__":
    main()
