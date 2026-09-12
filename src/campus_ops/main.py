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
    uvicorn.run(
        build_app(),
        host=DEFAULT_SETTINGS.host,
        port=DEFAULT_SETTINGS.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
