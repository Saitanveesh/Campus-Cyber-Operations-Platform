from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn

from campus_ops.config import DEFAULT_SETTINGS
from campus_ops.history_api import install_history_api
from campus_ops.link_state import install_link_state
from campus_ops.path_analysis import install_path_analysis
from campus_ops.sensor_identity import install_sensor_identity_api
from campus_ops.stable_api import create_stable_app
from campus_ops.stable_ui import install_stable_ui
from campus_ops.version_api import install_version_api
from campus_ops.watchdog_api import install_watchdog_api
from campus_ops.windows_orchestrator import WindowsOrchestrator


def _open_console() -> None:
    if os.environ.get("CAMPUS_OPS_NO_BROWSER", "").lower() in {"1", "true", "yes"}:
        return
    webbrowser.open(f"http://{DEFAULT_SETTINGS.host}:{DEFAULT_SETTINGS.port}")


def build_app():
    """Build MON's native Windows single-source runtime."""
    app = create_stable_app(WindowsOrchestrator())
    app = install_link_state(app)
    app = install_version_api(app)
    app = install_path_analysis(app)
    app = install_watchdog_api(app)
    app = install_history_api(app)
    app = install_sensor_identity_api(app)
    app = install_stable_ui(app)
    return app


def main() -> None:
    threading.Timer(1.2, _open_console).start()
    # The release EXE is built with PyInstaller --noconsole. In that mode
    # sys.stdout/sys.stderr can be None, while Uvicorn's default logging
    # formatter calls .isatty() on those streams during startup. Disable
    # Uvicorn's console log configuration for the frozen/direct-launch path;
    # the Windows Service has its own rotating file logger.
    uvicorn.run(
        build_app(),
        host=DEFAULT_SETTINGS.host,
        port=DEFAULT_SETTINGS.port,
        log_level="warning",
        access_log=False,
        log_config=None,
    )


if __name__ == "__main__":
    main()
