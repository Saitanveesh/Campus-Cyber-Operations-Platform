from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn

from campus_ops.api import create_app
from campus_ops.config import DEFAULT_SETTINGS


def _open_console() -> None:
    if os.environ.get("CAMPUS_OPS_NO_BROWSER", "").lower() in {"1", "true", "yes"}:
        return
    webbrowser.open(f"http://{DEFAULT_SETTINGS.host}:{DEFAULT_SETTINGS.port}")


def main() -> None:
    threading.Timer(1.2, _open_console).start()
    uvicorn.run(
        create_app(),
        host=DEFAULT_SETTINGS.host,
        port=DEFAULT_SETTINGS.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
