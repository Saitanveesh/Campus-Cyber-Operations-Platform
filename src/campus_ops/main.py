from __future__ import annotations

import uvicorn

from campus_ops.api import create_app
from campus_ops.config import DEFAULT_SETTINGS


def main() -> None:
    uvicorn.run(
        create_app(),
        host=DEFAULT_SETTINGS.host,
        port=DEFAULT_SETTINGS.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
