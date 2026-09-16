from __future__ import annotations

import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI

from campus_ops.platform_paths import data_root

IDENTITY_FILE = "sensor.json"


def _default_identity() -> dict[str, Any]:
    return {
        "sensor_id": str(uuid4()),
        "tenant_id": os.environ.get("MON_TENANT_ID", "local"),
        "site_id": os.environ.get("MON_SITE_ID", socket.gethostname()),
        "site_name": os.environ.get("MON_SITE_NAME", socket.gethostname()),
        "created_at": datetime.now(UTC).isoformat(),
    }


def load_identity() -> dict[str, Any]:
    path: Path = data_root() / IDENTITY_FILE
    value: dict[str, Any] | None = None
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("sensor_id"):
                value = raw
        except (OSError, ValueError, json.JSONDecodeError):
            value = None
    if value is None:
        value = _default_identity()
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")

    # Environment labels may be changed by deployment without rotating the persistent
    # sensor identity. This is useful when the same Windows sensor is assigned to a
    # different named school/campus site.
    value["tenant_id"] = os.environ.get("MON_TENANT_ID", str(value.get("tenant_id") or "local"))
    value["site_id"] = os.environ.get("MON_SITE_ID", str(value.get("site_id") or socket.gethostname()))
    value["site_name"] = os.environ.get("MON_SITE_NAME", str(value.get("site_name") or value["site_id"]))
    value["hostname"] = socket.gethostname()
    value["identity_file"] = str(path)
    return value


def install_sensor_identity_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "sensor_identity_installed", False):
        return app
    app.state.sensor_identity_installed = True

    @app.get("/api/v1/system/sensor")
    async def sensor_identity() -> dict[str, Any]:
        return load_identity()

    return app
