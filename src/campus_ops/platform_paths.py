"""Platform state locations, shared by the console and its workers."""
from __future__ import annotations

import os
from pathlib import Path


def data_root(*, agent: bool = False) -> Path:
    key = "CAMPUS_OPS_AGENT_DATA_DIR" if agent else "CAMPUS_OPS_DATA_DIR"
    explicit = os.environ.get(key)
    legacy = os.environ.get("LOCALAPPDATA")
    if explicit:
        root = Path(explicit).expanduser()
    elif legacy:
        root = Path(legacy) / ("CampusCyberAgent" if agent else "CampusCyberOperationsPlatform")
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
        root /= "campus-ops-agent" if agent else "campus-ops"
    root.mkdir(parents=True, exist_ok=True)
    return root
