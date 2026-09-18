"""Durable state locations for native Windows MON."""
from __future__ import annotations

import os
from pathlib import Path


def data_root(*, agent: bool = False) -> Path:
    """Return MON's durable data directory.

    The Windows service normally runs outside an interactive user's profile, so
    ProgramData is the canonical location. An explicit CAMPUS_OPS_DATA_DIR remains
    available for tests and controlled deployments.
    """
    key = "CAMPUS_OPS_AGENT_DATA_DIR" if agent else "CAMPUS_OPS_DATA_DIR"
    explicit = os.environ.get(key)
    if explicit:
        root = Path(explicit).expanduser()
    elif os.name == "nt":
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        root = program_data / ("MONAgent" if agent else "MON")
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
        root /= "mon-agent" if agent else "mon"
    root.mkdir(parents=True, exist_ok=True)
    return root
