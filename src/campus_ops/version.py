from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

PACKAGE_NAME = "campus-cyber-operations-platform"
BUILD_INFO_PATH = Path("/etc/campus-ops/build.json")


def package_version() -> str:
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "0.0.0+uninstalled"


def build_info(path: Path = BUILD_INFO_PATH) -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": package_version(),
        "branch": None,
        "commit": None,
        "commit_short": None,
        "installed_at": None,
        "source_dirty": None,
    }
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return info
    if not isinstance(raw, dict):
        return info
    commit = str(raw.get("commit") or "") or None
    info.update(
        branch=str(raw.get("branch") or "") or None,
        commit=commit,
        commit_short=commit[:12] if commit else None,
        installed_at=raw.get("installed_at"),
        source_dirty=bool(raw["source_dirty"]) if "source_dirty" in raw else None,
    )
    return info
