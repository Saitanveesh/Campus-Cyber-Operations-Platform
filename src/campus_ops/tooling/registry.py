from __future__ import annotations

import os
import shutil
from pathlib import Path


def _candidate_paths(name: str) -> tuple[str, ...]:
    if name != "tshark":
        return ()
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return (
            str(Path(program_files) / "Wireshark" / "tshark.exe"),
            "tshark.exe",
            "tshark",
        )
    return ("tshark", "/usr/bin/tshark", "/usr/local/bin/tshark")


def resolve_executable(name: str) -> str | None:
    """Resolve an executable supported by the stable runtime.

    Stable MON deliberately recognizes only TShark. Secondary scanners, IDS engines,
    response tools and active-probe utilities are outside this runtime profile.
    """
    for candidate in _candidate_paths(name):
        expanded = os.path.expandvars(os.path.expanduser(candidate))
        if os.path.isabs(expanded):
            if Path(expanded).is_file():
                return expanded
            continue
        found = shutil.which(expanded)
        if found:
            return found
    return None
