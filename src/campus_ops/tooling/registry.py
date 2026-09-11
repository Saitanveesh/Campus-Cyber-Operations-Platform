from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ToolStatus:
    key: str
    label: str
    purpose: str
    available: bool
    path: str | None
    required: bool


TOOL_SPECS: tuple[tuple[str, str, str, tuple[str, ...], bool], ...] = (
    ("dumpcap", "dumpcap", "privileged packet acquisition", ("dumpcap",), False),
    ("tshark", "TShark", "deep protocol decoding", ("tshark",), False),
    ("suricata", "Suricata", "IDS/signature telemetry", ("suricata",), False),
    ("yara", "YARA", "file-content rule matching", ("yara64", "yara"), False),
)


def _find_npcap() -> str | None:
    if os.name != "nt":
        return None
    candidates = (
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "SysWOW64" / "Npcap" / "wpcap.dll",
    )
    for path in candidates:
        if path.exists():
            return str(path)
    return None


def probe_tools() -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    npcap = _find_npcap()
    statuses.append(
        ToolStatus(
            key="npcap",
            label="Npcap",
            purpose="Windows packet capture driver",
            available=npcap is not None,
            path=npcap,
            required=False,
        )
    )
    for key, label, purpose, executables, required in TOOL_SPECS:
        path = next((shutil.which(exe) for exe in executables if shutil.which(exe)), None)
        statuses.append(ToolStatus(key, label, purpose, path is not None, path, required))
    return statuses


def probe_tools_json() -> list[dict[str, object]]:
    return [asdict(item) for item in probe_tools()]
