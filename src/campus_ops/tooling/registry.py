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
    ("dumpcap", "dumpcap", "privileged packet acquisition", ("dumpcap.exe", "dumpcap"), False),
    ("tshark", "TShark", "deep protocol decoding", ("tshark.exe", "tshark"), False),
    ("suricata", "Suricata", "IDS/signature telemetry", ("suricata.exe", "suricata"), False),
    ("yara", "YARA", "file-content rule matching", ("yara64.exe", "yara.exe", "yara64", "yara"), False),
)


def _program_roots() -> tuple[Path, ...]:
    values = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LOCALAPPDATA"),
    ]
    roots: list[Path] = []
    for value in values:
        if value:
            root = Path(value)
            if root not in roots:
                roots.append(root)
    return tuple(roots)


def _default_candidates(key: str) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for root in _program_roots():
        if key == "tshark":
            candidates.extend(
                [
                    root / "Wireshark" / "tshark.exe",
                    root / "Programs" / "Wireshark" / "tshark.exe",
                ]
            )
        elif key == "dumpcap":
            candidates.extend(
                [
                    root / "Wireshark" / "dumpcap.exe",
                    root / "Programs" / "Wireshark" / "dumpcap.exe",
                ]
            )
        elif key == "suricata":
            candidates.extend(
                [
                    root / "Suricata" / "suricata.exe",
                    root / "Programs" / "Suricata" / "suricata.exe",
                ]
            )
        elif key == "yara":
            candidates.extend(
                [
                    root / "YARA" / "yara64.exe",
                    root / "YARA" / "yara.exe",
                    root / "Programs" / "YARA" / "yara64.exe",
                ]
            )
    return tuple(candidates)


def resolve_executable(key: str) -> str | None:
    spec = next((item for item in TOOL_SPECS if item[0] == key), None)
    if spec is None:
        return None
    executables = spec[3]
    for executable in executables:
        resolved = shutil.which(executable)
        if resolved:
            return resolved
    if os.name == "nt":
        for candidate in _default_candidates(key):
            if candidate.exists() and candidate.is_file():
                return str(candidate)
    return None


def _find_npcap() -> str | None:
    if os.name != "nt":
        return None
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = (
        windir / "System32" / "Npcap" / "wpcap.dll",
        windir / "SysWOW64" / "Npcap" / "wpcap.dll",
        windir / "System32" / "Npcap" / "Packet.dll",
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
    for key, label, purpose, _executables, required in TOOL_SPECS:
        path = resolve_executable(key)
        statuses.append(ToolStatus(key, label, purpose, path is not None, path, required))
    return statuses


def probe_tools_json() -> list[dict[str, object]]:
    return [asdict(item) for item in probe_tools()]
