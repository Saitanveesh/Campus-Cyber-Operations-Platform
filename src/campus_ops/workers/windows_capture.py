from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from campus_ops.workers.capture import CaptureWorker


def _powershell_json(script: str, timeout: float = 5.0) -> object:
    if os.name != "nt":
        return []
    try:
        process = __import__("subprocess").run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, TimeoutError):
        return []
    if process.returncode != 0 or not process.stdout.strip():
        return []
    try:
        return json.loads(process.stdout)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


def _adapter_guid(alias: str) -> str | None:
    # InterfaceAlias is operator-facing (for example Wi-Fi or Ethernet). Npcap/TShark
    # usually exposes the same NIC as \\Device\\NPF_{GUID}. Resolve the GUID through
    # Windows instead of depending on fuzzy text matching in `tshark -D`.
    quoted = alias.replace("'", "''")
    script = (
        f"Get-NetAdapter -Name '{quoted}' -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 Name,InterfaceGuid,ifIndex,InterfaceDescription | "
        "ConvertTo-Json -Compress"
    )
    raw = _powershell_json(script)
    if not isinstance(raw, dict):
        return None
    value = str(raw.get("InterfaceGuid") or "").strip().strip("{}")
    return value.upper() or None


def _parse_tshark_interfaces(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "." not in line:
            continue
        index, description = line.split(".", 1)
        index = index.strip()
        description = description.strip()
        if not index:
            continue
        rows.append({"index": index, "description": description})
    return rows


class WindowsCaptureWorker(CaptureWorker):
    """Windows capture worker with deterministic Windows-adapter -> Npcap mapping.

    MON still launches exactly one TShark process. This class only improves adapter
    selection so a Windows alias such as ``Wi-Fi`` is bound to the matching Npcap GUID
    rather than whichever fuzzy description happens to match first.
    """

    async def _tshark_rows(self, tshark: str) -> list[dict[str, str]]:
        try:
            process = await asyncio.create_subprocess_exec(
                tshark,
                "-D",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10.0)
        except (OSError, TimeoutError):
            return []
        if process.returncode != 0:
            return []
        return _parse_tshark_interfaces(stdout.decode(errors="replace"))

    async def _interface_candidates(self, tshark: str, requested: str) -> list[str]:
        if os.name != "nt":
            return await super()._interface_candidates(tshark, requested)

        rows = await self._tshark_rows(tshark)
        if not rows:
            return [requested]

        requested_fold = requested.casefold().strip()
        guid = await asyncio.to_thread(_adapter_guid, requested)
        guid_fold = guid.casefold() if guid else ""

        exact_guid: list[str] = []
        exact_alias: list[str] = []
        fuzzy: list[str] = []
        for row in rows:
            index = row["index"]
            description = row["description"]
            lowered = description.casefold()
            if guid_fold and guid_fold in lowered:
                exact_guid.append(index)
                continue
            if requested_fold and (
                f"({requested_fold})" in lowered
                or lowered == requested_fold
                or lowered.endswith(f" {requested_fold}")
            ):
                exact_alias.append(index)
                continue
            if requested_fold and requested_fold in lowered:
                fuzzy.append(index)

        ordered: list[str] = []
        for value in [*exact_guid, *exact_alias, *fuzzy, requested]:
            if value and value not in ordered:
                ordered.append(value)
        return ordered

    @staticmethod
    def adapter_evidence(alias: str) -> dict[str, Any]:
        return {
            "alias": alias,
            "interface_guid": _adapter_guid(alias),
            "mapping": "WINDOWS_ALIAS_TO_NPCAP_GUID",
        }
