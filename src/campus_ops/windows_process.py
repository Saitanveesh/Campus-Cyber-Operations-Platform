from __future__ import annotations

import os
import subprocess
from typing import Any


def hidden_subprocess_kwargs() -> dict[str, Any]:
    """Return subprocess.Popen/run kwargs that never create a visible Windows console.

    MON is shipped as a PyInstaller --noconsole executable. Child console programs such
    as powershell.exe and tshark.exe must therefore be explicitly detached from any
    visible console window. Keeping this policy in one helper prevents individual
    workers from accidentally reintroducing terminal flashes.
    """
    if os.name != "nt":
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": startupinfo,
    }


def hidden_asyncio_subprocess_kwargs() -> dict[str, Any]:
    """Return kwargs accepted by asyncio.create_subprocess_exec on Windows."""
    if os.name != "nt":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}
