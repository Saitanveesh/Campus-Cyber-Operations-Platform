"""Compatibility shim for legacy imports on the Windows product branch.

The Windows runtime never calls this helper. It exists only so shared modules from the
pre-Windows branch can still import while they are being retired.
"""

from __future__ import annotations


def default_routes() -> dict[str, tuple[bool, int | None, str | None]]:
    return {}
