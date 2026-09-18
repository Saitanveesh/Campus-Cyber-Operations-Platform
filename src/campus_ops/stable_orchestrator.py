"""Compatibility alias for the Windows-only MON product branch.

The old cross-platform stable orchestrator was removed to prevent Linux/WSL network
logic from being mixed into the native Windows runtime.
"""
from __future__ import annotations

from campus_ops.windows_orchestrator import WindowsOrchestrator

StableOrchestrator = WindowsOrchestrator

__all__ = ["StableOrchestrator", "WindowsOrchestrator"]
