"""Windows-only network discovery compatibility exports.

The previous Linux/WSL discovery implementation is intentionally absent from the
Windows product branch so stale route/interface logic cannot be selected accidentally.
"""
from __future__ import annotations

from campus_ops.workers.windows_network import (
    WindowsNetworkDiscoveryWorker,
    classify_interface,
    discover_candidates,
    elect_network,
    score_candidate,
)

NetworkDiscoveryWorker = WindowsNetworkDiscoveryWorker

__all__ = [
    "NetworkDiscoveryWorker",
    "WindowsNetworkDiscoveryWorker",
    "classify_interface",
    "discover_candidates",
    "elect_network",
    "score_candidate",
]
