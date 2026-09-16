from __future__ import annotations

import os

from campus_ops.config import DEFAULT_SETTINGS, Settings
from campus_ops.stable_orchestrator import StableOrchestrator
from campus_ops.workers.windows_network import WindowsNetworkDiscoveryWorker


class WindowsOrchestrator(StableOrchestrator):
    """Native Windows MON runtime.

    Shared packet analytics remain unchanged. Only the platform boundary is replaced:
    Windows adapter/routing discovery + TShark/Npcap capture.
    """

    def __init__(self, settings: Settings = DEFAULT_SETTINGS) -> None:
        if os.name != "nt":
            raise RuntimeError("MON Windows must run on native Windows, not WSL/Linux")
        super().__init__(settings)
        old_network = self.network
        self.network = WindowsNetworkDiscoveryWorker(
            self.bus,
            interval=settings.network_poll_seconds,
            switch_margin=settings.interface_switch_margin,
            confirmations=settings.interface_confirmations,
            unavailable_confirmations=5,
            identity_confirmations=3,
        )
        self.workers = [self.network if worker is old_network else worker for worker in self.workers]

    def snapshot(self) -> dict[str, object]:
        value = super().snapshot()
        value["version"] = "1.0.0-windows"
        value["runtime_profile"] = "windows-native-single-source"
        value["capture_stack"] = "tshark+npcap"
        value["platform_contract"] = "native-windows-only"
        return value
