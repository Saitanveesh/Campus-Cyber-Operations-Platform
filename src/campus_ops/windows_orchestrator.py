from __future__ import annotations

import os

from campus_ops.config import DEFAULT_SETTINGS, Settings
from campus_ops.stable_orchestrator import StableOrchestrator
from campus_ops.workers.evidence_store import EvidenceStoreWorker
from campus_ops.workers.windows_capture import WindowsCaptureWorker
from campus_ops.workers.windows_network import WindowsNetworkDiscoveryWorker


class WindowsOrchestrator(StableOrchestrator):
    """Native Windows MON runtime.

    Shared packet analytics remain unchanged. The platform boundary is Windows-native:
    Windows adapter/routing discovery plus one TShark process through Npcap.
    """

    def __init__(self, settings: Settings = DEFAULT_SETTINGS) -> None:
        if os.name != "nt":
            raise RuntimeError("MON Windows must run on native Windows, not WSL/Linux")
        super().__init__(settings)

        old_network = self.network
        old_capture = self.capture

        self.network = WindowsNetworkDiscoveryWorker(
            self.bus,
            interval=settings.network_poll_seconds,
            switch_margin=settings.interface_switch_margin,
            confirmations=settings.interface_confirmations,
            unavailable_confirmations=5,
            identity_confirmations=3,
        )
        self.capture = WindowsCaptureWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_interface,
        )
        self.evidence_store = EvidenceStoreWorker(
            self.bus,
            self.state,
            self.get_session_id,
        )

        self.workers = [
            self.network if worker is old_network else self.capture if worker is old_capture else worker
            for worker in self.workers
        ]
        self.workers.append(self.evidence_store)

    def snapshot(self) -> dict[str, object]:
        value = super().snapshot()
        value["version"] = "1.0.0-windows"
        value["runtime_profile"] = "windows-native-single-source"
        value["capture_stack"] = "tshark+npcap"
        value["platform_contract"] = "native-windows-only"
        value["ip_truth_policy"] = "current-session-packet-evidence-only"
        value["history_policy"] = "metadata-only-7-day-local-retention"
        interface = self.get_interface()
        value["capture_adapter_evidence"] = (
            WindowsCaptureWorker.adapter_evidence(interface) if interface else None
        )
        return value
