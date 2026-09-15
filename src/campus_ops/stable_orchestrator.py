from __future__ import annotations

from campus_ops.orchestrator import Orchestrator
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker


class StableOrchestrator(Orchestrator):
    """Reduced runtime used by monitor-v1 stable mode.

    One external telemetry source is authoritative: TShark packet metadata. Everything
    else in this worker list is an in-process derivation of those packets or local link
    counters. External feeds, additional packet engines, endpoint agents, voice,
    forensics, SNMP/syslog/flow collectors and autonomous response workers are not
    started in stable mode.
    """

    OPTIONAL_DEGRADED_WORKERS = frozenset()

    def __init__(self, settings=None) -> None:
        if settings is None:
            super().__init__()
        else:
            super().__init__(settings)

        # Cyber-range links can momentarily disappear from one discovery poll while
        # NetworkManager, DHCP or a virtual switch updates state. Stable mode requires
        # five consecutive misses before it tears down the live session.
        self.network = NetworkDiscoveryWorker(
            self.bus,
            interval=self.settings.network_poll_seconds,
            switch_margin=self.settings.interface_switch_margin,
            confirmations=self.settings.interface_confirmations,
            unavailable_confirmations=5,
        )

        self.workers = [
            # Authoritative state + one network/capture path.
            self.state_sink,
            self.network,
            self.capture,
            self.capture_health,
            self.telemetry,
            self.stale_cleanup,
            # Deterministic in-process views derived from the same packet stream.
            self.protocol_engine,
            self.asset_engine,
            self.flow_engine,
            self.application_intelligence,
            self.dns_intelligence,
            self.service_intelligence,
            self.tcp_intelligence,
            self.traffic_baseline,
            self.performance_engine,
            # Minimal security correlation; no second packet source is started.
            self.arp_guard,
            self.detection,
            self.beaconing,
            self.dos_warning,
            self.incidents,
        ]

    def snapshot(self) -> dict[str, object]:
        result = super().snapshot()
        result["version"] = "0.4.0"
        result["runtime_profile"] = "stable-single-source"
        result["authoritative_packet_source"] = "tshark"
        result["link_loss_confirmations"] = 5
        return result
