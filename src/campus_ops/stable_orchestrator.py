from __future__ import annotations

from campus_ops.orchestrator import Orchestrator
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker


class StableOrchestrator(Orchestrator):
    """Reduced runtime used by monitor-v1 stable mode.

    TShark remains the only external live packet source. The UI may expose multiple
    views, but topology, flows, assets and security are deterministic in-process
    derivations of the same packet stream; they are not additional capture pipelines.
    """

    OPTIONAL_DEGRADED_WORKERS = frozenset()

    def __init__(self, settings=None) -> None:
        if settings is None:
            super().__init__()
        else:
            super().__init__(settings)

        # Cyber-range links can momentarily disappear from one discovery poll while
        # NetworkManager, DHCP or a virtual switch updates state. Stable mode requires
        # five consecutive misses before it tears down the live session. Material
        # address/route identity changes also require repeated confirmation so DHCP or
        # IPv6 privacy churn cannot restart TShark after one noisy poll.
        self.network = NetworkDiscoveryWorker(
            self.bus,
            interval=self.settings.network_poll_seconds,
            switch_margin=self.settings.interface_switch_margin,
            confirmations=self.settings.interface_confirmations,
            unavailable_confirmations=5,
            identity_confirmations=3,
        )

        self.workers = [
            # Authoritative state + exactly one live packet source.
            self.state_sink,
            self.network,
            self.capture,
            self.telemetry,
            self.stale_cleanup,
            # Deterministic in-process views derived from that same packet stream.
            self.protocol_engine,
            self.asset_engine,
            self.flow_engine,
            self.topology_engine,
            self.application_intelligence,
            self.dns_intelligence,
            self.service_intelligence,
            self.tcp_intelligence,
            self.traffic_baseline,
            self.performance_engine,
            # Minimal packet-derived security correlation. The old capture-health
            # watchdog is intentionally excluded: comparing OS counters with decoder
            # activity created false degradation on quiet/range interfaces.
            self.arp_guard,
            self.detection,
            self.beaconing,
            self.dos_warning,
            self.incidents,
        ]

    def snapshot(self) -> dict[str, object]:
        result = super().snapshot()
        result["version"] = "0.4.2"
        result["runtime_profile"] = "stable-single-source"
        result["authoritative_packet_source"] = "tshark"
        result["link_loss_confirmations"] = 5
        result["network_identity_confirmations"] = 3
        result["capture_state_policy"] = "process-health-only"
        result["topology_source"] = "same-tshark-packet-stream"
        return result
