from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from campus_ops.models import Event, EventKind
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

    @staticmethod
    def _session_control_event(event: Event) -> bool:
        """Keep high-rate packet observations out of the session-manager queue."""
        return event.source == "network-discovery" and event.kind == EventKind.NETWORK

    async def start(self) -> None:
        """Start stable workers with a dedicated network-only session control plane."""
        if self.started_at is not None:
            return
        self.started_at = datetime.now(UTC)
        self._session_sub = await self.bus.subscribe(
            "session-manager",
            predicate=self._session_control_event,
        )
        self._session_task = asyncio.create_task(
            self._session_loop(self._session_sub),
            name="session-manager",
        )
        for worker in self.workers:
            await worker.start()
        await self.bus.publish(
            Event(
                source="orchestrator",
                kind=EventKind.ACTION,
                payload={
                    "state": "STARTED",
                    "message": "Live Operations Console started",
                    "voice": "Welcome back.",
                },
            )
        )

    def snapshot(self) -> dict[str, object]:
        result = super().snapshot()
        result["version"] = "0.4.2"
        result["runtime_profile"] = "stable-single-source"
        result["authoritative_packet_source"] = "tshark"
        result["link_loss_confirmations"] = 5
        result["network_identity_confirmations"] = 3
        result["capture_state_policy"] = "process-health-only"
        result["topology_source"] = "same-tshark-packet-stream"
        result["session_control_plane"] = "network-events-only"
        return result
