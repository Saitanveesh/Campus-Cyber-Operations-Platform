from __future__ import annotations

import asyncio
import hashlib
import json
import platform
from dataclasses import asdict
from datetime import UTC, datetime
from uuid import uuid4

from campus_ops.config import DEFAULT_SETTINGS, Settings
from campus_ops.event_bus import EventBus, Subscription
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.application_intelligence import ApplicationIntelligenceWorker
from campus_ops.workers.arp_guard import ArpGuardWorker
from campus_ops.workers.asset_engine import AssetEngineWorker
from campus_ops.workers.beaconing import BeaconingWorker
from campus_ops.workers.capture import CaptureWorker
from campus_ops.workers.detection import BehaviourDetectionWorker
from campus_ops.workers.dns_intelligence import DnsIntelligenceWorker
from campus_ops.workers.dos_warning import DosEarlyWarningWorker
from campus_ops.workers.flow_engine import FlowEngineWorker
from campus_ops.workers.incidents import IncidentCorrelationWorker
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker
from campus_ops.workers.performance_engine import PerformanceEngineWorker
from campus_ops.workers.protocol_engine import ProtocolEngineWorker
from campus_ops.workers.service_intelligence import ServiceIntelligenceWorker
from campus_ops.workers.stale_cleanup import StaleCleanupWorker
from campus_ops.workers.state_sink import StateSinkWorker
from campus_ops.workers.tcp_intelligence import TcpIntelligenceWorker
from campus_ops.workers.telemetry import TelemetryWorker
from campus_ops.workers.topology_engine import TopologyEngineWorker
from campus_ops.workers.traffic_baseline import TrafficBaselineWorker


class StableOrchestrator:
    """Lean single-source runtime for MON stable mode.

    This class is intentionally standalone. It does not construct the legacy agent,
    response, multi-sensor, voice, forensic-capture, tool-probe or enterprise stacks.
    Every live network view is derived from one TShark packet stream.
    """

    def __init__(self, settings: Settings = DEFAULT_SETTINGS) -> None:
        self.settings = settings
        self.bus = EventBus()
        self.state = LiveState()
        self.started_at: datetime | None = None
        self.session_id: str | None = None

        self.network = NetworkDiscoveryWorker(
            self.bus,
            interval=settings.network_poll_seconds,
            switch_margin=settings.interface_switch_margin,
            confirmations=settings.interface_confirmations,
            unavailable_confirmations=5,
            identity_confirmations=3,
        )
        self.state_sink = StateSinkWorker(self.bus, self.state)
        self.capture = CaptureWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_interface,
        )
        self.telemetry = TelemetryWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_interface,
            interval=1.0,
        )
        self.stale_cleanup = StaleCleanupWorker(
            self.bus,
            self.state,
            self.get_session_id,
        )
        self.protocol_engine = ProtocolEngineWorker(self.bus, self.state, self.get_session_id)
        self.asset_engine = AssetEngineWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_network_context,
        )
        self.flow_engine = FlowEngineWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_network_context,
        )
        self.topology_engine = TopologyEngineWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_network_context,
        )
        self.application_intelligence = ApplicationIntelligenceWorker(
            self.bus, self.state, self.get_session_id
        )
        self.dns_intelligence = DnsIntelligenceWorker(self.bus, self.state, self.get_session_id)
        self.service_intelligence = ServiceIntelligenceWorker(
            self.bus, self.state, self.get_session_id
        )
        self.tcp_intelligence = TcpIntelligenceWorker(self.bus, self.state, self.get_session_id)
        self.traffic_baseline = TrafficBaselineWorker(self.bus, self.state, self.get_session_id)
        self.performance_engine = PerformanceEngineWorker(self.bus, self.state, self.get_session_id)
        self.arp_guard = ArpGuardWorker(self.bus, self.get_session_id)
        self.detection = BehaviourDetectionWorker(self.bus, self.state, self.get_session_id)
        self.beaconing = BeaconingWorker(self.bus, self.state, self.get_session_id)
        self.dos_warning = DosEarlyWarningWorker(self.bus, self.get_session_id)
        self.incidents = IncidentCorrelationWorker(self.bus, self.state, self.get_session_id)

        self.workers = [
            self.state_sink,
            self.network,
            self.capture,
            self.telemetry,
            self.stale_cleanup,
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
            self.arp_guard,
            self.detection,
            self.beaconing,
            self.dos_warning,
            self.incidents,
        ]
        self._session_task: asyncio.Task[None] | None = None
        self._session_sub: Subscription | None = None

    def get_session_id(self) -> str | None:
        return self.session_id

    def get_interface(self) -> str | None:
        return self.network.selected.interface if self.network.selected else None

    def get_network_context(self) -> dict[str, object] | None:
        return asdict(self.network.selected) if self.network.selected else None

    @staticmethod
    def _fingerprint(current: dict[str, object]) -> str:
        stable = {
            "interface": current.get("interface"),
            "ipv4": current.get("ipv4"),
            "ipv6": current.get("ipv6"),
            "prefixes": current.get("prefixes"),
            "gateway": current.get("gateway"),
            "default_route": current.get("default_route"),
        }
        raw = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()[:20]

    async def _open_session(self, current: dict[str, object], change: str) -> None:
        if self.session_id:
            self.state.close_session()
        self.session_id = str(uuid4())
        fingerprint = self._fingerprint(current)
        self.state.start_session(self.session_id, fingerprint)
        await self.bus.publish(
            Event(
                source="session-manager",
                kind=EventKind.NETWORK,
                session_id=self.session_id,
                payload={
                    "change": "LIVE_SESSION_STARTED",
                    "reason": change,
                    "current": current,
                    "fingerprint": fingerprint,
                },
            )
        )

    async def _close_session(self, reason: str) -> None:
        old = self.session_id
        if old is None:
            return
        await self.bus.publish(
            Event(
                source="session-manager",
                kind=EventKind.NETWORK,
                session_id=old,
                severity=Severity.MEDIUM,
                payload={"change": "LIVE_SESSION_CLOSING", "reason": reason},
            )
        )
        await asyncio.sleep(0)
        self.state.close_session()
        self.session_id = None

    @staticmethod
    def _session_control_event(event: Event) -> bool:
        return event.source == "network-discovery" and event.kind == EventKind.NETWORK

    async def _session_loop(self, sub: Subscription) -> None:
        while True:
            event = await sub.queue.get()
            change = str(event.payload.get("change") or "")
            if change == "NETWORK_UNAVAILABLE":
                await self._close_session(change)
                continue
            if change not in {
                "INTERFACE_SELECTED",
                "INTERFACE_CHANGED",
                "NETWORK_IDENTITY_CHANGED",
            }:
                continue
            current = event.payload.get("current")
            if isinstance(current, dict):
                new_fingerprint = self._fingerprint(current)
                if new_fingerprint != self.state.network_fingerprint:
                    await self._open_session(current, change)

    async def start(self) -> None:
        if self.started_at is not None:
            return
        self.started_at = datetime.now(UTC)
        self._session_sub = await self.bus.subscribe(
            "session-manager", predicate=self._session_control_event
        )
        self._session_task = asyncio.create_task(
            self._session_loop(self._session_sub), name="session-manager"
        )
        for worker in self.workers:
            await worker.start()
        await self.bus.publish(
            Event(
                source="orchestrator",
                kind=EventKind.ACTION,
                payload={"state": "STARTED", "message": "MON stable runtime started"},
            )
        )

    async def stop(self) -> None:
        await self._close_session("APPLICATION_STOP")
        for worker in reversed(self.workers):
            await worker.stop()
        if self._session_task:
            self._session_task.cancel()
            try:
                await self._session_task
            except asyncio.CancelledError:
                pass
        if self._session_sub:
            await self.bus.unsubscribe(self._session_sub.name)
        self._session_task = None
        self._session_sub = None
        self.started_at = None

    def snapshot(self) -> dict[str, object]:
        worker_states = {
            worker.name: {
                "state": worker.health.state.value,
                "detail": worker.health.detail,
                "last_heartbeat": (
                    worker.health.last_heartbeat.isoformat()
                    if worker.health.last_heartbeat
                    else None
                ),
                "last_error": worker.health.last_error,
            }
            for worker in self.workers
        }
        overall = "HEALTHY"
        if any(worker.health.state == WorkerState.FAILED for worker in self.workers):
            overall = "FAILED"
        elif any(worker.health.state == WorkerState.DEGRADED for worker in self.workers):
            overall = "DEGRADED"

        return {
            "product": "Campus Cyber Operations Platform",
            "platform": platform.system(),
            "version": "0.5.0",
            "runtime_profile": "stable-single-source",
            "authoritative_packet_source": "tshark",
            "capture_state_policy": "process-health-only",
            "session_control_plane": "network-events-only",
            "topology_source": "same-tshark-packet-stream",
            "link_loss_confirmations": 5,
            "network_identity_confirmations": 3,
            "overall": overall,
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "network": self.get_network_context(),
            "network_candidates": [asdict(item) for item in self.network.candidates],
            "workers": worker_states,
            "event_bus": self.bus.stats(),
            "live": self.state.snapshot(),
        }
