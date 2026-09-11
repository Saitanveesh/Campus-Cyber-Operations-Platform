from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import ClassVar
from uuid import uuid4

from campus_ops.config import DEFAULT_SETTINGS, Settings
from campus_ops.control import EndpointControl
from campus_ops.event_bus import EventBus, Subscription
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.arp_guard import ArpGuardWorker
from campus_ops.workers.capture import CaptureWorker
from campus_ops.workers.detection import BehaviourDetectionWorker
from campus_ops.workers.dos_warning import DosEarlyWarningWorker
from campus_ops.workers.forensic_capture import ForensicCaptureWorker
from campus_ops.workers.history import HistoryWorker
from campus_ops.workers.incidents import IncidentCorrelationWorker
from campus_ops.workers.intelligence import IntelligenceWorker
from campus_ops.workers.malware import MalwareAnalysisWorker
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker
from campus_ops.workers.state_sink import StateSinkWorker
from campus_ops.workers.suricata_feed import SuricataFeedWorker
from campus_ops.workers.tcp_intelligence import TcpIntelligenceWorker
from campus_ops.workers.telemetry import TelemetryWorker
from campus_ops.workers.tool_probe import ToolProbeWorker
from campus_ops.workers.voice import VoiceAlertWorker


class Orchestrator:
    """Single authority for worker lifecycle and the current live session."""

    OPTIONAL_DEGRADED_WORKERS: ClassVar[frozenset[str]] = frozenset(
        {"suricata-feed", "forensic-pcap"}
    )

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
        )
        self.tools = ToolProbeWorker(self.bus, interval=settings.tool_probe_seconds)
        self.state_sink = StateSinkWorker(self.bus, self.state)
        self.history = HistoryWorker(self.bus)
        self.intelligence = IntelligenceWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_network_context,
        )
        self.tcp_intelligence = TcpIntelligenceWorker(
            self.bus,
            self.state,
            self.get_session_id,
        )
        self.arp_guard = ArpGuardWorker(self.bus, self.get_session_id)
        self.detection = BehaviourDetectionWorker(self.bus, self.state, self.get_session_id)
        self.dos_warning = DosEarlyWarningWorker(self.bus, self.get_session_id)
        self.incidents = IncidentCorrelationWorker(self.bus, self.state, self.get_session_id)
        self.suricata = SuricataFeedWorker(self.bus, self.get_session_id)
        self.malware = MalwareAnalysisWorker(self.bus, self.get_session_id)
        self.telemetry = TelemetryWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_interface,
            interval=1.0,
        )
        self.capture = CaptureWorker(
            self.bus,
            self.state,
            self.get_session_id,
            self.get_interface,
        )
        self.forensic_capture = ForensicCaptureWorker(
            self.bus,
            self.get_session_id,
            self.get_interface,
        )
        self.voice = VoiceAlertWorker(self.bus, self.get_session_id)
        self.control = EndpointControl(self.bus, self.get_session_id)
        self.workers = [
            self.state_sink,
            self.history,
            self.intelligence,
            self.tcp_intelligence,
            self.arp_guard,
            self.detection,
            self.dos_warning,
            self.incidents,
            self.suricata,
            self.malware,
            self.telemetry,
            self.voice,
            self.tools,
            self.network,
            self.capture,
            self.forensic_capture,
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
        interface = str(current.get("interface") or "network interface")
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
                    "voice": f"Monitoring session started on {interface}",
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
                payload={
                    "change": "LIVE_SESSION_CLOSING",
                    "reason": reason,
                    "voice": "Monitoring network disconnected. Live state cleared.",
                },
            )
        )
        await asyncio.sleep(0)
        self.state.close_session()
        self.session_id = None

    async def _session_loop(self, sub: Subscription) -> None:
        while True:
            event = await sub.queue.get()
            if event.source != "network-discovery" or event.kind != EventKind.NETWORK:
                continue
            change = str(event.payload.get("change") or "")
            if change == "NETWORK_UNAVAILABLE":
                await self._close_session(change)
                continue
            if change in {"INTERFACE_SELECTED", "INTERFACE_CHANGED", "NETWORK_IDENTITY_CHANGED"}:
                current = event.payload.get("current")
                if isinstance(current, dict):
                    new_fingerprint = self._fingerprint(current)
                    if new_fingerprint != self.state.network_fingerprint:
                        await self._open_session(current, change)

    async def start(self) -> None:
        if self.started_at is not None:
            return
        self.started_at = datetime.now(UTC)
        self._session_sub = await self.bus.subscribe("session-manager")
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
                    "voice": "Welcome back, Sai Tanveesh. Live Operations Console is starting.",
                },
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
                "optional": worker.name in self.OPTIONAL_DEGRADED_WORKERS,
            }
            for worker in self.workers
        }
        core_workers = [
            worker for worker in self.workers if worker.name not in self.OPTIONAL_DEGRADED_WORKERS
        ]
        overall = "HEALTHY"
        if any(worker.health.state == WorkerState.FAILED for worker in core_workers):
            overall = "FAILED"
        elif any(worker.health.state == WorkerState.DEGRADED for worker in core_workers):
            overall = "DEGRADED"
        return {
            "product": "Campus Cyber Operations Platform",
            "version": "0.2.0",
            "live_contract": "CURRENT_SESSION_ONLY",
            "overall": overall,
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "network": self.get_network_context(),
            "network_candidates": [asdict(item) for item in self.network.candidates],
            "workers": worker_states,
            "tools": self.tools.statuses,
            "event_bus": self.bus.stats(),
            "enrolled_endpoints": self.control.list(),
            "evidence_root": str(self.forensic_capture.root),
            "malware_staging": str(self.malware.staging),
            "live": self.state.snapshot(),
        }
