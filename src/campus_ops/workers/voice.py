from __future__ import annotations

import asyncio
import os
import subprocess
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class VoiceAlertWorker(BaseWorker):
    """Windows voice and siren channel for operational events."""

    STARTUP_GREETING = "Welcome back, Sai Tanveesh. Live Operations Console is starting."

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("voice-alert", bus)
        self.session_provider = session_provider
        self.last_spoken: dict[str, float] = {}
        self._muted_until = 0.0

    def mute_for(self, seconds: int) -> None:
        seconds = max(1, min(seconds, 24 * 60 * 60))
        self._muted_until = time.monotonic() + seconds
        self.health.heartbeat(f"voice muted for {seconds}s")

    def unmute(self) -> None:
        self._muted_until = 0.0
        self.health.heartbeat("voice channel ready")

    @property
    def muted(self) -> bool:
        return time.monotonic() < self._muted_until

    def status(self) -> dict[str, object]:
        remaining = max(0, int(self._muted_until - time.monotonic()))
        return {
            "available": os.name == "nt",
            "muted": self.muted,
            "mute_remaining_seconds": remaining,
        }

    async def _speak(self, text: str, critical: bool = False) -> None:
        if os.name != "nt" or self.muted:
            return
        safe = text.replace("'", "''")[:300]
        script = (
            "Add-Type -AssemblyName System.Speech; "
            "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            "$s.Rate=0; $s.Volume=100; "
            f"$s.Speak('{safe}')"
        )
        if critical:
            try:
                import winsound

                winsound.Beep(1200, 250)
                winsound.Beep(900, 250)
                winsound.Beep(1200, 350)
            except RuntimeError:
                pass
        await asyncio.to_thread(
            subprocess.run,
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            check=False,
            timeout=10,
        )

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY if os.name == "nt" else WorkerState.DEGRADED
        if os.name == "nt":
            await self._speak(self.STARTUP_GREETING)
            self.last_spoken[f"ACTION:{self.STARTUP_GREETING}"] = time.monotonic()
            self.health.heartbeat("voice channel ready")
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if event.session_id and event.session_id != session_id:
                    continue
                text = None
                critical = False
                if event.kind == EventKind.ALERT and event.severity in {
                    Severity.HIGH,
                    Severity.CRITICAL,
                }:
                    text = str(event.payload.get("title") or "High priority security alert")
                    critical = event.severity == Severity.CRITICAL
                elif event.kind == EventKind.ACTION:
                    text = str(event.payload.get("voice") or event.payload.get("message") or "") or None
                elif event.kind == EventKind.NETWORK and event.payload.get("voice"):
                    text = str(event.payload["voice"])
                if text:
                    key = f"{event.kind.value}:{text}"
                    now = time.monotonic()
                    if now - self.last_spoken.get(key, 0.0) >= 10:
                        self.last_spoken[key] = now
                        await self._speak(text, critical=critical)
                if os.name == "nt":
                    detail = "voice muted" if self.muted else "voice channel ready"
                else:
                    detail = "voice unavailable on this OS"
                self.health.heartbeat(detail)
        finally:
            await self.bus.unsubscribe(self.name)
