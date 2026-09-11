from __future__ import annotations

import asyncio
import os
import subprocess
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class VoiceAlertWorker(BaseWorker):
    """Windows voice and siren channel with operator test/mute controls."""

    STARTUP_GREETING = "Welcome back, Sai Tanveesh. Live Operations Console is starting."

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("voice-alert", bus)
        self.session_provider = session_provider
        self.last_spoken: dict[str, float] = {}
        self._muted_until = 0.0
        self._last_spoken_text: str | None = None
        self._last_speech_error: str | None = None

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
            "last_spoken": self._last_spoken_text,
            "last_error": self._last_speech_error,
        }

    async def speak(self, text: str, critical: bool = False, force: bool = False) -> bool:
        if os.name != "nt":
            self._last_speech_error = "voice synthesis is available only on Windows"
            return False
        if self.muted and not force:
            self._last_speech_error = "voice is muted"
            return False
        safe = text.replace("'", "''")[:300]
        script = (
            "$ErrorActionPreference='Stop'; "
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
        try:
            process = await asyncio.to_thread(
                subprocess.run,
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=12,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._last_speech_error = str(exc)
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat(f"voice failed: {exc}")
            return False
        if process.returncode != 0:
            error = process.stderr.strip()[-300:] or f"PowerShell exited {process.returncode}"
            self._last_speech_error = error
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat(f"voice failed: {error}")
            return False
        self._last_spoken_text = text
        self._last_speech_error = None
        self.health.state = WorkerState.HEALTHY
        self.health.heartbeat("voice channel ready")
        return True

    async def test(self) -> dict[str, object]:
        was_muted = self.muted
        success = await self.speak(
            "Audio check. Live Operations Console voice channel is working.",
            force=True,
        )
        status = self.status()
        status["test_success"] = success
        status["was_muted"] = was_muted
        return status

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY if os.name == "nt" else WorkerState.DEGRADED
        if os.name == "nt":
            await self.speak(self.STARTUP_GREETING, force=True)
            self.last_spoken[f"ACTION:{self.STARTUP_GREETING}"] = time.monotonic()
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
                        await self.speak(text, critical=critical)
                if os.name == "nt":
                    detail = "voice muted" if self.muted else "voice channel ready"
                else:
                    detail = "voice unavailable on this OS"
                self.health.heartbeat(detail)
        finally:
            await self.bus.unsubscribe(self.name)
