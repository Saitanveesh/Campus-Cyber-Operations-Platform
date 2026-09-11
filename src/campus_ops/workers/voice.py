from __future__ import annotations

import asyncio
import base64
import itertools
import os
import subprocess
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class VoiceAlertWorker(BaseWorker):
    """Priority voice assistant for continuous Windows operational announcements."""

    STARTUP_GREETING = "Welcome back, Sai Tanveesh. Live Operations Console is starting."

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("voice-alert", bus)
        self.session_provider = session_provider
        self.last_spoken: dict[str, float] = {}
        self._muted_until = 0.0
        self._last_spoken_text: str | None = None
        self._last_speech_error: str | None = None
        self._engine: str | None = None
        self._speaking = False
        self._queue: asyncio.PriorityQueue[tuple[int, int, str, bool, bool]] = asyncio.PriorityQueue(
            maxsize=128
        )
        self._sequence = itertools.count()
        self._speaker_task: asyncio.Task[None] | None = None
        self._speech_lock = asyncio.Lock()

    def mute_for(self, seconds: int) -> None:
        seconds = max(1, min(seconds, 24 * 60 * 60))
        self._muted_until = time.monotonic() + seconds
        self.health.heartbeat(f"voice muted for {seconds}s")

    def unmute(self) -> None:
        self._muted_until = 0.0
        self.health.heartbeat("voice assistant ready")

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
            "engine": self._engine,
            "speaking": self._speaking,
            "queue_depth": self._queue.qsize(),
            "mode": "REAL_TIME_OPERATIONAL_ASSISTANT",
        }

    @staticmethod
    def _encoded_command(script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    async def _powershell(self, script: str) -> subprocess.CompletedProcess[str]:
        encoded = self._encoded_command(script)
        return await asyncio.to_thread(
            subprocess.run,
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    async def _synthesize(self, text: str) -> tuple[bool, str | None]:
        safe = text.replace("'", "''")[:400]
        system_speech = (
            "$ErrorActionPreference='Stop'; "
            "Add-Type -AssemblyName System.Speech; "
            "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            "$s.Rate=0; $s.Volume=100; "
            f"$s.Speak('{safe}')"
        )
        try:
            process = await self._powershell(system_speech)
        except (OSError, subprocess.SubprocessError) as exc:
            process = None
            first_error = str(exc)
        else:
            first_error = process.stderr.strip()[-300:] if process.returncode else ""
            if process.returncode == 0:
                self._engine = "System.Speech"
                return True, None

        sapi = (
            "$ErrorActionPreference='Stop'; "
            "$v=New-Object -ComObject SAPI.SpVoice; "
            "$v.Volume=100; $v.Rate=0; "
            f"[void]$v.Speak('{safe}')"
        )
        try:
            fallback = await self._powershell(sapi)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"{first_error}; SAPI fallback failed: {exc}".strip("; ")
        if fallback.returncode == 0:
            self._engine = "SAPI.SpVoice"
            return True, None
        fallback_error = fallback.stderr.strip()[-300:] or f"PowerShell exited {fallback.returncode}"
        return False, f"{first_error}; {fallback_error}".strip("; ")

    async def speak(self, text: str, critical: bool = False, force: bool = False) -> bool:
        if os.name != "nt":
            self._last_speech_error = "voice synthesis is available only on Windows"
            return False
        if self.muted and not force:
            self._last_speech_error = "voice is muted"
            return False
        if not text.strip():
            return False

        async with self._speech_lock:
            self._speaking = True
            try:
                if critical:
                    try:
                        import winsound

                        await asyncio.to_thread(winsound.Beep, 1200, 250)
                        await asyncio.to_thread(winsound.Beep, 900, 250)
                        await asyncio.to_thread(winsound.Beep, 1200, 350)
                    except RuntimeError:
                        pass
                success, error = await self._synthesize(text)
            finally:
                self._speaking = False

        if not success:
            self._last_speech_error = error or "voice synthesis failed"
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat(f"voice failed: {self._last_speech_error}")
            return False

        self._last_spoken_text = text
        self._last_speech_error = None
        self.health.state = WorkerState.HEALTHY
        self.health.heartbeat("voice assistant ready")
        return True

    def queue_speech(
        self,
        text: str,
        *,
        priority: int = 50,
        critical: bool = False,
        force: bool = False,
    ) -> bool:
        text = text.strip()
        if not text:
            return False
        item = (max(0, min(priority, 100)), next(self._sequence), text[:400], critical, force)
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            self._last_speech_error = "voice queue full"
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("voice queue full")
            return False
        return True

    async def test(self) -> dict[str, object]:
        was_muted = self.muted
        success = await self.speak(
            "Audio check. Live Operations Console voice assistant is working.",
            force=True,
        )
        status = self.status()
        status["test_success"] = success
        status["was_muted"] = was_muted
        return status

    @staticmethod
    def _event_speech(event: Event) -> tuple[str | None, int, bool]:
        text: str | None = None
        priority = 50
        critical = False

        if event.kind == EventKind.ALERT:
            if event.severity == Severity.CRITICAL:
                text = str(event.payload.get("title") or "Critical security alert")
                priority = 0
                critical = True
            elif event.severity == Severity.HIGH:
                text = str(event.payload.get("title") or "High priority security alert")
                priority = 10
        elif event.kind == EventKind.INCIDENT and event.payload.get("voice"):
            text = str(event.payload["voice"])
            priority = 15
            critical = event.severity == Severity.CRITICAL
        elif event.kind == EventKind.HEALTH and event.payload.get("voice"):
            text = str(event.payload["voice"])
            priority = 5 if event.severity in {Severity.HIGH, Severity.CRITICAL} else 25
            critical = event.severity == Severity.CRITICAL
        elif event.kind == EventKind.ACTION:
            text = str(event.payload.get("voice") or "") or None
            priority = 30
        elif event.kind == EventKind.NETWORK and event.payload.get("voice"):
            text = str(event.payload["voice"])
            priority = 20

        return text, priority, critical

    async def _speaker_loop(self) -> None:
        while not self.stopping:
            try:
                priority, sequence, text, critical, force = await self._queue.get()
            except asyncio.CancelledError:
                return
            del priority, sequence
            try:
                await self.speak(text, critical=critical, force=force)
            finally:
                self._queue.task_done()

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY if os.name == "nt" else WorkerState.DEGRADED
        self._speaker_task = asyncio.create_task(self._speaker_loop(), name="voice-speaker")
        if os.name == "nt":
            self.queue_speech(self.STARTUP_GREETING, priority=0, force=True)
            self.last_spoken[f"ACTION:{self.STARTUP_GREETING}"] = time.monotonic()

        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if event.session_id and event.session_id != session_id:
                    continue
                text, priority, critical = self._event_speech(event)
                if text:
                    key = f"{event.kind.value}:{text}"
                    now = time.monotonic()
                    if now - self.last_spoken.get(key, 0.0) >= 10:
                        self.last_spoken[key] = now
                        self.queue_speech(text, priority=priority, critical=critical)
                if os.name == "nt":
                    detail = "voice muted" if self.muted else "voice assistant ready"
                else:
                    detail = "voice unavailable on this OS"
                self.health.heartbeat(detail)
        finally:
            if self._speaker_task:
                self._speaker_task.cancel()
                try:
                    await self._speaker_task
                except asyncio.CancelledError:
                    pass
            await self.bus.unsubscribe(self.name)
