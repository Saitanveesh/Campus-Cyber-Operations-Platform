from __future__ import annotations

import asyncio
import base64
import itertools
import os
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class VoiceAlertWorker(BaseWorker):
    """Minimal priority voice assistant with interruptible page briefings."""

    STARTUP_GREETING = "Welcome back."
    EVENT_REPEAT_SECONDS = 1800.0

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("voice-alert", bus)
        self.session_provider = session_provider
        self.last_spoken: dict[str, float] = {}
        self._muted_until = 0.0
        self._last_spoken_text: str | None = None
        self._last_speech_error: str | None = None
        self._engine: str | None = None
        self._speaking = False
        self._backend_ready = os.name == "nt"
        self._generation = 0
        self._queue: asyncio.PriorityQueue[tuple[int, int, int, str, bool, bool]] = (
            asyncio.PriorityQueue(maxsize=64)
        )
        self._sequence = itertools.count()
        self._speaker_task: asyncio.Task[None] | None = None
        self._speech_lock = asyncio.Lock()
        self._current_process: asyncio.subprocess.Process | None = None

    @staticmethod
    def _clean_text(text: str) -> str:
        cleaned = text.replace(
            "Welcome back, Sai Tanveesh. Live Operations Console is starting.",
            "Welcome back.",
        )
        cleaned = cleaned.replace("Sai Tanveesh, ", "").replace("Sai Tanveesh", "")
        return " ".join(cleaned.split())

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
            "available": self._backend_ready,
            "backend_present": os.name == "nt",
            "muted": self.muted,
            "mute_remaining_seconds": remaining,
            "last_spoken": self._last_spoken_text,
            "last_error": self._last_speech_error,
            "engine": self._engine,
            "speaking": self._speaking,
            "queue_depth": self._queue.qsize(),
            "mode": "MINIMAL_CONTEXT_ASSISTANT",
        }

    @staticmethod
    def _encoded_command(script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    async def _powershell(self, script: str) -> tuple[int, str, str]:
        encoded = self._encoded_command(script)
        process = await asyncio.create_subprocess_exec(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._current_process = process
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
        except TimeoutError:
            if process.returncode is None:
                process.kill()
            await process.wait()
            return -1, "", "voice synthesis timed out"
        finally:
            if self._current_process is process:
                self._current_process = None
        return (
            int(process.returncode or 0),
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
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
            code, _stdout, stderr = await self._powershell(system_speech)
        except (OSError, asyncio.SubprocessError) as exc:
            code = -1
            stderr = str(exc)
        if code == 0:
            self._engine = "System.Speech"
            return True, None
        first_error = stderr.strip()[-300:] or f"System.Speech exited {code}"

        sapi = (
            "$ErrorActionPreference='Stop'; "
            "$v=New-Object -ComObject SAPI.SpVoice; "
            "$v.Volume=100; $v.Rate=0; "
            f"[void]$v.Speak('{safe}')"
        )
        try:
            code, _stdout, stderr = await self._powershell(sapi)
        except (OSError, asyncio.SubprocessError) as exc:
            return False, f"{first_error}; SAPI fallback failed: {exc}"
        if code == 0:
            self._engine = "SAPI.SpVoice"
            return True, None
        fallback_error = stderr.strip()[-300:] or f"SAPI exited {code}"
        return False, f"{first_error}; {fallback_error}"

    async def cancel_speech(self, clear_queue: bool = True) -> None:
        self._generation += 1
        process = self._current_process
        if process is not None and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except (ProcessLookupError, TimeoutError):
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        self._current_process = None
        if clear_queue:
            while True:
                try:
                    self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                else:
                    self._queue.task_done()
        self._speaking = False

    async def speak(self, text: str, critical: bool = False, force: bool = False) -> bool:
        text = self._clean_text(text)
        if os.name != "nt":
            self._backend_ready = False
            self._last_speech_error = "backend voice synthesis is available only on Windows"
            return False
        if self.muted and not force:
            return False
        if not text:
            return False
        if not self._backend_ready and not force:
            return False

        async with self._speech_lock:
            self._speaking = True
            try:
                if critical:
                    try:
                        import winsound

                        await asyncio.to_thread(winsound.Beep, 1200, 220)
                        await asyncio.to_thread(winsound.Beep, 900, 220)
                    except RuntimeError:
                        pass
                success, error = await self._synthesize(text)
            finally:
                self._speaking = False

        if not success:
            self._backend_ready = False
            self._last_speech_error = error or "voice synthesis failed"
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat("backend voice unavailable; browser fallback can be used")
            return False

        self._backend_ready = True
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
        text = self._clean_text(text)
        if not text or self.muted:
            return False
        if not self._backend_ready and not force:
            return False
        item = (
            max(0, min(priority, 100)),
            next(self._sequence),
            self._generation,
            text[:400],
            critical,
            force,
        )
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            self._last_speech_error = "voice queue full"
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat("voice queue full; speech skipped")
            return False
        return True

    async def replace_speech(self, text: str, *, priority: int = 18) -> bool:
        if self.muted:
            return False
        await self.cancel_speech(clear_queue=True)
        return self.queue_speech(text, priority=priority)

    async def test(self) -> dict[str, object]:
        was_muted = self.muted
        self._backend_ready = os.name == "nt"
        await self.cancel_speech(clear_queue=True)
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
        payload = event.payload
        if event.kind == EventKind.INCIDENT:
            incident_type = str(payload.get("type") or "")
            if incident_type not in {
                "INCIDENT_OPENED",
                "INCIDENT_REOPENED",
                "INCIDENT_ESCALATED",
            }:
                return None, 50, False
            if event.severity not in {Severity.HIGH, Severity.CRITICAL}:
                return None, 50, False
            text = str(payload.get("voice") or payload.get("title") or "Security incident")
            return text, 5 if event.severity == Severity.CRITICAL else 10, event.severity == Severity.CRITICAL

        if event.kind == EventKind.HEALTH:
            if str(payload.get("state") or "").upper() != "ACTIVE":
                return None, 50, False
            if event.severity not in {Severity.HIGH, Severity.CRITICAL}:
                return None, 50, False
            return (
                str(payload.get("voice") or payload.get("title") or "Operational problem detected"),
                5,
                event.severity == Severity.CRITICAL,
            )

        if event.kind == EventKind.ACTION:
            if (
                str(payload.get("action") or "") == "RESPONSE_JOB_RESULT"
                and str(payload.get("status") or "").upper() in {"FAILED", "REJECTED"}
            ):
                return str(payload.get("voice") or "Response job failed."), 15, False
            return None, 50, False

        return None, 50, False

    async def _speaker_loop(self) -> None:
        while not self.stopping:
            try:
                priority, sequence, generation, text, critical, force = await self._queue.get()
            except asyncio.CancelledError:
                return
            del priority, sequence
            try:
                if generation != self._generation:
                    continue
                await self.speak(text, critical=critical, force=force)
            finally:
                self._queue.task_done()

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        self._speaker_task = asyncio.create_task(self._speaker_loop(), name="voice-speaker")
        if os.name == "nt":
            self.queue_speech(self.STARTUP_GREETING, priority=0, force=True)
            self.last_spoken[f"ACTION:{self.STARTUP_GREETING}"] = time.monotonic()
        else:
            self._backend_ready = False

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
                    if now - self.last_spoken.get(key, 0.0) >= self.EVENT_REPEAT_SECONDS:
                        self.last_spoken[key] = now
                        self.queue_speech(text, priority=priority, critical=critical)
                if self.muted:
                    detail = "voice muted"
                elif self._backend_ready:
                    detail = "voice assistant ready"
                else:
                    detail = "backend voice unavailable; browser fallback available in console"
                self.health.heartbeat(detail)
        finally:
            await self.cancel_speech(clear_queue=True)
            if self._speaker_task:
                self._speaker_task.cancel()
                try:
                    await self._speaker_task
                except asyncio.CancelledError:
                    pass
            await self.bus.unsubscribe(self.name)
