from __future__ import annotations

import asyncio
import os
import subprocess
import time

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, Severity, WorkerState
from campus_ops.workers.base import BaseWorker


class VoiceAlertWorker(BaseWorker):
    """Windows voice and siren channel for operational events.

    Audio is supplemental only; every message is also represented in the UI/event log.
    """

    def __init__(self, bus: EventBus, session_provider) -> None:
        super().__init__("voice-alert", bus)
        self.session_provider = session_provider
        self.last_spoken: dict[str, float] = {}

    async def _speak(self, text: str, critical: bool = False) -> None:
        if os.name != "nt":
            return
        safe = text.replace("'", "''")[:300]
        script = (
            "Add-Type -AssemblyName System.Speech; "
            "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
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
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if event.session_id and event.session_id != session_id:
                    continue
                text = None
                critical = False
                if event.kind == EventKind.ALERT and event.severity in {Severity.HIGH, Severity.CRITICAL}:
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
                self.health.heartbeat("voice channel ready" if os.name == "nt" else "voice unavailable on this OS")
        finally:
            await self.bus.unsubscribe(self.name)
