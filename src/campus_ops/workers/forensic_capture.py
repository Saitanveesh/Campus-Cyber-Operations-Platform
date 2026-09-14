from __future__ import annotations

import asyncio
from pathlib import Path

from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.platform_paths import data_root
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.base import BaseWorker


def evidence_root() -> Path:
    root = data_root() / "evidence" / "pcap"
    root.mkdir(parents=True, exist_ok=True)
    return root


class ForensicCaptureWorker(BaseWorker):
    """Optional bounded rolling PCAP-NG evidence capture using dumpcap."""

    def __init__(self, bus: EventBus, session_provider, interface_provider) -> None:
        super().__init__("forensic-pcap", bus)
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self.root = evidence_root()
        self._process: asyncio.subprocess.Process | None = None
        self._bound: tuple[str, str] | None = None

    async def _resolve_interface(self, dumpcap: str, requested: str) -> str:
        process = await asyncio.create_subprocess_exec(
            dumpcap,
            "-D",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await process.communicate()
        text = stdout.decode(errors="replace")
        requested_lower = requested.lower()
        for line in text.splitlines():
            if requested_lower in line.lower():
                return line.split(".", 1)[0].strip()
        return requested

    async def _stop_process(self) -> None:
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except TimeoutError:
                self._process.kill()
                await self._process.wait()
        self._process = None
        self._bound = None

    async def stop(self) -> None:
        await self._stop_process()
        await super().stop()

    async def run(self) -> None:
        while not self.stopping:
            dumpcap = resolve_executable("dumpcap")
            if dumpcap is None:
                await self._stop_process()
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("dumpcap unavailable; rolling PCAP disabled")
                await asyncio.sleep(5)
                continue

            session_id = self.session_provider()
            interface = self.interface_provider()
            if not session_id or not interface:
                await self._stop_process()
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat("waiting for active session")
                await asyncio.sleep(1)
                continue

            binding = (session_id, interface)
            if self._bound != binding or self._process is None or self._process.returncode is not None:
                await self._stop_process()
                capture_interface = await self._resolve_interface(dumpcap, interface)
                base = self.root / f"session-{session_id}.pcapng"
                self._process = await asyncio.create_subprocess_exec(
                    dumpcap,
                    "-q",
                    "-i",
                    capture_interface,
                    "-b",
                    "filesize:32768",
                    "-b",
                    "files:6",
                    "-w",
                    str(base),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.sleep(0.5)
                if self._process.returncode is not None:
                    detail = f"dumpcap exited with code {self._process.returncode}"
                    if self._process.stderr is not None:
                        stderr = await self._process.stderr.read()
                        text = stderr.decode(errors="replace").strip()[-300:]
                        if text:
                            detail = f"{detail}: {text}"
                    self.health.state = WorkerState.DEGRADED
                    self.health.heartbeat(detail)
                    await asyncio.sleep(3)
                    continue
                self._bound = binding
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat(f"bounded PCAP ring active on {interface}")
            else:
                self.health.heartbeat(f"bounded PCAP ring active on {interface}")
            await asyncio.sleep(2)
