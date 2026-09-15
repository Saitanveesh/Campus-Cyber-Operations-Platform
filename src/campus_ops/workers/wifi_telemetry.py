from __future__ import annotations

import asyncio
import os
import re

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

LINE_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$")


def parse_iw_link(text: str, interface: str) -> dict[str, str]:
    if "Connected to " not in text:
        return {}
    result = {"name": interface, "state": "connected"}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Connected to "):
            result["bssid"] = line.split()[2]
        for prefix, key in (("SSID:", "ssid"), ("signal:", "signal"),
                            ("freq:", "frequency_mhz"), ("tx bitrate:", "transmit_rate_(mbps)")):
            if line.startswith(prefix):
                result[key] = line[len(prefix):].strip()
    return result


def parse_netsh_wlan(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower().replace(" ", "_")
        value = match.group(2).strip()
        if key in {
            "name",
            "description",
            "state",
            "ssid",
            "bssid",
            "network_type",
            "radio_type",
            "authentication",
            "cipher",
            "channel",
            "receive_rate_(mbps)",
            "transmit_rate_(mbps)",
            "signal",
        }:
            result[key] = value
    return result


class WifiTelemetryWorker(BaseWorker):
    """Read visible Wi-Fi link state using iw on Linux and netsh on Windows."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, interval: float = 5.0) -> None:
        super().__init__("wifi-telemetry", bus)
        self.state = state
        self.session_provider = session_provider
        self.interval = interval

    async def _collect(self) -> dict[str, str]:
        if os.name != "nt":
            try:
                process = await asyncio.create_subprocess_exec(
                    "iw", "dev", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=4)
                names = re.findall(r"^\s*Interface (\S+)", stdout.decode(errors="replace"), re.MULTILINE)
                for name in names:
                    process = await asyncio.create_subprocess_exec(
                        "iw", "dev", name, "link", stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL)
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=4)
                    current = parse_iw_link(stdout.decode(errors="replace"), name)
                    if current:
                        return current
            except OSError:
                return {}
            except TimeoutError:
                process.kill()
                await process.wait()
            return {}
        process = await asyncio.create_subprocess_exec(
            "netsh.exe",
            "wlan",
            "show",
            "interfaces",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await process.communicate()
        if process.returncode != 0:
            return {}
        return parse_netsh_wlan(stdout.decode(errors="replace"))

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        previous: dict[str, str] = {}
        while not self.stopping:
            current = await self._collect()
            self.state.update_metrics(wifi=current)
            session_id = self.session_provider()
            if session_id and current and current != previous:
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.OBSERVATION,
                        session_id=session_id,
                        evidence_class="WINDOWS_WIFI_TELEMETRY" if os.name == "nt" else "LINUX_WIFI_TELEMETRY",
                        payload={"type": "WIFI_TELEMETRY", **current},
                    )
                )
            previous = current
            if current:
                self.health.heartbeat(
                    f"ssid={current.get('ssid', 'unknown')} signal={current.get('signal', 'unknown')}"
                )
            else:
                self.health.heartbeat("no connected Wi-Fi interface reported")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
