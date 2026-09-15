"""Systemd-owned sensor process supervisor with automatic network rebinding.

The web application never starts privileged processes. Arguments are fixed here;
the only network selector is validated against actual Linux interface names.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from campus_ops.event_bus import EventBus
from campus_ops.workers.network_discovery import (
    NetworkDiscoveryWorker,
    discover_candidates,
    elect_network,
)

LOG_ROOT = Path("/var/log/campus-ops")
RUN_ROOT = Path("/run/campus-ops-sensors")
NETWORK_SENSORS = {"zeek", "suricata"}


def command_for(sensor: str, interface: str | None, root: Path = LOG_ROOT) -> list[str]:
    if sensor == "zeek" and interface:
        return ["/opt/zeek/bin/zeek", "-C", "-i", interface,
                "/etc/campus-ops/sensors/local.zeek"]
    if sensor == "suricata" and interface:
        return ["/usr/bin/suricata", "--pcap=" + interface, "-c",
                "/etc/campus-ops/sensors/suricata.yaml", "-l", str(root / "suricata")]
    if sensor == "falco":
        return ["/usr/bin/falco", "-c", "/etc/falco/falco.yaml", "-o", "engine.kind=modern_ebpf",
                "-o", "json_output=true", "-o", "json_include_output_property=true",
                "-o", "file_output.enabled=true", "-o", "file_output.keep_alive=false",
                "-o", f"file_output.filename={root / 'falco/events.jsonl'}",
                "-o", "stdout_output.enabled=false", "-o", "webserver.enabled=false"]
    if sensor == "opencanary":
        # Direct twistd avoids the opencanaryd wrapper's sudo and /var/run pidfile.
        return ["/opt/campus-ops/opencanary/bin/twistd", "-noy",
                "/opt/campus-ops/opencanary/bin/opencanary.tac", "--pidfile="]
    raise ValueError("unsupported sensor or missing network interface")


class Supervisor:
    def __init__(self, sensor: str, runtime: Path = RUN_ROOT) -> None:
        self.sensor = sensor
        self.runtime = runtime
        self.process = None
        self.binding = None
        self.stop_requested = False
        self.restarts = 0
        self.next_start = 0.0
        self.output = None
        self.started_at = None

    def status(self, state: str, detail: str = "") -> None:
        self.runtime.mkdir(parents=True, exist_ok=True)
        path = self.runtime / f"{self.sensor}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({
            "state": state, "detail": detail, "checked_at": time.time(),
            "interface": self.binding, "restarts": self.restarts,
            "pid": self.process.pid if self.process else None,
            "started_at": self.started_at,
        }))
        temporary.replace(path)

    def stop_child(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None
        self.started_at = None
        self.binding = None
        if self.output:
            self.output.close()
            self.output = None

    def tick(self, interface: str | None) -> None:
        if self.sensor in NETWORK_SENSORS and not interface:
            self.stop_child()
            self.status("WAITING_INTERFACE", "No eligible link is up")
            return
        if self.process and self.process.poll() is not None:
            code = self.process.returncode
            self.stop_child()
            self.next_start = time.monotonic() + 10
            self.status("FAILED", f"Sensor exited {code}; check journalctl and sensor.log")
            return
        if self.process and self.binding != interface:
            self.stop_child()
            self.next_start = 0
        if not self.process:
            if time.monotonic() < self.next_start:
                self.status("RETRY_WAIT", "Sensor restart backoff")
                return
            try:
                directory = LOG_ROOT / self.sensor
                directory.mkdir(parents=True, exist_ok=True)
                # Bound supervisor diagnostics independently of sensor event retention.
                self.output = (directory / "sensor.log").open("w")
                cwd = Path("/etc/campus-ops/sensors") if self.sensor == "opencanary" else directory
                self.process = subprocess.Popen(command_for(self.sensor, interface), cwd=cwd,
                                                stdout=self.output, stderr=subprocess.STDOUT)
                self.binding = interface
                self.started_at = time.time()
                self.restarts += 1
            except (OSError, ValueError) as exc:
                self.stop_child()
                self.next_start = time.monotonic() + 15
                self.status("FAILED", str(exc)[:240])
                return
        self.status("RUNNING", "Process alive; ingestion counters establish received evidence")

    async def run(self) -> None:
        def stop(*_args):
            self.stop_requested = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        discovery = NetworkDiscoveryWorker(EventBus())
        try:
            while not self.stop_requested:
                if self.sensor in NETWORK_SENSORS:
                    discovery.candidates = await asyncio.to_thread(discover_candidates)
                    await discovery._consider(elect_network(discovery.candidates))
                interface = discovery.selected.interface if discovery.selected else None
                self.tick(interface)
                await asyncio.sleep(2)
        finally:
            self.stop_child()
            self.status("STOPPED")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sensor", choices=["zeek", "suricata", "falco", "opencanary"])
    args = parser.parse_args()
    os.umask(0o027)
    asyncio.run(Supervisor(args.sensor).run())


if __name__ == "__main__":
    main()
