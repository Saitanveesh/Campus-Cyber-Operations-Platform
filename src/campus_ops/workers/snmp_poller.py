from __future__ import annotations

import asyncio
import os
import shutil

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.workers.base import BaseWorker

OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
}


class SnmpPollerWorker(BaseWorker):
    """Optional read-only SNMP inventory poller for configured infrastructure devices."""

    def __init__(self, bus: EventBus, session_provider, interval: float = 60.0) -> None:
        super().__init__("snmp-poller", bus)
        self.session_provider = session_provider
        self.interval = interval
        raw_targets = os.environ.get("CAMPUS_OPS_SNMP_TARGETS", "")
        self.targets = [item.strip() for item in raw_targets.split(",") if item.strip()]
        self.community = os.environ.get("CAMPUS_OPS_SNMP_COMMUNITY", "public")

    async def _get(self, executable: str, target: str, oid: str) -> str | None:
        process = await asyncio.create_subprocess_exec(
            executable,
            "-v2c",
            "-c",
            self.community,
            "-t",
            "1",
            "-r",
            "0",
            target,
            oid,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=4.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            return None
        if process.returncode != 0:
            return None
        text = stdout.decode(errors="replace").strip()
        if " = " in text:
            text = text.split(" = ", 1)[1]
        if ": " in text:
            text = text.split(": ", 1)[1]
        return text.strip('"') or None

    async def run(self) -> None:
        executable = shutil.which("snmpget") or shutil.which("snmpget.exe")
        if not self.targets:
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat("SNMP not configured")
            while not self.stopping:
                await asyncio.sleep(10)
            return
        if executable is None:
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("SNMP targets configured but snmpget is unavailable")
            while not self.stopping:
                await asyncio.sleep(10)
            return

        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            for target in self.targets:
                values = {}
                for name, oid in OIDS.items():
                    values[name] = await self._get(executable, target, oid)
                if session_id and any(values.values()):
                    await self.bus.publish(
                        Event(
                            source=self.name,
                            kind=EventKind.OBSERVATION,
                            session_id=session_id,
                            evidence_class="SNMP_READ_ONLY",
                            payload={"type": "SNMP_TELEMETRY", "target": target, **values},
                        )
                    )
            self.health.heartbeat(f"targets={len(self.targets)}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
