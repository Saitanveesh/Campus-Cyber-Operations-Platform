from __future__ import annotations

import asyncio
import os
import shutil
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.workers.base import BaseWorker

OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
}

WALK_OIDS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
}


class SnmpPollerWorker(BaseWorker):
    """Optional read-only SNMP/LLDP telemetry for explicitly configured infrastructure."""

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
        return self._clean_value(stdout.decode(errors="replace").strip())

    async def _walk(self, executable: str, target: str, oid: str) -> list[dict[str, str]]:
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
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=8.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            return []
        if process.returncode != 0:
            return []
        rows: list[dict[str, str]] = []
        for raw_line in stdout.decode(errors="replace").splitlines()[:1000]:
            line = raw_line.strip()
            if not line or " = " not in line:
                continue
            key, value = line.split(" = ", 1)
            rows.append({"oid": key.strip(), "value": self._clean_value(value) or ""})
        return rows

    @staticmethod
    def _clean_value(text: str) -> str | None:
        value = text.strip()
        if ": " in value:
            value = value.split(": ", 1)[1]
        value = value.strip('"')
        return value or None

    @staticmethod
    def _index_from_oid(oid: str) -> str:
        return oid.rsplit(".", 1)[-1] if "." in oid else oid

    @classmethod
    def _interfaces(cls, tables: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
        combined: dict[str, dict[str, Any]] = {}
        for field in ("ifName", "ifAlias", "ifOperStatus"):
            for row in tables.get(field, []):
                index = cls._index_from_oid(row.get("oid", ""))
                combined.setdefault(index, {"ifIndex": index})[field] = row.get("value")
        return list(combined.values())[:500]

    @classmethod
    def _lldp_neighbors(cls, tables: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
        names = tables.get("lldpRemSysName", [])
        ports = tables.get("lldpRemPortDesc", [])
        port_map = {row.get("oid", "").rsplit(".", 3)[-3:][0]: row.get("value") for row in ports}
        neighbors = []
        for row in names:
            oid = row.get("oid", "")
            parts = oid.split(".")
            key = parts[-3] if len(parts) >= 3 else cls._index_from_oid(oid)
            neighbors.append(
                {
                    "system_name": row.get("value"),
                    "remote_port": port_map.get(key),
                    "source_oid": oid,
                }
            )
        return neighbors[:250]

    async def run(self) -> None:
        snmpget = shutil.which("snmpget") or shutil.which("snmpget.exe")
        snmpwalk = shutil.which("snmpwalk") or shutil.which("snmpwalk.exe")
        if not self.targets:
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat("SNMP/LLDP not configured")
            while not self.stopping:
                await asyncio.sleep(10)
            return
        if snmpget is None:
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("SNMP targets configured but snmpget is unavailable")
            while not self.stopping:
                await asyncio.sleep(10)
            return

        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            responsive = 0
            for target in self.targets:
                values = {name: await self._get(snmpget, target, oid) for name, oid in OIDS.items()}
                if not any(values.values()):
                    continue
                responsive += 1
                tables: dict[str, list[dict[str, str]]] = {}
                if snmpwalk:
                    for name, oid in WALK_OIDS.items():
                        tables[name] = await self._walk(snmpwalk, target, oid)
                if session_id:
                    await self.bus.publish(
                        Event(
                            source=self.name,
                            kind=EventKind.OBSERVATION,
                            session_id=session_id,
                            evidence_class="SNMP_READ_ONLY",
                            payload={
                                "type": "SNMP_INFRASTRUCTURE_TELEMETRY",
                                "target": target,
                                **values,
                                "interfaces": self._interfaces(tables),
                                "lldp_neighbors": self._lldp_neighbors(tables),
                                "lldp_available": bool(tables.get("lldpRemSysName")),
                            },
                        )
                    )
            self.health.heartbeat(
                f"configured={len(self.targets)} responsive={responsive} lldp={'yes' if snmpwalk else 'no'}"
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
