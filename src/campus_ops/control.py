from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity


@dataclass(frozen=True, slots=True)
class EnrolledEndpoint:
    endpoint_id: str
    name: str
    host: str
    platform: Literal["windows", "linux", "other"]
    allow_rdp: bool = False
    allow_ssh: bool = False
    ssh_user: str = ""


def default_registry_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root / "endpoints.json"


class EndpointControl:
    """Explicit-enrollment remote-access launcher for authorized lab systems."""

    def __init__(self, bus: EventBus, session_provider, path: Path | None = None) -> None:
        self.bus = bus
        self.session_provider = session_provider
        self.path = path or default_registry_path()
        self._items: dict[str, EnrolledEndpoint] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                endpoint = EnrolledEndpoint(**item)
                self._items[endpoint.endpoint_id] = endpoint
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._items = {}

    def _save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(
            json.dumps([asdict(item) for item in self._items.values()], indent=2),
            encoding="utf-8",
        )
        temp.replace(self.path)

    def list(self) -> list[dict[str, object]]:
        return [
            asdict(item)
            for item in sorted(self._items.values(), key=lambda item: item.name.lower())
        ]

    def enroll(self, endpoint: EnrolledEndpoint) -> dict[str, object]:
        self._items[endpoint.endpoint_id] = endpoint
        self._save()
        return asdict(endpoint)

    def remove(self, endpoint_id: str) -> bool:
        removed = self._items.pop(endpoint_id, None)
        if removed:
            self._save()
        return removed is not None

    async def _port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            del reader
            return True
        except (OSError, TimeoutError):
            return False

    async def _windows_terminal_available(self) -> bool:
        process = await asyncio.create_subprocess_exec(
            "where.exe",
            "wt.exe",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await process.wait() == 0

    async def _launch_windows_client(self, endpoint: EnrolledEndpoint, protocol: str) -> None:
        if protocol == "rdp":
            await asyncio.create_subprocess_exec(
                "mstsc.exe",
                f"/v:{endpoint.host}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            return

        ssh_target = f"{endpoint.ssh_user}@{endpoint.host}" if endpoint.ssh_user else endpoint.host
        if await self._windows_terminal_available():
            await asyncio.create_subprocess_exec(
                "wt.exe",
                "ssh",
                ssh_target,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        else:
            await asyncio.create_subprocess_exec(
                "cmd.exe",
                "/k",
                "ssh",
                ssh_target,
            )

    async def connect(
        self,
        endpoint_id: str,
        protocol: Literal["rdp", "ssh"],
    ) -> dict[str, object]:
        endpoint = self._items.get(endpoint_id)
        if endpoint is None:
            raise KeyError("endpoint is not enrolled")
        allowed = endpoint.allow_rdp if protocol == "rdp" else endpoint.allow_ssh
        if not allowed:
            raise PermissionError(
                f"{protocol.upper()} is not permitted for this enrolled endpoint"
            )
        port = 3389 if protocol == "rdp" else 22
        session_id = self.session_provider()
        await self.bus.publish(
            Event(
                source="endpoint-control",
                kind=EventKind.ACTION,
                session_id=session_id,
                payload={
                    "action": "CONNECT_START",
                    "endpoint_id": endpoint.endpoint_id,
                    "protocol": protocol,
                    "message": f"Connecting to {endpoint.name}",
                },
            )
        )
        reachable = await self._port_open(endpoint.host, port)
        if not reachable:
            await self.bus.publish(
                Event(
                    source="endpoint-control",
                    kind=EventKind.ACTION,
                    session_id=session_id,
                    severity=Severity.MEDIUM,
                    payload={
                        "action": "CONNECT_FAILED",
                        "endpoint_id": endpoint.endpoint_id,
                        "protocol": protocol,
                        "message": f"Connection to {endpoint.name} failed: service unreachable",
                    },
                )
            )
            return {"status": "FAILED", "reason": "SERVICE_UNREACHABLE"}

        if os.name == "nt":
            await self._launch_windows_client(endpoint, protocol)
        await self.bus.publish(
            Event(
                source="endpoint-control",
                kind=EventKind.ACTION,
                session_id=session_id,
                payload={
                    "action": "CONNECT_READY",
                    "endpoint_id": endpoint.endpoint_id,
                    "protocol": protocol,
                    "message": f"Connection service available on {endpoint.name}",
                },
            )
        )
        return {
            "status": "LAUNCHED",
            "protocol": protocol,
            "host": endpoint.host,
            "ssh_user": endpoint.ssh_user if protocol == "ssh" else "",
        }
