from __future__ import annotations

import asyncio
import json
import os
import subprocess
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


def default_registry_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    root.mkdir(parents=True, exist_ok=True)
    return root / "endpoints.json"


class EndpointControl:
    """Explicit-enrollment remote-access launcher for authorized lab systems.

    The platform never turns a merely observed host into a controllable host. An
    operator must first enroll the endpoint and choose the permitted protocols.
    """

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
        temp.write_text(json.dumps([asdict(item) for item in self._items.values()], indent=2), encoding="utf-8")
        temp.replace(self.path)

    def list(self) -> list[dict[str, object]]:
        return [asdict(item) for item in sorted(self._items.values(), key=lambda item: item.name.lower())]

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
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            del reader
            return True
        except (OSError, TimeoutError):
            return False

    async def connect(self, endpoint_id: str, protocol: Literal["rdp", "ssh"]) -> dict[str, object]:
        endpoint = self._items.get(endpoint_id)
        if endpoint is None:
            raise KeyError("endpoint is not enrolled")
        allowed = endpoint.allow_rdp if protocol == "rdp" else endpoint.allow_ssh
        if not allowed:
            raise PermissionError(f"{protocol.upper()} is not permitted for this enrolled endpoint")
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
                    "voice": f"Connecting to {endpoint.name}. Please wait.",
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
                        "voice": f"Connection to {endpoint.name} failed. Service is unreachable.",
                    },
                )
            )
            return {"status": "FAILED", "reason": "SERVICE_UNREACHABLE"}

        if os.name == "nt":
            if protocol == "rdp":
                subprocess.Popen(["mstsc.exe", f"/v:{endpoint.host}"], close_fds=True)
            else:
                terminal = "wt.exe" if subprocess.run(["where", "wt.exe"], capture_output=True, check=False).returncode == 0 else "cmd.exe"
                if terminal == "wt.exe":
                    subprocess.Popen([terminal, "ssh", endpoint.host], close_fds=True)
                else:
                    subprocess.Popen([terminal, "/k", "ssh", endpoint.host], close_fds=True)
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
                    "voice": f"Connection to {endpoint.name} is available. Opening {protocol.upper()}.",
                },
            )
        )
        return {"status": "LAUNCHED", "protocol": protocol, "host": endpoint.host}
