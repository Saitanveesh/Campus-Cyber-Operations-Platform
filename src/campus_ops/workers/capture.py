from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


FIELDS = (
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "arp.src.proto_ipv4",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "tcp.flags",
)


class CaptureWorker(BaseWorker):
    """Passive live packet metadata capture through TShark/Npcap.

    Only metadata required by observability workers is emitted. Payload content is
    not retained here. If TShark is unavailable the worker fails closed and the UI
    exposes capture as unavailable rather than displaying stale data.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider, interface_provider) -> None:
        super().__init__("capture", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self._process: asyncio.subprocess.Process | None = None

    async def stop(self) -> None:
        if self._process and self._process.returncode is None:
            self._process.terminate()
        await super().stop()

    async def _resolve_interface(self, tshark: str, requested: str) -> str:
        process = await asyncio.create_subprocess_exec(
            tshark,
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

    async def run(self) -> None:
        tshark = shutil.which("tshark")
        if tshark is None:
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("TShark unavailable; install Wireshark/Npcap")
            self.state.set_capture(state="UNAVAILABLE", backend=None, detail="TShark not installed")
            while not self.stopping:
                await asyncio.sleep(2)
            return

        self.health.state = WorkerState.HEALTHY
        bound_interface: str | None = None
        while not self.stopping:
            interface = self.interface_provider()
            session_id = self.session_provider()
            if not interface or not session_id:
                self.state.set_capture(state="WAITING", interface=interface, backend="tshark", detail="waiting for active network session")
                self.health.heartbeat("waiting for network")
                await asyncio.sleep(1)
                continue

            if bound_interface != interface or self._process is None or self._process.returncode is not None:
                if self._process and self._process.returncode is None:
                    self._process.terminate()
                    await self._process.wait()
                capture_interface = await self._resolve_interface(tshark, interface)
                command = [tshark, "-l", "-n", "-i", capture_interface, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
                for field in FIELDS:
                    command.extend(["-e", field])
                self._process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                bound_interface = interface
                self.state.set_capture(state="ACTIVE", interface=interface, backend="tshark", detail="passive metadata capture active")

            assert self._process.stdout is not None
            try:
                raw = await asyncio.wait_for(self._process.stdout.readline(), timeout=2.0)
            except TimeoutError:
                self.health.heartbeat(f"capture active on {interface}; no packet in last 2s")
                continue
            if not raw:
                code = await self._process.wait()
                self.state.set_capture(state="ERROR", detail=f"TShark exited with code {code}")
                self.health.state = WorkerState.DEGRADED
                self._process = None
                await asyncio.sleep(1)
                continue

            values = raw.decode(errors="replace").rstrip("\r\n").split("\t")
            values += [""] * (len(FIELDS) - len(values))
            packet = dict(zip(FIELDS, values, strict=False))
            try:
                length = int(packet["frame.len"] or 0)
            except ValueError:
                length = 0
            protocol = packet["_ws.col.Protocol"] or "UNKNOWN"
            src_ip = packet["ip.src"] or packet["ipv6.src"] or packet["arp.src.proto_ipv4"]
            dst_ip = packet["ip.dst"] or packet["ipv6.dst"]
            src_port = packet["tcp.srcport"] or packet["udp.srcport"]
            dst_port = packet["tcp.dstport"] or packet["udp.dstport"]
            capture = self.state.capture
            self.state.set_capture(
                packets=int(capture.get("packets", 0)) + 1,
                bytes=int(capture.get("bytes", 0)) + length,
                last_packet_at=datetime.now(UTC).isoformat(),
                state="ACTIVE",
            )
            self.state.increment_protocol(protocol)
            await self.bus.publish(
                Event(
                    source=self.name,
                    kind=EventKind.OBSERVATION,
                    session_id=session_id,
                    evidence_class="PASSIVE_PACKET_METADATA",
                    payload={
                        "type": "PACKET",
                        "length": length,
                        "protocol": protocol,
                        "eth_src": packet["eth.src"],
                        "eth_dst": packet["eth.dst"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "dns_query": packet["dns.qry.name"],
                        "tls_sni": packet["tls.handshake.extensions_server_name"],
                        "tcp_flags": packet["tcp.flags"],
                    },
                )
            )
            self.health.heartbeat(f"capture active on {interface}")
