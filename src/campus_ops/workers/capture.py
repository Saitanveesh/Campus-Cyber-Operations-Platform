from __future__ import annotations

import asyncio
import datetime as dt

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.base import BaseWorker

FIELDS = (
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "arp.src.proto_ipv4",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmpv6.type",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "http.host",
    "dhcp.option.hostname",
)


class CaptureWorker(BaseWorker):
    """Passive live packet metadata capture through TShark/Npcap."""

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

    async def _wait_for_tshark(self) -> str | None:
        while not self.stopping:
            tshark = resolve_executable("tshark")
            if tshark:
                return tshark
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("TShark unavailable")
            self.state.set_capture(
                state="UNAVAILABLE",
                backend=None,
                detail="TShark not found. Install Wireshark with Npcap.",
            )
            await asyncio.sleep(3)
        return None

    async def run(self) -> None:
        tshark = await self._wait_for_tshark()
        if not tshark:
            return

        self.health.state = WorkerState.HEALTHY
        bound_interface: str | None = None
        while not self.stopping:
            interface = self.interface_provider()
            session_id = self.session_provider()
            if not interface or not session_id:
                self.state.set_capture(
                    state="WAITING",
                    interface=interface,
                    backend="tshark",
                    detail="waiting for active network session",
                )
                self.health.heartbeat("waiting for network")
                await asyncio.sleep(1)
                continue

            if bound_interface != interface or self._process is None or self._process.returncode is not None:
                if self._process and self._process.returncode is None:
                    self._process.terminate()
                    await self._process.wait()
                capture_interface = await self._resolve_interface(tshark, interface)
                command = [
                    tshark,
                    "-l",
                    "-n",
                    "-i",
                    capture_interface,
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-E",
                    "occurrence=f",
                ]
                for field in FIELDS:
                    command.extend(["-e", field])
                self._process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                bound_interface = interface
                self.health.state = WorkerState.HEALTHY
                self.state.set_capture(
                    state="ACTIVE",
                    interface=interface,
                    backend="tshark",
                    detail=f"capturing on {interface}",
                )

            assert self._process.stdout is not None
            try:
                raw = await asyncio.wait_for(self._process.stdout.readline(), timeout=2.0)
            except TimeoutError:
                self.state.set_capture(
                    state="LINK_UP_IDLE",
                    interface=interface,
                    backend="tshark",
                    detail="capture is running; no packet observed in the last 2 seconds",
                )
                self.health.heartbeat(f"capture healthy on {interface}; idle")
                continue
            if not raw:
                code = await self._process.wait()
                stderr_text = ""
                if self._process.stderr is not None:
                    stderr = await self._process.stderr.read()
                    stderr_text = stderr.decode(errors="replace").strip()[-300:]
                detail = f"TShark exited with code {code}"
                if stderr_text:
                    detail = f"{detail}: {stderr_text}"
                self.state.set_capture(state="ERROR", detail=detail)
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(detail)
                self._process = None
                await asyncio.sleep(2)
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
            tcp = bool(packet["tcp.srcport"] or packet["tcp.dstport"] or packet["tcp.flags"])
            udp = bool(packet["udp.srcport"] or packet["udp.dstport"])
            transport = "TCP" if tcp else "UDP" if udp else protocol
            src_port = packet["tcp.srcport"] or packet["udp.srcport"]
            dst_port = packet["tcp.dstport"] or packet["udp.dstport"]
            capture = self.state.get_capture()
            self.state.set_capture(
                packets=int(capture.get("packets", 0)) + 1,
                bytes=int(capture.get("bytes", 0)) + length,
                last_packet_at=dt.datetime.now(dt.UTC).isoformat(),
                state="ACTIVE",
                detail=f"capturing on {interface}",
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
                        "protocol_stack": packet["frame.protocols"],
                        "transport": transport,
                        "eth_src": packet["eth.src"],
                        "eth_dst": packet["eth.dst"],
                        "vlan_id": packet["vlan.id"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ip_ttl": packet["ip.ttl"],
                        "ipv6_hop_limit": packet["ipv6.hlim"],
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "dns_query": packet["dns.qry.name"],
                        "tls_sni": packet["tls.handshake.extensions_server_name"],
                        "http_host": packet["http.host"],
                        "dhcp_hostname": packet["dhcp.option.hostname"],
                        "tcp_flags": packet["tcp.flags"],
                        "tcp_window": packet["tcp.window_size_value"],
                        "tcp_ack_rtt": packet["tcp.analysis.ack_rtt"],
                        "tcp_retransmission": bool(packet["tcp.analysis.retransmission"]),
                        "tcp_fast_retransmission": bool(packet["tcp.analysis.fast_retransmission"]),
                        "tcp_duplicate_ack": bool(packet["tcp.analysis.duplicate_ack"]),
                        "icmp_type": packet["icmp.type"] or packet["icmpv6.type"],
                    },
                )
            )
            self.health.heartbeat(f"capture active on {interface}")
