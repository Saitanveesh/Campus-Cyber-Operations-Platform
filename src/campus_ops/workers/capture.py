from __future__ import annotations

import asyncio
import datetime as dt
import os

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.base import BaseWorker

FIELDS = (
    "frame.len", "frame.protocols", "eth.src", "eth.dst", "eth.src.oui_resolved",
    "eth.dst.oui_resolved", "vlan.id", "ip.src", "ip.dst", "ip.ttl", "ipv6.src",
    "ipv6.dst", "ipv6.hlim", "arp.src.proto_ipv4", "tcp.srcport", "tcp.dstport",
    "tcp.flags", "tcp.window_size_value", "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.out_of_order",
    "udp.srcport", "udp.dstport", "icmp.type", "icmpv6.type", "_ws.col.Protocol",
    "dns.qry.name", "dns.flags.response", "dns.flags.rcode", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "tls.handshake.type", "tls.handshake.version",
    "http.host", "dhcp.option.hostname", "dhcp.option.dhcp_server_id", "dhcp.option.dhcp",
    "lldp.chassis.id", "lldp.port.id", "lldp.system.name",
)
SPECIAL_FIELDS = frozenset({"_ws.col.Protocol"})
FALLBACK_FIELDS = (
    "frame.len", "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "tcp.srcport", "tcp.dstport",
    "tcp.flags", "udp.srcport", "udp.dstport", "_ws.col.Protocol", "dns.qry.name",
    "tls.handshake.extensions_server_name",
)


class CaptureWorker(BaseWorker):
    """Passive packet metadata capture through TShark/Npcap, hard-bound to one live session."""

    def __init__(self, bus: EventBus, state: LiveState, session_provider, interface_provider) -> None:
        super().__init__("capture", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self._process: asyncio.subprocess.Process | None = None
        self._bound: tuple[str, str] | None = None
        self.active_fields: tuple[str, ...] = FALLBACK_FIELDS
        self._capture_candidates: list[str] = []
        self._candidate_index = 0
        self._idle_busy_checks = 0

    async def _stop_process(self) -> None:
        process = self._process
        self._process = None
        self._bound = None
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3.0)
            except TimeoutError:
                process.kill()
                await process.wait()

    async def stop(self) -> None:
        await self._stop_process()
        await super().stop()

    async def _interface_candidates(self, tshark: str, requested: str) -> list[str]:
        if os.name != "nt":
            # Linux interface names are stable; numeric capture indexes change on hotplug.
            return [requested]
        process = await asyncio.create_subprocess_exec(
            tshark, "-D", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await process.communicate()
        requested_lower = requested.casefold().strip()
        exact: list[str] = []
        fuzzy: list[str] = []
        for line in stdout.decode(errors="replace").splitlines():
            if "." not in line:
                continue
            index, description = line.split(".", 1)
            index = index.strip()
            lowered = description.casefold()
            if f"({requested_lower})" in lowered or lowered.strip() == requested_lower:
                exact.append(index)
            elif requested_lower and requested_lower in lowered:
                fuzzy.append(index)
        ordered: list[str] = []
        for value in [*exact, *fuzzy, requested]:
            if value and value not in ordered:
                ordered.append(value)
        return ordered

    async def _discover_fields(self, tshark: str) -> tuple[str, ...]:
        process = await asyncio.create_subprocess_exec(
            tshark, "-G", "fields", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=20.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            return FALLBACK_FIELDS
        if process.returncode != 0:
            return FALLBACK_FIELDS
        supported: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                supported.add(parts[2])
        active = tuple(field for field in FIELDS if field in SPECIAL_FIELDS or field in supported)
        if "frame.len" not in active or "eth.src" not in active:
            return FALLBACK_FIELDS
        return active

    async def _wait_for_tshark(self) -> str | None:
        while not self.stopping:
            tshark = resolve_executable("tshark")
            if tshark:
                return tshark
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat("TShark unavailable")
            self.state.set_capture(
                state="UNAVAILABLE", backend=None,
                detail=("TShark not found. Run sudo bash scripts/install_ubuntu.sh."
                        if os.name != "nt" else "TShark not found. Install Wireshark with Npcap."),
            )
            await asyncio.sleep(3)
        return None

    async def _start_capture(self, tshark: str, interface: str, session_id: str) -> None:
        await self._stop_process()
        if not self._capture_candidates:
            self._capture_candidates = await self._interface_candidates(tshark, interface)
            self._candidate_index = 0
        capture_interface = self._capture_candidates[self._candidate_index % len(self._capture_candidates)]
        command = [
            tshark, "-l", "-n", "-i", capture_interface, "-T", "fields",
            "-E", "separator=\t", "-E", "occurrence=f",
        ]
        for field in self.active_fields:
            command.extend(["-e", field])
        self._process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        self._bound = (session_id, interface)
        self._idle_busy_checks = 0
        self.health.state = WorkerState.HEALTHY
        self.state.set_capture(
            state="ACTIVE", interface=interface, capture_device=capture_interface,
            capture_session_id=session_id, backend="tshark", process_pid=self._process.pid,
            started_at=dt.datetime.now(dt.UTC).isoformat(), decoder_fields=len(self.active_fields),
            detail=f"capturing on {interface} via device {capture_interface}",
        )

    def _rx_pps(self) -> float:
        try:
            return float(self.state.snapshot().get("metrics", {}).get("rx_pps") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    async def _recover_busy_idle(self, tshark: str, interface: str, session_id: str) -> bool:
        if self._rx_pps() < 5.0:
            self._idle_busy_checks = 0
            return False
        self._idle_busy_checks += 1
        if self._idle_busy_checks < 3:
            return False
        if len(self._capture_candidates) > 1:
            self._candidate_index = (self._candidate_index + 1) % len(self._capture_candidates)
        else:
            self._capture_candidates = await self._interface_candidates(tshark, interface)
        self.health.state = WorkerState.DEGRADED
        self.health.heartbeat("OS traffic is active but decoder is idle; rebinding capture device")
        self.state.set_capture(
            state="REBINDING", interface=interface, backend="tshark",
            detail="OS traffic is active but no packets are decoded; automatically rebinding Npcap/TShark",
        )
        await self._start_capture(tshark, interface, session_id)
        return True

    async def run(self) -> None:
        tshark = await self._wait_for_tshark()
        if not tshark:
            return
        self.active_fields = await self._discover_fields(tshark)
        self.health.state = WorkerState.HEALTHY
        last_binding: tuple[str, str] | None = None
        while not self.stopping:
            interface = self.interface_provider()
            session_id = self.session_provider()
            if not interface or not session_id:
                await self._stop_process()
                self._capture_candidates = []
                self.state.set_capture(
                    state="WAITING", interface=interface, backend="tshark",
                    detail="waiting for active network session",
                )
                self.health.heartbeat("waiting for network")
                await asyncio.sleep(1)
                continue

            binding = (session_id, interface)
            if binding != last_binding:
                self._capture_candidates = []
                self._candidate_index = 0
                self._idle_busy_checks = 0
                last_binding = binding
            if self._bound != binding or self._process is None or self._process.returncode is not None:
                await self._start_capture(tshark, interface, session_id)

            process = self._process
            assert process is not None and process.stdout is not None
            try:
                raw = await asyncio.wait_for(process.stdout.readline(), timeout=2.0)
            except TimeoutError:
                if self._bound != (self.session_provider(), self.interface_provider()):
                    continue
                if await self._recover_busy_idle(tshark, interface, session_id):
                    continue
                self.state.set_capture(
                    state="LINK_UP_IDLE", interface=interface, backend="tshark",
                    decoder_fields=len(self.active_fields),
                    detail="capture backend is running; waiting for packets",
                )
                self.health.heartbeat(f"capture healthy on {interface}; idle")
                continue

            if self._bound != (self.session_provider(), self.interface_provider()):
                await self._stop_process()
                continue
            if not raw:
                code = await process.wait()
                stderr_text = ""
                if process.stderr is not None:
                    stderr = await process.stderr.read()
                    stderr_text = stderr.decode(errors="replace").strip()[-300:]
                detail = f"TShark exited with code {code}"
                if stderr_text:
                    detail = f"{detail}: {stderr_text}"
                self.state.set_capture(state="ERROR", detail=detail)
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(detail)
                self._process = None
                self._bound = None
                await asyncio.sleep(2)
                continue

            self._idle_busy_checks = 0
            values = raw.decode(errors="replace").rstrip("\r\n").split("\t")
            values += [""] * (len(self.active_fields) - len(values))
            packet = {field: "" for field in FIELDS}
            packet.update(dict(zip(self.active_fields, values, strict=False)))
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
                last_packet_at=dt.datetime.now(dt.UTC).isoformat(), state="ACTIVE",
                decoder_fields=len(self.active_fields), detail=f"capturing on {interface}",
            )
            await self.bus.publish(Event(
                source=self.name, kind=EventKind.OBSERVATION, session_id=session_id,
                evidence_class="PASSIVE_PACKET_METADATA",
                payload={
                    "type": "PACKET", "length": length, "protocol": protocol,
                    "protocol_stack": packet["frame.protocols"], "transport": transport,
                    "eth_src": packet["eth.src"], "eth_dst": packet["eth.dst"],
                    "eth_src_vendor": packet["eth.src.oui_resolved"],
                    "eth_dst_vendor": packet["eth.dst.oui_resolved"],
                    "vlan_id": packet["vlan.id"], "src_ip": src_ip, "dst_ip": dst_ip,
                    "ip_ttl": packet["ip.ttl"], "ipv6_hop_limit": packet["ipv6.hlim"],
                    "src_port": src_port, "dst_port": dst_port,
                    "dns_query": packet["dns.qry.name"],
                    "dns_is_response": packet["dns.flags.response"],
                    "dns_rcode": packet["dns.flags.rcode"], "dns_a": packet["dns.a"],
                    "dns_aaaa": packet["dns.aaaa"],
                    "tls_sni": packet["tls.handshake.extensions_server_name"],
                    "tls_handshake_type": packet["tls.handshake.type"],
                    "tls_version": packet["tls.handshake.version"],
                    "http_host": packet["http.host"],
                    "dhcp_hostname": packet["dhcp.option.hostname"],
                    "dhcp_server_id": packet["dhcp.option.dhcp_server_id"],
                    "dhcp_message_type": packet["dhcp.option.dhcp"],
                    "lldp_chassis_id": packet["lldp.chassis.id"],
                    "lldp_port_id": packet["lldp.port.id"],
                    "lldp_system_name": packet["lldp.system.name"],
                    "tcp_flags": packet["tcp.flags"], "tcp_window": packet["tcp.window_size_value"],
                    "tcp_ack_rtt": packet["tcp.analysis.ack_rtt"],
                    "tcp_retransmission": bool(packet["tcp.analysis.retransmission"]),
                    "tcp_fast_retransmission": bool(packet["tcp.analysis.fast_retransmission"]),
                    "tcp_duplicate_ack": bool(packet["tcp.analysis.duplicate_ack"]),
                    "tcp_lost_segment": bool(packet["tcp.analysis.lost_segment"]),
                    "tcp_out_of_order": bool(packet["tcp.analysis.out_of_order"]),
                    "icmp_type": packet["icmp.type"] or packet["icmpv6.type"],
                },
            ))
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat(f"capture active on {interface}; fields={len(self.active_fields)}")
