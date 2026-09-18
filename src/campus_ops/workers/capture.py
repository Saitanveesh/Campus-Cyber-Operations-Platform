from __future__ import annotations

import asyncio
import datetime as dt
import os
from collections import deque

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.tooling.registry import resolve_executable
from campus_ops.windows_process import hidden_asyncio_subprocess_kwargs
from campus_ops.workers.base import BaseWorker

FIELDS = (
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "eth.src.oui_resolved",
    "eth.dst.oui_resolved",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "arp.opcode",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmpv6.type",
    "_ws.col.Protocol",
    "dns.qry.name",
    "dns.resp.name",
    "dns.ptr.domain_name",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.a",
    "dns.aaaa",
    "llmnr.qry.name",
    "llmnr.resp.name",
    "nbns.name",
    "tls.handshake.extensions_server_name",
    "tls.handshake.type",
    "tls.handshake.version",
    "http.host",
    "dhcp.option.hostname",
    "dhcp.option.dhcp_server_id",
    "dhcp.option.dhcp",
    "lldp.chassis.id",
    "lldp.port.id",
    "lldp.system.name",
)
SPECIAL_FIELDS = frozenset({"_ws.col.Protocol"})
FALLBACK_FIELDS = (
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "arp.src.proto_ipv4",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
)


class CaptureWorker(BaseWorker):
    """Single-source passive packet metadata capture.

    TShark is the only capture/decoder process managed by MON. A healthy process stays
    ACTIVE even when the wire is quiet. Packet silence is traffic activity, not link
    health, and therefore never changes the capture state or triggers a rebind.

    On Linux, Wireshark's dumpcap helper is only TShark's internal privilege helper.
    On Windows, TShark uses Npcap. MON does not run a second capture engine.
    """

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        session_provider,
        interface_provider,
    ) -> None:
        super().__init__("capture", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self._process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._stderr_lines: deque[str] = deque(maxlen=30)
        self._bound: tuple[str, str] | None = None
        self.active_fields: tuple[str, ...] = FALLBACK_FIELDS
        self._capture_candidates: list[str] = []
        self._candidate_index = 0

    async def _drain_stderr(self, process: asyncio.subprocess.Process) -> None:
        if process.stderr is None:
            return
        try:
            while True:
                raw = await process.stderr.readline()
                if not raw:
                    return
                text = raw.decode(errors="replace").strip()
                if text:
                    self._stderr_lines.append(text)
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError):
            return

    async def _stop_stderr_task(self) -> None:
        task = self._stderr_task
        self._stderr_task = None
        if task is None:
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _terminate(self) -> None:
        process = self._process
        self._process = None
        self._bound = None
        if process is not None and process.returncode is None:
            try:
                process.terminate()
            except (ProcessLookupError, OSError):
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=3.0)
            except TimeoutError:
                try:
                    process.kill()
                except (ProcessLookupError, OSError):
                    pass
                try:
                    await process.wait()
                except (ProcessLookupError, OSError):
                    pass
        await self._stop_stderr_task()

    async def stop(self) -> None:
        await self._terminate()
        await super().stop()

    async def _interface_candidates(self, tshark: str, requested: str) -> list[str]:
        if os.name != "nt":
            return [requested]
        try:
            process = await asyncio.create_subprocess_exec(
                tshark,
                "-D",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                **hidden_asyncio_subprocess_kwargs(),
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10.0)
        except (OSError, TimeoutError):
            return [requested]
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
        try:
            process = await asyncio.create_subprocess_exec(
                tshark,
                "-G",
                "fields",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                **hidden_asyncio_subprocess_kwargs(),
            )
        except OSError:
            return FALLBACK_FIELDS
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=20.0)
        except TimeoutError:
            try:
                process.kill()
            except (ProcessLookupError, OSError):
                pass
            await process.wait()
            return FALLBACK_FIELDS
        if process.returncode != 0:
            return FALLBACK_FIELDS
        supported: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                supported.add(parts[2])
        active = tuple(
            field for field in FIELDS if field in SPECIAL_FIELDS or field in supported
        )
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
                state="UNAVAILABLE",
                backend="tshark",
                process_pid=None,
                capture_device=None,
                traffic_activity="STOPPED",
                detail=(
                    "TShark not found. Run bash bootstrap.sh."
                    if os.name != "nt"
                    else "TShark not found. Install Wireshark with Npcap."
                ),
            )
            await asyncio.sleep(3)
        return None

    def _command(self, tshark: str, capture_device: str) -> list[str]:
        command = [
            tshark,
            "-l",
            "-n",
            "-i",
            capture_device,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
        ]
        for field in self.active_fields:
            command.extend(["-e", field])
        return command

    async def _start_capture(self, tshark: str, interface: str, session_id: str) -> None:
        await self._terminate()
        self._capture_candidates = await self._interface_candidates(tshark, interface)
        if not self._capture_candidates:
            raise RuntimeError(f"TShark could not resolve capture interface {interface}")
        capture_device = self._capture_candidates[
            self._candidate_index % len(self._capture_candidates)
        ]
        self._stderr_lines.clear()
        try:
            process = await asyncio.create_subprocess_exec(
                *self._command(tshark, capture_device),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=256 * 1024,
                **hidden_asyncio_subprocess_kwargs(),
            )
        except OSError as exc:
            raise RuntimeError(f"TShark could not start: {exc}") from exc

        try:
            code = await asyncio.wait_for(process.wait(), timeout=0.5)
        except TimeoutError:
            code = None
        if code is not None:
            detail = ""
            if process.stderr is not None:
                raw = await process.stderr.read()
                detail = raw.decode(errors="replace").strip()[-1200:]
            raise RuntimeError(detail or f"TShark exited with code {code}")

        self._process = process
        self._bound = (session_id, interface)
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(process),
            name=f"tshark-stderr-{process.pid}",
        )
        self.health.state = WorkerState.HEALTHY
        self.state.set_capture(
            state="ACTIVE",
            interface=interface,
            capture_device=capture_device,
            capture_session_id=session_id,
            backend="tshark",
            process_pid=process.pid,
            started_at=dt.datetime.now(dt.UTC).isoformat(),
            decoder_fields=len(self.active_fields),
            traffic_activity="STARTING",
            detail=f"capture active on {interface} via tshark",
        )

    def _advance_candidate(self) -> None:
        if len(self._capture_candidates) > 1:
            self._candidate_index = (self._candidate_index + 1) % len(self._capture_candidates)

    async def _mark_process_exit(
        self, process: asyncio.subprocess.Process, interface: str
    ) -> None:
        code = await process.wait()
        if self._stderr_task is not None and not self._stderr_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._stderr_task), timeout=0.5)
            except TimeoutError:
                pass
        detail = " | ".join(self._stderr_lines)[-1200:]
        message = f"TShark exited with code {code}"
        if detail:
            message += f": {detail}"
        self.state.set_capture(
            state="ERROR",
            interface=interface,
            backend="tshark",
            process_pid=None,
            traffic_activity="STOPPED",
            detail=message[-1400:],
        )
        self.health.state = WorkerState.DEGRADED
        self.health.heartbeat(message[-800:])
        self._process = None
        self._bound = None
        self._advance_candidate()
        await self._stop_stderr_task()

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
                await self._terminate()
                self._capture_candidates = []
                self.state.set_capture(
                    state="WAITING",
                    interface=interface,
                    capture_device=None,
                    capture_session_id=None,
                    backend="tshark",
                    process_pid=None,
                    traffic_activity="NONE",
                    detail="waiting for a confirmed active network interface",
                )
                self.health.heartbeat("waiting for network")
                await asyncio.sleep(1)
                continue

            binding = (session_id, interface)
            if binding != last_binding:
                self._capture_candidates = []
                self._candidate_index = 0
                last_binding = binding

            if (
                self._bound != binding
                or self._process is None
                or self._process.returncode is not None
            ):
                if self._process is not None and self._process.returncode is not None:
                    await self._mark_process_exit(self._process, interface)
                    await asyncio.sleep(5)
                try:
                    await self._start_capture(tshark, interface, session_id)
                except RuntimeError as exc:
                    detail = str(exc)
                    self._advance_candidate()
                    self.state.set_capture(
                        state="ERROR",
                        interface=interface,
                        capture_device=None,
                        capture_session_id=session_id,
                        backend="tshark",
                        process_pid=None,
                        traffic_activity="STOPPED",
                        detail=detail,
                    )
                    self.health.state = WorkerState.DEGRADED
                    self.health.heartbeat(detail)
                    await asyncio.sleep(5)
                    continue

            process = self._process
            assert process is not None and process.stdout is not None
            try:
                raw = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)
            except TimeoutError:
                if self._bound != (self.session_provider(), self.interface_provider()):
                    await self._terminate()
                    continue
                if process.returncode is not None:
                    await self._mark_process_exit(process, interface)
                    await asyncio.sleep(5)
                    continue

                # A quiet interval does not alter capture/link state and never restarts
                # TShark. The process is alive, therefore capture remains ACTIVE.
                self.state.set_capture(
                    state="ACTIVE",
                    interface=interface,
                    backend="tshark",
                    process_pid=process.pid,
                    traffic_activity="QUIET",
                    detail=f"capture active on {interface} via tshark",
                )
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat(
                    f"capture process healthy on {interface}; traffic quiet"
                )
                continue
            except (OSError, ValueError) as exc:
                await self._terminate()
                message = f"TShark output stream error: {exc}"
                self.state.set_capture(
                    state="ERROR",
                    interface=interface,
                    backend="tshark",
                    process_pid=None,
                    traffic_activity="STOPPED",
                    detail=message,
                )
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(message)
                await asyncio.sleep(5)
                continue

            if self._bound != (self.session_provider(), self.interface_provider()):
                await self._terminate()
                continue

            if not raw:
                await self._mark_process_exit(process, interface)
                await asyncio.sleep(5)
                continue

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
                last_packet_at=dt.datetime.now(dt.UTC).isoformat(),
                state="ACTIVE",
                interface=interface,
                backend="tshark",
                process_pid=process.pid,
                traffic_activity="PACKETS",
                decoder_fields=len(self.active_fields),
                detail=f"capture active on {interface} via tshark",
            )

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
                        "eth_src_vendor": packet["eth.src.oui_resolved"],
                        "eth_dst_vendor": packet["eth.dst.oui_resolved"],
                        "vlan_id": packet["vlan.id"],
                        "arp_target_ip": packet["arp.dst.proto_ipv4"],
                        "arp_opcode": packet["arp.opcode"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ip_ttl": packet["ip.ttl"],
                        "ipv6_hop_limit": packet["ipv6.hlim"],
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "dns_query": packet["dns.qry.name"],
                        "dns_response_name": packet["dns.resp.name"],
                        "dns_ptr_name": packet["dns.ptr.domain_name"],
                        "llmnr_name": packet["llmnr.qry.name"] or packet["llmnr.resp.name"],
                        "nbns_name": packet["nbns.name"],
                        "dns_is_response": packet["dns.flags.response"],
                        "dns_rcode": packet["dns.flags.rcode"],
                        "dns_a": packet["dns.a"],
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
                        "tcp_flags": packet["tcp.flags"],
                        "tcp_window": packet["tcp.window_size_value"],
                        "tcp_ack_rtt": packet["tcp.analysis.ack_rtt"],
                        "tcp_retransmission": bool(packet["tcp.analysis.retransmission"]),
                        "tcp_fast_retransmission": bool(
                            packet["tcp.analysis.fast_retransmission"]
                        ),
                        "tcp_duplicate_ack": bool(packet["tcp.analysis.duplicate_ack"]),
                        "tcp_lost_segment": bool(packet["tcp.analysis.lost_segment"]),
                        "tcp_out_of_order": bool(packet["tcp.analysis.out_of_order"]),
                        "icmp_type": packet["icmp.type"] or packet["icmpv6.type"],
                    },
                )
            )
            self.health.state = WorkerState.HEALTHY
            self.health.heartbeat(
                f"capture active on {interface} via tshark; fields={len(self.active_fields)}"
            )
