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
    """Passive packet metadata capture, hard-bound to one live session.

    Windows keeps TShark/Npcap direct capture. Linux deliberately separates the
    privileged acquisition plane from protocol decoding: dumpcap (preferred) or
    tcpdump acquires raw packets and writes pcap to a pipe, while an unprivileged
    TShark process only decodes stdin. This avoids the fragile TShark -> dumpcap
    privilege hand-off that caused repeated "wireshark-common" capture failures.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider, interface_provider) -> None:
        super().__init__("capture", bus)
        self.state = state
        self.session_provider = session_provider
        self.interface_provider = interface_provider
        self._process: asyncio.subprocess.Process | None = None
        self._acquirer: asyncio.subprocess.Process | None = None
        self._bound: tuple[str, str] | None = None
        self.active_fields: tuple[str, ...] = FALLBACK_FIELDS
        self._capture_candidates: list[str] = []
        self._candidate_index = 0
        self._idle_busy_checks = 0
        self._linux_backends: list[tuple[str, str]] = []
        self._linux_backend_index = 0
        self._active_backend = "tshark"

    async def _terminate(self, process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def _stop_process(self) -> None:
        decoder = self._process
        acquirer = self._acquirer
        self._process = None
        self._acquirer = None
        self._bound = None
        # Stop acquisition first so the decoder receives EOF on its pcap stream.
        await self._terminate(acquirer)
        await self._terminate(decoder)

    async def stop(self) -> None:
        await self._stop_process()
        await super().stop()

    async def _interface_candidates(self, tshark: str, requested: str) -> list[str]:
        if os.name != "nt":
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
                detail=("TShark not found. Run bash bootstrap.sh."
                        if os.name != "nt" else "TShark not found. Install Wireshark with Npcap."),
            )
            await asyncio.sleep(3)
        return None

    def _decoder_command(self, tshark: str, source_args: list[str]) -> list[str]:
        command = [tshark, "-l", "-n", *source_args, "-T", "fields",
                   "-E", "separator=\t", "-E", "occurrence=f"]
        for field in self.active_fields:
            command.extend(["-e", field])
        return command

    def _refresh_linux_backends(self) -> None:
        rows: list[tuple[str, str]] = []
        dumpcap = resolve_executable("dumpcap")
        tcpdump = resolve_executable("tcpdump")
        if dumpcap:
            rows.append(("dumpcap", dumpcap))
        if tcpdump:
            rows.append(("tcpdump", tcpdump))
        self._linux_backends = rows
        if self._linux_backend_index >= len(rows):
            self._linux_backend_index = 0

    async def _stderr_tail(self, process: asyncio.subprocess.Process | None, limit: int = 600) -> str:
        if process is None or process.stderr is None or process.returncode is None:
            return ""
        try:
            raw = await asyncio.wait_for(process.stderr.read(), timeout=1.0)
        except TimeoutError:
            return ""
        return raw.decode(errors="replace").strip()[-limit:]

    async def _spawn_linux_pipeline(
        self, tshark: str, interface: str, backend_name: str, backend_path: str
    ) -> tuple[asyncio.subprocess.Process | None, asyncio.subprocess.Process | None, str]:
        read_fd, write_fd = os.pipe()
        read_file = os.fdopen(read_fd, "rb", buffering=0)
        write_file = os.fdopen(write_fd, "wb", buffering=0)
        try:
            if backend_name == "dumpcap":
                acquire_command = [backend_path, "-q", "-i", interface, "-w", "-"]
            else:
                acquire_command = [backend_path, "-U", "-n", "-i", interface, "-w", "-"]
            acquirer = await asyncio.create_subprocess_exec(
                *acquire_command, stdout=write_file, stderr=asyncio.subprocess.PIPE
            )
            decoder = await asyncio.create_subprocess_exec(
                *self._decoder_command(tshark, ["-r", "-"]), stdin=read_file,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        finally:
            # Children have dup'd these descriptors; the parent must not keep the pipe open.
            read_file.close()
            write_file.close()

        await asyncio.sleep(0.25)
        if acquirer.returncode is not None:
            detail = await self._stderr_tail(acquirer)
            await self._terminate(decoder)
            return None, None, detail or f"{backend_name} exited with code {acquirer.returncode}"
        if decoder.returncode is not None:
            detail = await self._stderr_tail(decoder)
            await self._terminate(acquirer)
            return None, None, detail or f"TShark decoder exited with code {decoder.returncode}"
        return acquirer, decoder, ""

    async def _start_linux_capture(self, tshark: str, interface: str, session_id: str) -> None:
        self._refresh_linux_backends()
        if not self._linux_backends:
            raise RuntimeError("No Linux capture helper is installed (dumpcap/tcpdump). Run bash bootstrap.sh.")

        errors: list[str] = []
        total = len(self._linux_backends)
        for offset in range(total):
            index = (self._linux_backend_index + offset) % total
            backend_name, backend_path = self._linux_backends[index]
            acquirer, decoder, detail = await self._spawn_linux_pipeline(
                tshark, interface, backend_name, backend_path
            )
            if acquirer is None or decoder is None:
                errors.append(f"{backend_name}: {detail}")
                continue
            self._linux_backend_index = index
            self._acquirer = acquirer
            self._process = decoder
            self._active_backend = f"{backend_name}+tshark"
            self._bound = (session_id, interface)
            self._idle_busy_checks = 0
            self.health.state = WorkerState.HEALTHY
            self.state.set_capture(
                state="ACTIVE", interface=interface, capture_device=interface,
                capture_session_id=session_id, backend=self._active_backend,
                process_pid=decoder.pid, acquirer_pid=acquirer.pid,
                started_at=dt.datetime.now(dt.UTC).isoformat(), decoder_fields=len(self.active_fields),
                detail=f"capturing on {interface} via {self._active_backend}",
            )
            return

        joined = " | ".join(errors)[-1200:]
        raise RuntimeError(
            f"Linux packet acquisition could not open {interface}. {joined}. "
            "Run 'bash bootstrap.sh' so capture capabilities are repaired."
        )

    async def _start_capture(self, tshark: str, interface: str, session_id: str) -> None:
        await self._stop_process()
        if os.name != "nt":
            await self._start_linux_capture(tshark, interface, session_id)
            return

        if not self._capture_candidates:
            self._capture_candidates = await self._interface_candidates(tshark, interface)
            self._candidate_index = 0
        capture_interface = self._capture_candidates[self._candidate_index % len(self._capture_candidates)]
        self._process = await asyncio.create_subprocess_exec(
            *self._decoder_command(tshark, ["-i", capture_interface]),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self._active_backend = "tshark"
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
        if os.name == "nt":
            if len(self._capture_candidates) > 1:
                self._candidate_index = (self._candidate_index + 1) % len(self._capture_candidates)
            else:
                self._capture_candidates = await self._interface_candidates(tshark, interface)
        self.health.state = WorkerState.DEGRADED
        self.health.heartbeat("OS traffic is active but decoder is idle; rebinding capture")
        self.state.set_capture(
            state="REBINDING", interface=interface, backend=self._active_backend,
            detail="OS traffic is active but no packets are decoded; automatically rebinding capture",
        )
        await self._start_capture(tshark, interface, session_id)
        return True

    async def _pipeline_failure(self) -> str | None:
        if os.name == "nt" or self._acquirer is None:
            return None
        if self._acquirer.returncode is None:
            return None
        detail = await self._stderr_tail(self._acquirer)
        backend = self._active_backend.split("+", 1)[0]
        if len(self._linux_backends) > 1:
            self._linux_backend_index = (self._linux_backend_index + 1) % len(self._linux_backends)
        return f"{backend} acquisition stopped with code {self._acquirer.returncode}: {detail}".rstrip()

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
                    state="WAITING", interface=interface, backend=self._active_backend,
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
                self._linux_backend_index = 0
                last_binding = binding
            if self._bound != binding or self._process is None or self._process.returncode is not None:
                try:
                    await self._start_capture(tshark, interface, session_id)
                except RuntimeError as exc:
                    detail = str(exc)
                    self.state.set_capture(state="ERROR", interface=interface, detail=detail)
                    self.health.state = WorkerState.DEGRADED
                    self.health.heartbeat(detail)
                    await asyncio.sleep(3)
                    continue

            process = self._process
            assert process is not None and process.stdout is not None
            try:
                raw = await asyncio.wait_for(process.stdout.readline(), timeout=2.0)
            except TimeoutError:
                if self._bound != (self.session_provider(), self.interface_provider()):
                    continue
                acquisition_error = await self._pipeline_failure()
                if acquisition_error:
                    self.state.set_capture(state="REBINDING", interface=interface, detail=acquisition_error)
                    self.health.state = WorkerState.DEGRADED
                    self.health.heartbeat(acquisition_error)
                    await self._start_capture(tshark, interface, session_id)
                    continue
                if await self._recover_busy_idle(tshark, interface, session_id):
                    continue
                self.state.set_capture(
                    state="LINK_UP_IDLE", interface=interface, backend=self._active_backend,
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
                decoder_error = await self._stderr_tail(process)
                acquisition_error = await self._pipeline_failure()
                detail = f"TShark decoder exited with code {code}"
                if decoder_error:
                    detail += f": {decoder_error}"
                if acquisition_error:
                    detail += f" | {acquisition_error}"
                self.state.set_capture(state="ERROR", interface=interface, detail=detail[-1400:])
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(detail[-800:])
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
                backend=self._active_backend, decoder_fields=len(self.active_fields),
                detail=f"capturing on {interface} via {self._active_backend}",
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
            self.health.heartbeat(
                f"capture active on {interface} via {self._active_backend}; fields={len(self.active_fields)}"
            )
