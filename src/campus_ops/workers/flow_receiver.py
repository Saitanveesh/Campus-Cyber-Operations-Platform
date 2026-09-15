from __future__ import annotations

import asyncio
import ipaddress
import os
import struct
from dataclasses import dataclass
from typing import Any

from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, WorkerState
from campus_ops.workers.base import BaseWorker


@dataclass(slots=True)
class IpfixField:
    field_id: int
    length: int
    enterprise: int | None = None


class IpfixTemplateCache:
    def __init__(self) -> None:
        self.templates: dict[tuple[str, int, int], list[IpfixField]] = {}

    def store(self, exporter: str, domain: int, template_id: int, fields: list[IpfixField]) -> None:
        self.templates[(exporter, domain, template_id)] = fields

    def get(self, exporter: str, domain: int, template_id: int) -> list[IpfixField] | None:
        return self.templates.get((exporter, domain, template_id))


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def decode_netflow_v5(data: bytes, exporter: str) -> list[dict[str, Any]]:
    if len(data) < 24:
        return []
    version, count, sys_uptime, unix_secs, unix_nsecs, sequence, engine_type, engine_id, sampling = struct.unpack(
        "!HHIIIIBBH", data[:24]
    )
    if version != 5:
        return []
    records: list[dict[str, Any]] = []
    offset = 24
    for _ in range(min(count, 1000)):
        if offset + 48 > len(data):
            break
        chunk = data[offset : offset + 48]
        (
            src,
            dst,
            next_hop,
            input_if,
            output_if,
            packets,
            octets,
            first_ms,
            last_ms,
            src_port,
            dst_port,
            _pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            _pad2,
        ) = struct.unpack("!4s4s4sHHIIIIHHBBBBHHBBH", chunk)
        records.append(
            {
                "type": "FLOW_TELEMETRY",
                "source": "NETFLOW_V5",
                "exporter": exporter,
                "src_ip": _ipv4(src),
                "dst_ip": _ipv4(dst),
                "next_hop": _ipv4(next_hop),
                "input_if": input_if,
                "output_if": output_if,
                "packets": packets,
                "bytes": octets,
                "first_ms": first_ms,
                "last_ms": last_ms,
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol)),
                "protocol_number": protocol,
                "tcp_flags": tcp_flags,
                "tos": tos,
                "src_as": src_as,
                "dst_as": dst_as,
                "src_mask": src_mask,
                "dst_mask": dst_mask,
                "sequence": sequence,
                "sys_uptime_ms": sys_uptime,
                "export_time": unix_secs,
                "export_nsec": unix_nsecs,
                "engine_type": engine_type,
                "engine_id": engine_id,
                "sampling": sampling,
            }
        )
        offset += 48
    return records


def _decode_unsigned(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=False)


def _decode_ipfix_value(field_id: int, raw: bytes) -> Any:
    if field_id in {8, 12} and len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if field_id in {27, 28} and len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    if field_id in {1, 2, 4, 5, 6, 7, 11, 152, 153}:
        return _decode_unsigned(raw)
    return raw.hex()


IPFIX_NAMES = {
    1: "bytes",
    2: "packets",
    4: "protocol_number",
    5: "ip_class_of_service",
    6: "tcp_flags",
    7: "src_port",
    8: "src_ip",
    11: "dst_port",
    12: "dst_ip",
    27: "src_ip",
    28: "dst_ip",
    152: "flow_start_ms",
    153: "flow_end_ms",
}


def _parse_ipfix_templates(
    body: bytes,
    exporter: str,
    domain: int,
    cache: IpfixTemplateCache,
) -> None:
    offset = 0
    while offset + 4 <= len(body):
        template_id, field_count = struct.unpack("!HH", body[offset : offset + 4])
        offset += 4
        fields: list[IpfixField] = []
        valid = True
        for _ in range(field_count):
            if offset + 4 > len(body):
                valid = False
                break
            raw_id, length = struct.unpack("!HH", body[offset : offset + 4])
            offset += 4
            enterprise = None
            field_id = raw_id & 0x7FFF
            if raw_id & 0x8000:
                if offset + 4 > len(body):
                    valid = False
                    break
                enterprise = struct.unpack("!I", body[offset : offset + 4])[0]
                offset += 4
            fields.append(IpfixField(field_id=field_id, length=length, enterprise=enterprise))
        if valid and template_id >= 256 and fields:
            cache.store(exporter, domain, template_id, fields)
        if not valid:
            break


def _parse_ipfix_data(
    body: bytes,
    exporter: str,
    domain: int,
    template_id: int,
    cache: IpfixTemplateCache,
) -> list[dict[str, Any]]:
    fields = cache.get(exporter, domain, template_id)
    if not fields or any(field.length == 65535 for field in fields):
        return []
    record_length = sum(field.length for field in fields)
    if record_length <= 0:
        return []
    records = []
    offset = 0
    while offset + record_length <= len(body) and len(records) < 1000:
        values: dict[str, Any] = {
            "type": "FLOW_TELEMETRY",
            "source": "IPFIX",
            "exporter": exporter,
            "observation_domain": domain,
            "template_id": template_id,
        }
        cursor = offset
        for field in fields:
            raw = body[cursor : cursor + field.length]
            cursor += field.length
            name = IPFIX_NAMES.get(field.field_id)
            if name and field.enterprise is None:
                values[name] = _decode_ipfix_value(field.field_id, raw)
        protocol = values.get("protocol_number")
        if protocol is not None:
            values["transport"] = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(protocol), str(protocol))
        records.append(values)
        offset += record_length
    return records


def decode_ipfix(data: bytes, exporter: str, cache: IpfixTemplateCache) -> list[dict[str, Any]]:
    if len(data) < 16:
        return []
    version, length, export_time, sequence, domain = struct.unpack("!HHIII", data[:16])
    if version != 10 or length > len(data) or length < 16:
        return []
    records: list[dict[str, Any]] = []
    offset = 16
    while offset + 4 <= length:
        set_id, set_length = struct.unpack("!HH", data[offset : offset + 4])
        if set_length < 4 or offset + set_length > length:
            break
        body = data[offset + 4 : offset + set_length]
        if set_id == 2:
            _parse_ipfix_templates(body, exporter, domain, cache)
        elif set_id >= 256:
            records.extend(_parse_ipfix_data(body, exporter, domain, set_id, cache))
        offset += set_length
    for record in records:
        record["export_time"] = export_time
        record["sequence"] = sequence
    return records


class _FlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[tuple[bytes, tuple[str, int]]]) -> None:
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            pass


class FlowTelemetryReceiverWorker(BaseWorker):
    """NetFlow v5 and IPFIX v10 UDP receiver for configured infrastructure exporters."""

    def __init__(self, bus: EventBus, session_provider, port: int | None = None) -> None:
        super().__init__("flow-telemetry-receiver", bus)
        self.session_provider = session_provider
        self.port = port if port is not None else int(os.environ.get("CAMPUS_OPS_FLOW_PORT", "2055"))
        self.cache = IpfixTemplateCache()

    async def run(self) -> None:
        queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=4000)
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _FlowProtocol(queue),
                local_addr=("0.0.0.0", self.port),
            )
        except OSError as exc:
            self.health.state = WorkerState.DEGRADED
            self.health.heartbeat(f"flow UDP/{self.port} unavailable: {exc}")
            while not self.stopping:
                await asyncio.sleep(5)
            return

        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                try:
                    data, addr = await asyncio.wait_for(queue.get(), timeout=2.0)
                except TimeoutError:
                    self.health.heartbeat(f"listening UDP/{self.port}")
                    continue
                if len(data) < 2:
                    continue
                version = int.from_bytes(data[:2], "big")
                records = (
                    decode_netflow_v5(data, addr[0])
                    if version == 5
                    else decode_ipfix(data, addr[0], self.cache)
                    if version == 10
                    else []
                )
                session_id = self.session_provider()
                for record in records:
                    await self.bus.publish(
                        Event(
                            source=self.name,
                            kind=EventKind.OBSERVATION,
                            session_id=session_id,
                            evidence_class=str(record.get("source") or "FLOW_TELEMETRY"),
                            payload=record,
                        )
                    )
                self.health.heartbeat(f"exporter={addr[0]} version={version} records={len(records)}")
        finally:
            transport.close()
