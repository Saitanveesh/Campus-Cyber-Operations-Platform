from __future__ import annotations

import asyncio
import ipaddress
from collections import defaultdict
from typing import Any

from campus_ops.agent_plane import AgentRegistry
from campus_ops.event_bus import EventBus
from campus_ops.models import Event, EventKind, Severity, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker

ADMIN_PORTS = {22, 23, 445, 3389, 5985, 5986}


def _split_endpoint(value: object) -> tuple[str, int | None]:
    raw = str(value or "").strip()
    if not raw:
        return "", None
    if raw.startswith("[") and "]:" in raw:
        host, _, port_raw = raw[1:].partition("]:")
    else:
        host, sep, port_raw = raw.rpartition(":")
        if not sep:
            return raw, None
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = None
    return host, port


def _public_peer(value: object) -> bool:
    host, _ = _split_endpoint(value)
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def analyze_agent(agent: dict[str, Any]) -> dict[str, Any]:
    telemetry = agent.get("telemetry") if isinstance(agent.get("telemetry"), dict) else {}
    processes = [item for item in telemetry.get("processes", []) if isinstance(item, dict)]
    connections = [
        item for item in telemetry.get("connection_sample", []) if isinstance(item, dict)
    ]
    services = [item for item in telemetry.get("services", []) if isinstance(item, dict)]
    users = [str(item) for item in telemetry.get("users", []) if item]

    process_by_pid: dict[int, dict[str, Any]] = {}
    for process in processes:
        try:
            pid = int(process.get("pid"))
        except (TypeError, ValueError):
            continue
        process_by_pid[pid] = process

    peers_by_pid: dict[int, set[str]] = defaultdict(set)
    public_by_pid: dict[int, set[str]] = defaultdict(set)
    listeners_by_pid: dict[int, set[int]] = defaultdict(set)
    remote_admin_by_pid: dict[int, set[str]] = defaultdict(set)
    remote_rows: list[dict[str, Any]] = []
    listener_rows: list[dict[str, Any]] = []

    for connection in connections:
        try:
            pid = int(connection.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        process = process_by_pid.get(pid, {})
        remote = str(connection.get("remote") or "")
        local = str(connection.get("local") or "")
        status = str(connection.get("status") or "")
        remote_host, remote_port = _split_endpoint(remote)
        _, local_port = _split_endpoint(local)

        if remote_host:
            peers_by_pid[pid].add(remote_host)
            if _public_peer(remote):
                public_by_pid[pid].add(remote_host)
            if remote_port in ADMIN_PORTS:
                remote_admin_by_pid[pid].add(remote_host)
            remote_rows.append(
                {
                    "pid": pid or None,
                    "process": process.get("name") or "",
                    "user": process.get("user") or "",
                    "local": local,
                    "remote": remote,
                    "remote_ip": remote_host,
                    "remote_port": remote_port,
                    "status": status,
                    "transport": connection.get("type") or "",
                }
            )

        if status.upper() == "LISTEN" and local_port is not None:
            listeners_by_pid[pid].add(local_port)
            listener_rows.append(
                {
                    "pid": pid or None,
                    "process": process.get("name") or "",
                    "user": process.get("user") or "",
                    "local": local,
                    "port": local_port,
                    "transport": connection.get("type") or "",
                    "administrative_port": local_port in ADMIN_PORTS,
                }
            )

    process_rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for pid, process in process_by_pid.items():
        peers = peers_by_pid.get(pid, set())
        public_peers = public_by_pid.get(pid, set())
        admin_peers = remote_admin_by_pid.get(pid, set())
        listeners = listeners_by_pid.get(pid, set())
        row = {
            "pid": pid,
            "name": process.get("name") or "",
            "user": process.get("user") or "",
            "cpu_percent": process.get("cpu_percent") or 0,
            "memory_percent": process.get("memory_percent") or 0,
            "peer_count": len(peers),
            "public_peer_count": len(public_peers),
            "admin_peer_count": len(admin_peers),
            "listening_ports": sorted(listeners),
        }
        process_rows.append(row)

        if len(admin_peers) >= 5:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "PROCESS_ADMIN_FANOUT",
                    "pid": pid,
                    "process": row["name"],
                    "detail": f"Process contacted {len(admin_peers)} peers on administrative ports",
                    "peer_count": len(admin_peers),
                }
            )
        elif len(public_peers) >= 20:
            findings.append(
                {
                    "severity": "LOW",
                    "type": "PROCESS_PUBLIC_FANOUT",
                    "pid": pid,
                    "process": row["name"],
                    "detail": f"Process currently references {len(public_peers)} public peers",
                    "peer_count": len(public_peers),
                }
            )

        exposed = sorted(port for port in listeners if port in ADMIN_PORTS)
        if exposed:
            findings.append(
                {
                    "severity": "LOW",
                    "type": "ADMIN_LISTENER",
                    "pid": pid,
                    "process": row["name"],
                    "detail": "Administrative service listener observed",
                    "ports": exposed,
                }
            )

    process_rows.sort(
        key=lambda item: (
            int(item["admin_peer_count"]),
            int(item["public_peer_count"]),
            float(item["memory_percent"] or 0),
        ),
        reverse=True,
    )
    remote_rows.sort(key=lambda item: (item["process"], item["remote"]))
    listener_rows.sort(key=lambda item: (not item["administrative_port"], item["port"]))

    running_services = [
        item
        for item in services
        if str(item.get("status") or "").lower() in {"running", "started"}
    ]

    return {
        "endpoint_id": agent.get("endpoint_id"),
        "name": agent.get("name"),
        "host": agent.get("host"),
        "platform": agent.get("platform"),
        "status": agent.get("status"),
        "last_seen": agent.get("last_seen"),
        "isolation_state": telemetry.get("isolation_state") or "UNKNOWN",
        "users": users,
        "process_count": len(processes),
        "service_count": len(services),
        "running_service_count": len(running_services),
        "connection_count": len(connections),
        "remote_connection_count": len(remote_rows),
        "listener_count": len(listener_rows),
        "processes": process_rows[:200],
        "connections": remote_rows[:300],
        "listeners": listener_rows[:200],
        "services": running_services[:300],
        "findings": findings[:100],
    }


class EndpointDeepMonitorWorker(BaseWorker):
    """Correlate authenticated endpoint telemetry into process/network exposure context."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        agents: AgentRegistry,
        session_provider,
        interval: float = 3.0,
    ) -> None:
        super().__init__("endpoint-deep-monitor", bus)
        self.state = state
        self.agents = agents
        self.session_provider = session_provider
        self.interval = max(1.0, interval)
        self._last_medium: set[tuple[str, str, int]] = set()

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            agents = self.agents.list()
            reports = {
                str(agent.get("endpoint_id")): analyze_agent(agent)
                for agent in agents
                if agent.get("endpoint_id")
            }
            if session_id:
                self.state.update_metrics(
                    endpoint_deep={
                        "managed_count": len(reports),
                        "online_count": sum(
                            1
                            for report in reports.values()
                            if str(report.get("status") or "").upper() == "ONLINE"
                        ),
                        "finding_count": sum(
                            len(report.get("findings", [])) for report in reports.values()
                        ),
                        "endpoints": reports,
                    }
                )

                current_medium: set[tuple[str, str, int]] = set()
                for endpoint_id, report in reports.items():
                    for finding in report.get("findings", []):
                        if str(finding.get("severity") or "").upper() != "MEDIUM":
                            continue
                        try:
                            pid = int(finding.get("pid") or 0)
                        except (TypeError, ValueError):
                            pid = 0
                        key = (endpoint_id, str(finding.get("type") or ""), pid)
                        current_medium.add(key)
                        if key in self._last_medium:
                            continue
                        await self.bus.publish(
                            Event(
                                source=self.name,
                                kind=EventKind.ALERT,
                                session_id=session_id,
                                severity=Severity.MEDIUM,
                                evidence_class="AUTHENTICATED_ENDPOINT_TELEMETRY",
                                payload={
                                    "type": "ENDPOINT_BEHAVIOUR_INDICATOR",
                                    "title": "Managed endpoint process fan-out observed",
                                    "confidence": 70,
                                    "evidence": {
                                        "endpoint_id": endpoint_id,
                                        "host": report.get("host"),
                                        **finding,
                                    },
                                },
                            )
                        )
                self._last_medium = current_medium
            else:
                self._last_medium.clear()

            self.health.heartbeat(
                f"managed={len(reports)} findings={sum(len(r.get('findings', [])) for r in reports.values())}"
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
