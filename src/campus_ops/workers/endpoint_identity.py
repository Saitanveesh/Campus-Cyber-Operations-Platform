from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from campus_ops.agent_plane import AgentRegistry
from campus_ops.event_bus import EventBus
from campus_ops.models import WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker


class EndpointIdentityWorker(BaseWorker):
    """Merges authenticated endpoint-agent identity into current live asset state."""

    def __init__(
        self,
        bus: EventBus,
        state: LiveState,
        agents: AgentRegistry,
        session_provider,
        interval: float = 3.0,
    ) -> None:
        super().__init__("endpoint-identity", bus)
        self.state = state
        self.agents = agents
        self.session_provider = session_provider
        self.interval = interval

    async def run(self) -> None:
        self.health.state = WorkerState.HEALTHY
        while not self.stopping:
            session_id = self.session_provider()
            agents = self.agents.list()
            online = 0
            if session_id:
                now = datetime.now(UTC).isoformat()
                for agent in agents:
                    if agent.get("status") == "ONLINE":
                        online += 1
                    telemetry = agent.get("telemetry") if isinstance(agent.get("telemetry"), dict) else {}
                    addresses = telemetry.get("network_addresses") if isinstance(telemetry, dict) else []
                    if not isinstance(addresses, list):
                        continue
                    for item in addresses:
                        if not isinstance(item, dict):
                            continue
                        address = str(item.get("address") or "").strip()
                        if not address:
                            continue
                        previous = self.state.get_asset(address)
                        self.state.upsert_asset(
                            address,
                            {
                                **previous,
                                "id": address,
                                "ip": address,
                                "hostname": telemetry.get("hostname") or agent.get("host") or agent.get("name"),
                                "role": previous.get("role", "LOCAL_SUBNET_ENDPOINT"),
                                "classification": previous.get("classification", "LOCAL_SUBNET_ENDPOINT"),
                                "local_device": True,
                                "first_seen": previous.get("first_seen", now),
                                "last_seen": agent.get("last_seen") or now,
                                "evidence": "AUTHENTICATED_ENDPOINT_AGENT",
                                "agent": {
                                    "endpoint_id": agent.get("endpoint_id"),
                                    "name": agent.get("name"),
                                    "platform": agent.get("platform"),
                                    "status": agent.get("status"),
                                    "version": agent.get("version"),
                                    "cpu_percent": telemetry.get("cpu_percent"),
                                    "memory_percent": telemetry.get("memory_percent"),
                                    "disk_percent": telemetry.get("disk_percent"),
                                    "users": telemetry.get("users", []),
                                    "connections": telemetry.get("connections", {}),
                                },
                                "identity": {
                                    **(previous.get("identity") or {}),
                                    "hostname": telemetry.get("hostname") or agent.get("host"),
                                    "os_guess": telemetry.get("system") or agent.get("platform"),
                                    "os_confidence": 100,
                                    "source": "AUTHENTICATED_ENDPOINT_AGENT",
                                },
                                "os_guess": telemetry.get("system") or agent.get("platform"),
                                "os_confidence": 100,
                            },
                        )
                self.state.update_metrics(
                    endpoint_agents_total=len(agents),
                    endpoint_agents_online=online,
                )
            self.health.heartbeat(f"agents={len(agents)} online={online}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
