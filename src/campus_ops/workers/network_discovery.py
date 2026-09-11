from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import subprocess
from dataclasses import asdict

import psutil

from campus_ops.models import (
    Event,
    EventKind,
    NetworkCandidate,
    SelectedNetwork,
    WorkerState,
)
from campus_ops.workers.base import BaseWorker

VIRTUAL_HINTS = (
    "loopback",
    "virtual",
    "vmware",
    "hyper-v",
    "vbox",
    "bluetooth",
    "tunnel",
    "tap",
    "vpn",
)


def classify_interface(name: str) -> str:
    lowered = name.lower()
    if any(token in lowered for token in VIRTUAL_HINTS):
        return "virtual"
    if "wi-fi" in lowered or "wifi" in lowered or "wireless" in lowered or "wlan" in lowered:
        return "wireless"
    if "ethernet" in lowered or lowered.startswith("eth"):
        return "ethernet"
    return "other"


def score_candidate(candidate: NetworkCandidate) -> tuple[int, tuple[str, ...]]:
    score = 0
    reasons: list[str] = []
    if not candidate.is_up:
        return -1000, ("interface-down",)
    score += 40
    reasons.append("up")
    if candidate.is_loopback:
        return -900, tuple(reasons + ["loopback"])
    if candidate.ipv4:
        score += 30
        reasons.append("usable-ipv4")
    elif candidate.ipv6:
        score += 15
        reasons.append("ipv6-only")
    else:
        score -= 35
        reasons.append("no-unicast-address")
    if candidate.default_route:
        score += 45
        reasons.append("default-route")
    if candidate.route_metric is not None:
        score += max(0, 20 - min(candidate.route_metric, 20))
        reasons.append(f"metric:{candidate.route_metric}")
    if candidate.category == "ethernet":
        score += 12
        reasons.append("ethernet")
    elif candidate.category == "wireless":
        score += 8
        reasons.append("wireless")
    elif candidate.category == "virtual":
        score -= 30
        reasons.append("virtual-penalty")
    if candidate.bytes_recv > 0 or candidate.bytes_sent > 0:
        score += 5
        reasons.append("traffic-seen")
    return score, tuple(reasons)


def _is_usable_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def _windows_routes() -> dict[str, tuple[bool, int | None]]:
    if os.name != "nt":
        return {}
    script = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,RouteMetric | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        raw = json.loads(proc.stdout)
        rows = raw if isinstance(raw, list) else [raw]
        result: dict[str, tuple[bool, int | None]] = {}
        for row in rows:
            name = str(row.get("InterfaceAlias", ""))
            metric_raw = row.get("RouteMetric")
            metric = int(metric_raw) if metric_raw is not None else None
            previous = result.get(name)
            if previous is None or (
                metric is not None and (previous[1] is None or metric < previous[1])
            ):
                result[name] = (True, metric)
        return result
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
        return {}


def discover_candidates() -> list[NetworkCandidate]:
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    routes = _windows_routes()
    candidates: list[NetworkCandidate] = []
    for name, addr_list in addresses.items():
        ipv4: list[str] = []
        ipv6: list[str] = []
        is_loopback = False
        for addr in addr_list:
            value = addr.address
            if addr.family.name == "AF_INET":
                if value.startswith("127."):
                    is_loopback = True
                if _is_usable_ip(value):
                    ipv4.append(value)
            elif addr.family.name == "AF_INET6" and _is_usable_ip(value):
                ipv6.append(value.split("%", 1)[0])
        stat = stats.get(name)
        io = counters.get(name)
        default_route, metric = routes.get(name, (False, None))
        candidates.append(
            NetworkCandidate(
                name=name,
                is_up=bool(stat and stat.isup),
                is_loopback=is_loopback,
                ipv4=tuple(sorted(set(ipv4))),
                ipv6=tuple(sorted(set(ipv6))),
                default_route=default_route,
                route_metric=metric,
                bytes_recv=io.bytes_recv if io else 0,
                bytes_sent=io.bytes_sent if io else 0,
                category=classify_interface(name),
            )
        )
    return candidates


def elect_network(candidates: list[NetworkCandidate]) -> SelectedNetwork | None:
    scored = [(score_candidate(candidate), candidate) for candidate in candidates]
    viable = [(result, candidate) for result, candidate in scored if result[0] >= 40]
    if not viable:
        return None
    (score, reasons), selected = max(viable, key=lambda item: (item[0][0], item[1].name))
    return SelectedNetwork(
        interface=selected.name,
        score=score,
        reasons=reasons,
        ipv4=selected.ipv4,
        ipv6=selected.ipv6,
        default_route=selected.default_route,
        route_metric=selected.route_metric,
    )


class NetworkDiscoveryWorker(BaseWorker):
    def __init__(
        self,
        bus,
        interval: float = 3.0,
        switch_margin: int = 15,
        confirmations: int = 2,
    ) -> None:
        super().__init__("network-discovery", bus)
        self.interval = interval
        self.switch_margin = switch_margin
        self.confirmations = max(1, confirmations)
        self.selected: SelectedNetwork | None = None
        self.candidates: list[NetworkCandidate] = []
        self._pending_name: str | None = None
        self._pending_count = 0

    async def run(self) -> None:
        while not self.stopping:
            self.candidates = discover_candidates()
            proposed = elect_network(self.candidates)
            await self._consider(proposed)
            if self.selected:
                self.health.state = WorkerState.HEALTHY
                self.health.heartbeat(f"selected {self.selected.interface}")
            else:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("no viable monitoring interface")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass

    async def _consider(self, proposed: SelectedNetwork | None) -> None:
        if proposed is None:
            if self.selected is not None:
                old = self.selected
                self.selected = None
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.NETWORK,
                        payload={"change": "NETWORK_UNAVAILABLE", "previous": asdict(old)},
                    )
                )
            return
        if self.selected is None:
            await self._confirm_and_switch(proposed)
            return
        if proposed.interface == self.selected.interface:
            self.selected = proposed
            self._pending_name = None
            self._pending_count = 0
            return
        if proposed.score < self.selected.score + self.switch_margin:
            return
        await self._confirm_and_switch(proposed)

    async def _confirm_and_switch(self, proposed: SelectedNetwork) -> None:
        if self._pending_name == proposed.interface:
            self._pending_count += 1
        else:
            self._pending_name = proposed.interface
            self._pending_count = 1
        if self._pending_count < self.confirmations:
            return
        previous = self.selected
        self.selected = proposed
        self._pending_name = None
        self._pending_count = 0
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.NETWORK,
                payload={
                    "change": "INTERFACE_SELECTED" if previous is None else "INTERFACE_CHANGED",
                    "previous": asdict(previous) if previous else None,
                    "current": asdict(proposed),
                },
            )
        )
