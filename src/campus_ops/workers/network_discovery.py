from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import subprocess
from dataclasses import asdict

import psutil

from campus_ops.linux_host import default_routes as linux_routes
from campus_ops.models import Event, EventKind, NetworkCandidate, SelectedNetwork, WorkerState
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
    "docker",
    "wsl",
    "veth",
    "cilium",
    "flannel",
)


def classify_interface(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith(("lo", "loopback")):
        return "loopback"
    if lowered.startswith(("tun", "tap", "wg", "ppp", "tailscale", "zt")):
        return "tunnel"
    if any(token in lowered for token in VIRTUAL_HINTS):
        return "virtual"
    if lowered.startswith(("wlp", "wlx")) or "wi-fi" in lowered or "wifi" in lowered or "wireless" in lowered or "wlan" in lowered:
        return "wireless"
    if "ethernet" in lowered or lowered.startswith(("eth", "enp", "ens", "eno", "enx", "usb")):
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
        score += 60
        reasons.append("default-route")
    else:
        score -= 20
        reasons.append("no-default-route")
    if candidate.gateway:
        score += 8
        reasons.append("gateway")
    if candidate.prefixes:
        score += 3
        reasons.append("prefix-known")
    if candidate.route_metric is not None:
        score += max(0, 25 - min(candidate.route_metric, 25))
        reasons.append(f"metric:{candidate.route_metric}")
    if candidate.category == "ethernet":
        score += 12
        reasons.append("ethernet")
    elif candidate.category == "wireless":
        score += 8
        reasons.append("wireless")
    elif candidate.category == "virtual":
        score -= 55
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


def _prefix(address: str, netmask: str | None) -> str | None:
    if not netmask:
        return None
    try:
        return ipaddress.ip_network(f"{address}/{netmask}", strict=False).with_prefixlen
    except ValueError:
        return None


def _windows_routes() -> dict[str, tuple[bool, int | None, str | None]]:
    if os.name != "nt":
        return {}
    script = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,RouteMetric,NextHop | ConvertTo-Json -Compress"
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
        result: dict[str, tuple[bool, int | None, str | None]] = {}
        for row in rows:
            name = str(row.get("InterfaceAlias", ""))
            metric_raw = row.get("RouteMetric")
            metric = int(metric_raw) if metric_raw is not None else None
            gateway = str(row.get("NextHop") or "") or None
            previous = result.get(name)
            if previous is None or (metric is not None and (previous[1] is None or metric < previous[1])):
                result[name] = (True, metric, gateway)
        return result
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
        return {}


def discover_candidates() -> list[NetworkCandidate]:
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    routes = _windows_routes() if os.name == "nt" else linux_routes()
    candidates: list[NetworkCandidate] = []
    for name, addr_list in addresses.items():
        ipv4: list[str] = []
        ipv6: list[str] = []
        prefixes: list[str] = []
        is_loopback = name == "lo"
        for addr in addr_list:
            value = addr.address
            if addr.family.name == "AF_INET":
                if value.startswith("127."):
                    is_loopback = True
                if _is_usable_ip(value):
                    ipv4.append(value)
                    prefix = _prefix(value, addr.netmask)
                    if prefix:
                        prefixes.append(prefix)
            elif addr.family.name == "AF_INET6" and value.split("%", 1)[0] == "::1":
                is_loopback = True
            elif addr.family.name == "AF_INET6" and _is_usable_ip(value):
                clean = value.split("%", 1)[0]
                ipv6.append(clean)
                prefix = _prefix(clean, addr.netmask)
                if prefix:
                    prefixes.append(prefix)
        stat = stats.get(name)
        io = counters.get(name)
        default_route, metric, gateway = routes.get(name, (False, None, None))
        candidates.append(
            NetworkCandidate(
                name=name,
                is_up=bool(stat and stat.isup),
                is_loopback=is_loopback,
                ipv4=tuple(sorted(set(ipv4))),
                ipv6=tuple(sorted(set(ipv6))),
                prefixes=tuple(sorted(set(prefixes))),
                default_route=default_route,
                route_metric=metric,
                gateway=gateway,
                bytes_recv=io.bytes_recv if io else 0,
                bytes_sent=io.bytes_sent if io else 0,
                category=classify_interface(name),
            )
        )
    return candidates


def elect_network(candidates: list[NetworkCandidate], requested: str | None = None) -> SelectedNetwork | None:
    requested = requested if requested is not None else os.environ.get("CAMPUS_OPS_INTERFACE", "auto")
    if requested and requested != "auto":
        if requested == "any" and os.name != "nt":
            live = [c for c in candidates if c.is_up and not c.is_loopback]
            if not live:
                return None
            return SelectedNetwork(
                "any", 100, ("all-linux-interfaces",),
                tuple(sorted({ip for c in live for ip in c.ipv4})),
                tuple(sorted({ip for c in live for ip in c.ipv6})),
                tuple(sorted({prefix for c in live for prefix in c.prefixes})),
                any(c.default_route for c in live), None, None,
            )
        forced = next((c for c in candidates if c.name == requested and c.is_up), None)
        if forced is None:
            return None
        return SelectedNetwork(forced.name, 100, ("explicit-interface",), forced.ipv4,
                               forced.ipv6, forced.prefixes, forced.default_route,
                               forced.route_metric, forced.gateway)
    scored = [(score_candidate(candidate), candidate) for candidate in candidates]
    viable = [(result, candidate) for result, candidate in scored if result[0] >= 40]
    if not viable:
        return None

    routed = [(result, candidate) for result, candidate in viable if candidate.default_route]
    pool = routed or viable
    physical = [(result, candidate) for result, candidate in pool if candidate.category != "virtual"]
    if physical:
        pool = physical

    (score, reasons), selected = max(
        pool,
        key=lambda item: (
            item[0][0],
            -(item[1].route_metric if item[1].route_metric is not None else 9999),
            item[1].name,
        ),
    )
    return SelectedNetwork(
        interface=selected.name,
        score=score,
        reasons=reasons,
        ipv4=selected.ipv4,
        ipv6=selected.ipv6,
        prefixes=selected.prefixes,
        default_route=selected.default_route,
        route_metric=selected.route_metric,
        gateway=selected.gateway,
    )


class NetworkDiscoveryWorker(BaseWorker):
    def __init__(
        self,
        bus,
        interval: float = 3.0,
        switch_margin: int = 15,
        confirmations: int = 2,
        unavailable_confirmations: int = 3,
    ) -> None:
        super().__init__("network-discovery", bus)
        self.interval = interval
        self.switch_margin = switch_margin
        self.confirmations = max(1, confirmations)
        self.unavailable_confirmations = max(1, unavailable_confirmations)
        self.selected: SelectedNetwork | None = None
        self.candidates: list[NetworkCandidate] = []
        self._pending_name: str | None = None
        self._pending_count = 0
        self._loss_count = 0

    async def run(self) -> None:
        while not self.stopping:
            self.candidates = await asyncio.to_thread(discover_candidates)
            proposed = elect_network(self.candidates)
            await self._consider(proposed)
            if self.selected:
                self.health.state = WorkerState.HEALTHY
                if self._loss_count:
                    self.health.heartbeat(
                        f"holding {self.selected.interface} through transient link observation "
                        f"{self._loss_count}/{self.unavailable_confirmations}"
                    )
                else:
                    self.health.heartbeat(f"selected {self.selected.interface}")
            else:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat("no viable monitoring interface")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass

    async def _declare_unavailable(self) -> None:
        if self.selected is None:
            return
        old = self.selected
        self.selected = None
        self._pending_name = None
        self._pending_count = 0
        self._loss_count = 0
        await self.bus.publish(
            Event(
                source=self.name,
                kind=EventKind.NETWORK,
                payload={"change": "NETWORK_UNAVAILABLE", "previous": asdict(old)},
            )
        )

    async def _consider(self, proposed: SelectedNetwork | None) -> None:
        if proposed is None:
            self._pending_name = None
            self._pending_count = 0
            if self.selected is None:
                self._loss_count = 0
                return
            self._loss_count += 1
            if self._loss_count < self.unavailable_confirmations:
                return
            await self._declare_unavailable()
            return

        if self.selected is not None and self.candidates:
            current = next((c for c in self.candidates if c.name == self.selected.interface), None)
            if self.selected.interface != "any" and (current is None or not current.is_up):
                self._loss_count += 1
                if self._loss_count < self.unavailable_confirmations:
                    return
                await self._declare_unavailable()
            elif current is not None:
                self._loss_count = 0
                # Compare against current link/route state, never yesterday's high score.
                current_score, current_reasons = score_candidate(current)
                self.selected = SelectedNetwork(current.name, current_score, current_reasons,
                    self.selected.ipv4, self.selected.ipv6, self.selected.prefixes,
                    self.selected.default_route, self.selected.route_metric, self.selected.gateway)

        if self.selected is None:
            await self._confirm_and_switch(proposed)
            return

        if proposed.interface == self.selected.interface:
            self._loss_count = 0
            changed_identity = (
                proposed.ipv4 != self.selected.ipv4
                or proposed.ipv6 != self.selected.ipv6
                or proposed.prefixes != self.selected.prefixes
                or proposed.gateway != self.selected.gateway
            )
            previous = self.selected
            self.selected = proposed
            self._pending_name = None
            self._pending_count = 0
            if changed_identity:
                await self.bus.publish(
                    Event(
                        source=self.name,
                        kind=EventKind.NETWORK,
                        payload={
                            "change": "NETWORK_IDENTITY_CHANGED",
                            "previous": asdict(previous),
                            "current": asdict(proposed),
                        },
                    )
                )
            return

        forced = "explicit-interface" in proposed.reasons or proposed.interface == "any"
        if not forced and proposed.score < self.selected.score + self.switch_margin:
            self._pending_name = None
            self._pending_count = 0
            return
        await self._confirm_and_switch(proposed)

    async def _confirm_and_switch(self, proposed: SelectedNetwork) -> None:
        self._loss_count = 0
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
