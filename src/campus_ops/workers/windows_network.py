from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import subprocess
from dataclasses import asdict

import psutil

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
)


def classify_interface(name: str) -> str:
    lowered = name.casefold()
    if "loopback" in lowered:
        return "loopback"
    if any(token in lowered for token in VIRTUAL_HINTS):
        return "virtual"
    if "wi-fi" in lowered or "wifi" in lowered or "wireless" in lowered or "wlan" in lowered:
        return "wireless"
    if "ethernet" in lowered:
        return "ethernet"
    return "other"


def _powershell_json(script: str, timeout: float = 6.0) -> object:
    if os.name != "nt":
        raise RuntimeError("MON Windows requires native Windows")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "PowerShell network discovery failed")
    text = proc.stdout.strip()
    if not text:
        return []
    return json.loads(text)


def _route_table() -> dict[str, tuple[bool, int | None, str | None]]:
    raw = _powershell_json(
        "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | Select-Object InterfaceAlias,RouteMetric,NextHop | "
        "ConvertTo-Json -Compress"
    )
    rows = raw if isinstance(raw, list) else [raw]
    routes: dict[str, tuple[bool, int | None, str | None]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("InterfaceAlias") or "").strip()
        if not name:
            continue
        metric_raw = row.get("RouteMetric")
        try:
            metric = int(metric_raw) if metric_raw is not None else None
        except (TypeError, ValueError):
            metric = None
        gateway = str(row.get("NextHop") or "").strip() or None
        previous = routes.get(name)
        if previous is None or (
            metric is not None and (previous[1] is None or metric < previous[1])
        ):
            routes[name] = (True, metric, gateway)
    return routes


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


def discover_candidates() -> list[NetworkCandidate]:
    if os.name != "nt":
        raise RuntimeError("MON Windows network discovery can run only on native Windows")
    routes = _route_table()
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    candidates: list[NetworkCandidate] = []
    for name, addr_list in addresses.items():
        ipv4: list[str] = []
        ipv6: list[str] = []
        prefixes: list[str] = []
        is_loopback = "loopback" in name.casefold()
        for addr in addr_list:
            family_name = getattr(addr.family, "name", "")
            value = str(addr.address or "")
            if family_name == "AF_INET":
                if value.startswith("127."):
                    is_loopback = True
                if _is_usable_ip(value):
                    ipv4.append(value)
                    prefix = _prefix(value, addr.netmask)
                    if prefix:
                        prefixes.append(prefix)
            elif family_name == "AF_INET6":
                clean = value.split("%", 1)[0]
                if clean == "::1":
                    is_loopback = True
                elif _is_usable_ip(clean):
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


def score_candidate(candidate: NetworkCandidate) -> tuple[int, tuple[str, ...]]:
    if not candidate.is_up:
        return -1000, ("interface-down",)
    if candidate.is_loopback:
        return -900, ("loopback",)
    score = 40
    reasons = ["up"]
    if candidate.ipv4:
        score += 35
        reasons.append("usable-ipv4")
    elif candidate.ipv6:
        score += 15
        reasons.append("ipv6-only")
    else:
        score -= 40
        reasons.append("no-unicast-address")
    if candidate.default_route:
        score += 70
        reasons.append("default-route")
    else:
        score -= 20
    if candidate.gateway:
        score += 8
        reasons.append("gateway")
    if candidate.category == "ethernet":
        score += 14
        reasons.append("physical-ethernet")
    elif candidate.category == "wireless":
        score += 12
        reasons.append("physical-wireless")
    elif candidate.category == "virtual":
        score -= 80
        reasons.append("virtual-penalty")
    if candidate.route_metric is not None:
        score += max(0, 30 - min(candidate.route_metric, 30))
        reasons.append(f"metric:{candidate.route_metric}")
    if candidate.bytes_recv or candidate.bytes_sent:
        score += 5
        reasons.append("traffic-seen")
    return score, tuple(reasons)


def elect_network(candidates: list[NetworkCandidate], requested: str | None = None) -> SelectedNetwork | None:
    requested = requested if requested is not None else os.environ.get("CAMPUS_OPS_INTERFACE", "auto")
    if requested and requested.casefold() != "auto":
        forced = next((item for item in candidates if item.name.casefold() == requested.casefold() and item.is_up), None)
        if forced is None:
            return None
        return SelectedNetwork(
            interface=forced.name,
            score=100,
            reasons=("explicit-interface",),
            ipv4=forced.ipv4,
            ipv6=forced.ipv6,
            prefixes=forced.prefixes,
            default_route=forced.default_route,
            route_metric=forced.route_metric,
            gateway=forced.gateway,
        )
    scored = [(score_candidate(item), item) for item in candidates]
    viable = [(result, item) for result, item in scored if result[0] >= 40]
    if not viable:
        return None
    routed = [(result, item) for result, item in viable if item.default_route]
    pool = routed or viable
    physical = [(result, item) for result, item in pool if item.category in {"ethernet", "wireless", "other"}]
    if physical:
        pool = physical
    (score, reasons), selected = max(
        pool,
        key=lambda row: (
            row[0][0],
            -(row[1].route_metric if row[1].route_metric is not None else 9999),
            row[1].name.casefold(),
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


def _material_identity(network: SelectedNetwork) -> tuple[object, ...]:
    return (
        network.interface.casefold(),
        tuple(sorted(network.ipv4)),
        tuple(sorted(network.prefixes)),
        network.default_route,
        network.gateway,
    )


class WindowsNetworkDiscoveryWorker(BaseWorker):
    def __init__(
        self,
        bus,
        interval: float = 3.0,
        switch_margin: int = 15,
        confirmations: int = 2,
        unavailable_confirmations: int = 5,
        identity_confirmations: int = 3,
    ) -> None:
        super().__init__("network-discovery", bus)
        self.interval = interval
        self.switch_margin = switch_margin
        self.confirmations = max(1, confirmations)
        self.unavailable_confirmations = max(1, unavailable_confirmations)
        self.identity_confirmations = max(1, identity_confirmations)
        self.selected: SelectedNetwork | None = None
        self.candidates: list[NetworkCandidate] = []
        self._pending_name: str | None = None
        self._pending_count = 0
        self._loss_count = 0
        self._pending_identity: tuple[object, ...] | None = None
        self._pending_identity_network: SelectedNetwork | None = None
        self._pending_identity_count = 0

    async def _sleep(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
        except TimeoutError:
            pass

    async def run(self) -> None:
        while not self.stopping:
            try:
                self.candidates = await asyncio.to_thread(discover_candidates)
                proposed = elect_network(self.candidates)
                await self._consider(proposed)
                if self.selected:
                    self.health.state = WorkerState.HEALTHY
                    self.health.heartbeat(f"selected {self.selected.interface}")
                else:
                    self.health.state = WorkerState.DEGRADED
                    self.health.heartbeat("no eligible native Windows network adapter")
            except (OSError, ValueError, RuntimeError, psutil.Error, subprocess.SubprocessError) as exc:
                self.health.state = WorkerState.DEGRADED
                self.health.heartbeat(f"Windows network discovery retry: {exc}")
            await self._sleep()

    async def _publish(self, change: str, previous: SelectedNetwork | None, current: SelectedNetwork | None) -> None:
        payload: dict[str, object] = {"change": change}
        if previous is not None:
            payload["previous"] = asdict(previous)
        if current is not None:
            payload["current"] = asdict(current)
        await self.bus.publish(Event(source=self.name, kind=EventKind.NETWORK, payload=payload))

    async def _consider(self, proposed: SelectedNetwork | None) -> None:
        if proposed is None:
            self._pending_name = None
            self._pending_count = 0
            self._pending_identity = None
            self._pending_identity_network = None
            self._pending_identity_count = 0
            if self.selected is None:
                self._loss_count = 0
                return
            self._loss_count += 1
            if self._loss_count >= self.unavailable_confirmations:
                previous = self.selected
                self.selected = None
                self._loss_count = 0
                await self._publish("NETWORK_UNAVAILABLE", previous, None)
            return

        self._loss_count = 0
        if self.selected is None:
            if self._pending_name == proposed.interface:
                self._pending_count += 1
            else:
                self._pending_name = proposed.interface
                self._pending_count = 1
            if self._pending_count >= self.confirmations:
                self.selected = proposed
                self._pending_name = None
                self._pending_count = 0
                await self._publish("INTERFACE_SELECTED", None, proposed)
            return

        if proposed.interface.casefold() != self.selected.interface.casefold():
            current_score = self.selected.score
            if proposed.score < current_score + self.switch_margin:
                self._pending_name = None
                self._pending_count = 0
                return
            if self._pending_name == proposed.interface:
                self._pending_count += 1
            else:
                self._pending_name = proposed.interface
                self._pending_count = 1
            if self._pending_count >= self.confirmations:
                previous = self.selected
                self.selected = proposed
                self._pending_name = None
                self._pending_count = 0
                await self._publish("INTERFACE_CHANGED", previous, proposed)
            return

        self._pending_name = None
        self._pending_count = 0
        if _material_identity(proposed) == _material_identity(self.selected):
            self.selected = proposed
            self._pending_identity = None
            self._pending_identity_network = None
            self._pending_identity_count = 0
            return

        identity = _material_identity(proposed)
        if identity == self._pending_identity:
            self._pending_identity_count += 1
            self._pending_identity_network = proposed
        else:
            self._pending_identity = identity
            self._pending_identity_network = proposed
            self._pending_identity_count = 1
        if self._pending_identity_count >= self.identity_confirmations:
            previous = self.selected
            current = self._pending_identity_network or proposed
            self.selected = current
            self._pending_identity = None
            self._pending_identity_network = None
            self._pending_identity_count = 0
            await self._publish("NETWORK_IDENTITY_CHANGED", previous, current)
