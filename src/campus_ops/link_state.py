from __future__ import annotations

import asyncio
import re
import subprocess
from typing import Any

import psutil
from fastapi import FastAPI


def _run(command: list[str], timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout or ""


def _parse_netsh_wlan() -> list[dict[str, Any]]:
    text = _run(["netsh", "wlan", "show", "interfaces"])
    if not text:
        return []
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        k = key.lower()
        if k == "name" and current:
            rows.append(current)
            current = {}
        mapping = {
            "name": "name",
            "description": "description",
            "state": "state",
            "ssid": "ssid",
            "bssid": "bssid",
            "radio type": "radio_type",
            "authentication": "authentication",
            "cipher": "cipher",
            "channel": "channel",
            "receive rate (mbps)": "rx_rate_mbps",
            "transmit rate (mbps)": "tx_rate_mbps",
            "signal": "signal_percent",
            "profile": "profile",
        }
        if k in mapping:
            field = mapping[k]
            if field in {"channel", "rx_rate_mbps", "tx_rate_mbps"}:
                try:
                    current[field] = float(value) if "." in value else int(value)
                except ValueError:
                    current[field] = value
            elif field == "signal_percent":
                m = re.search(r"(\d+)", value)
                current[field] = int(m.group(1)) if m else None
            else:
                current[field] = value
    if current:
        rows.append(current)
    return rows


def _interface_addresses(name: str) -> list[str]:
    out: list[str] = []
    for address in psutil.net_if_addrs().get(name, []):
        value = str(address.address or "").split("%", 1)[0]
        if value and value not in out:
            out.append(value)
    return out


def _duplex_name(value: int) -> str:
    names = {
        int(getattr(psutil, "NIC_DUPLEX_FULL", 2)): "FULL",
        int(getattr(psutil, "NIC_DUPLEX_HALF", 1)): "HALF",
        int(getattr(psutil, "NIC_DUPLEX_UNKNOWN", 0)): "UNKNOWN",
    }
    return names.get(int(value), "UNKNOWN")


def collect_link_state(app: FastAPI) -> dict[str, Any]:
    snapshot = app.state.orchestrator.snapshot()
    network = snapshot.get("network") if isinstance(snapshot, dict) else {}
    network = network if isinstance(network, dict) else {}
    selected = str(network.get("interface") or "")
    stats = psutil.net_if_stats()
    wlan_rows = _parse_netsh_wlan()
    wlan_by_name = {str(row.get("name") or "").lower(): row for row in wlan_rows}

    interfaces: list[dict[str, Any]] = []
    for name, stat in stats.items():
        wlan = wlan_by_name.get(name.lower())
        lname = name.lower()
        medium = "WIFI" if wlan or any(token in lname for token in ("wi-fi", "wifi", "wireless", "wlan")) else "ETHERNET"
        interfaces.append(
            {
                "name": name,
                "selected": name == selected,
                "medium": medium,
                "state": "UP" if stat.isup else "DOWN",
                "speed_mbps": int(stat.speed or 0),
                "duplex": _duplex_name(stat.duplex),
                "mtu": int(stat.mtu or 0),
                "addresses": _interface_addresses(name),
                "channel": wlan.get("channel") if wlan else None,
                "ssid": wlan.get("ssid") if wlan else None,
                "bssid": wlan.get("bssid") if wlan else None,
                "signal_percent": wlan.get("signal_percent") if wlan else None,
                "radio_type": wlan.get("radio_type") if wlan else None,
                "authentication": wlan.get("authentication") if wlan else None,
                "rx_rate_mbps": wlan.get("rx_rate_mbps") if wlan else None,
                "tx_rate_mbps": wlan.get("tx_rate_mbps") if wlan else None,
            }
        )

    active = next((row for row in interfaces if row["selected"]), None)
    if active is None and interfaces:
        active = next((row for row in interfaces if row["state"] == "UP"), interfaces[0])

    return {
        "selected_interface": selected or (active or {}).get("name"),
        "active": active,
        "interfaces": interfaces,
        "supports_wifi_channel_state": any(row.get("medium") == "WIFI" for row in interfaces),
        "truth_note": "Wi-Fi channel fields come from the local WLAN adapter. Ethernet reports link state/speed/duplex; switch-port channel or RF data requires infrastructure telemetry.",
    }


def install_link_state(app: FastAPI) -> FastAPI:
    if getattr(app.state, "link_state_installed", False):
        return app
    app.state.link_state_installed = True

    @app.get("/api/v1/system/link-state")
    async def link_state() -> dict[str, Any]:
        return await asyncio.to_thread(collect_link_state, app)

    return app
