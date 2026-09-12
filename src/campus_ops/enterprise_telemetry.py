from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Any

from fastapi import FastAPI


@dataclass(slots=True)
class ToolCapability:
    name: str
    plane: str
    purpose: str
    command: str
    native_path: str | None
    wsl_path: str | None
    state: str


def _which(command: str) -> str | None:
    return shutil.which(command)


def _wsl_which(command: str) -> str | None:
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        return None
    try:
        result = subprocess.run(
            [wsl, "sh", "-lc", f"command -v {command} 2>/dev/null || true"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip().splitlines()
    return value[0] if value else None


TOOLS = (
    ("TShark", "PACKET", "packet decode and protocol extraction", "tshark"),
    ("dumpcap", "PACKET", "high-performance packet capture", "dumpcap"),
    ("tcpdump", "PACKET", "Linux/WSL packet capture", "tcpdump"),
    ("Zeek", "NETWORK_SECURITY", "structured network security metadata", "zeek"),
    ("Suricata", "NETWORK_SECURITY", "IDS signatures and protocol events", "suricata"),
    ("Arkime", "FORENSICS", "indexed packet/session forensics", "capture"),
    ("ntopng", "FLOW", "traffic and flow observability", "ntopng"),
    ("nfdump", "FLOW", "NetFlow/IPFIX analysis", "nfdump"),
    ("pmacct", "FLOW", "flow/accounting telemetry", "pmacctd"),
    ("SNMP walk", "INFRASTRUCTURE", "switch/router inventory and counters", "snmpwalk"),
    ("SNMP get", "INFRASTRUCTURE", "targeted infrastructure telemetry", "snmpget"),
    ("Nmap", "DISCOVERY", "explicitly authorized service verification", "nmap"),
    ("osquery", "ENDPOINT", "endpoint state interrogation", "osqueryi"),
    ("Velociraptor", "DFIR", "managed endpoint collection and hunting", "velociraptor"),
    ("Sigma", "DETECTION", "portable detection-rule execution", "sigma"),
    ("YARA", "MALWARE", "file and memory rule matching", "yara"),
    ("ClamAV", "MALWARE", "secondary malware file scanning", "clamscan"),
)


def _targets_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def telemetry_fabric_status() -> dict[str, Any]:
    tools: list[ToolCapability] = []
    for name, plane, purpose, command in TOOLS:
        native = _which(command)
        wsl = None if native else _wsl_which(command)
        state = "READY_NATIVE" if native else ("READY_WSL" if wsl else "NOT_INSTALLED")
        tools.append(ToolCapability(name, plane, purpose, command, native, wsl, state))

    protocols = {
        "gnmi": {
            "state": "CONFIGURED" if _targets_env("CAMPUS_OPS_GNMI_TARGETS") else "NOT_CONFIGURED",
            "targets": len(_targets_env("CAMPUS_OPS_GNMI_TARGETS")),
            "model": "YANG / OpenConfig streaming telemetry",
        },
        "netconf": {
            "state": "CONFIGURED" if _targets_env("CAMPUS_OPS_NETCONF_TARGETS") else "NOT_CONFIGURED",
            "targets": len(_targets_env("CAMPUS_OPS_NETCONF_TARGETS")),
            "model": "NETCONF / YANG device state",
        },
        "restconf": {
            "state": "CONFIGURED" if _targets_env("CAMPUS_OPS_RESTCONF_TARGETS") else "NOT_CONFIGURED",
            "targets": len(_targets_env("CAMPUS_OPS_RESTCONF_TARGETS")),
            "model": "RESTCONF / YANG device state",
        },
        "syslog": {
            "state": "CONFIGURED" if os.environ.get("CAMPUS_OPS_SYSLOG_PORT", "").strip() else "NOT_CONFIGURED",
            "targets": 0,
            "model": "passive infrastructure / firewall / NAC logs",
        },
    }

    ready = sum(1 for tool in tools if tool.state.startswith("READY"))
    by_plane: dict[str, dict[str, int]] = {}
    for tool in tools:
        plane = by_plane.setdefault(tool.plane, {"ready": 0, "total": 0})
        plane["total"] += 1
        if tool.state.startswith("READY"):
            plane["ready"] += 1

    return {
        "state": "READY" if ready >= 5 else ("PARTIAL" if ready else "BASELINE_ONLY"),
        "ready_tools": ready,
        "total_tools": len(tools),
        "tools": [asdict(tool) for tool in tools],
        "planes": by_plane,
        "streaming_telemetry": protocols,
        "design_rules": [
            "Passive collection remains the default.",
            "Active discovery and service verification require explicit operator action.",
            "Physical topology is asserted only from infrastructure evidence such as LLDP/CDP/SNMP/controller telemetry.",
            "Missing sensors are reported as unavailable rather than inferred.",
        ],
    }


def install_enterprise_telemetry(app: FastAPI) -> FastAPI:
    if getattr(app.state, "enterprise_telemetry_installed", False):
        return app
    app.state.enterprise_telemetry_installed = True

    @app.get("/api/v1/system/telemetry-fabric")
    async def telemetry_fabric() -> dict[str, Any]:
        return telemetry_fabric_status()

    @app.get("/api/v1/system/enterprise-engines")
    async def enterprise_engines() -> dict[str, Any]:
        fabric = telemetry_fabric_status()
        return {
            "engines": [
                {"name": "Packet Decode", "state": "READY" if any(t["name"] == "TShark" and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Network Security Metadata", "state": "READY" if any(t["name"] == "Zeek" and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "IDS", "state": "READY" if any(t["name"] == "Suricata" and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Flow Analytics", "state": "READY" if any(t["plane"] == "FLOW" and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Infrastructure Telemetry", "state": "READY" if any(t["plane"] == "INFRASTRUCTURE" and t["state"].startswith("READY") for t in fabric["tools"]) or any(v["state"] == "CONFIGURED" for v in fabric["streaming_telemetry"].values()) else "NOT_CONFIGURED"},
                {"name": "Endpoint / DFIR", "state": "READY" if any(t["plane"] in {"ENDPOINT", "DFIR"} and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Malware Analysis", "state": "READY" if any(t["plane"] == "MALWARE" and t["state"].startswith("READY") for t in fabric["tools"]) else "OPTIONAL_SENSOR_MISSING"},
            ],
            "fabric": fabric,
        }

    return app
