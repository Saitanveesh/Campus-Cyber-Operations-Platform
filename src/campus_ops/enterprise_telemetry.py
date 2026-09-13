from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
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
    mode: str = "PASSIVE"
    tier: str = "OPTIONAL"


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


# Capability registry. Presence never authorizes execution. Active discovery tools
# are surfaced to operators but require explicit private/lab scope before use.
TOOLS = (
    ("TShark", "PACKET", "packet decode and protocol extraction", "tshark", "PASSIVE", "CORE"),
    ("dumpcap", "PACKET", "high-performance packet capture", "dumpcap", "PASSIVE", "CORE"),
    ("Wireshark", "PACKET", "interactive packet inspection", "wireshark", "PASSIVE", "OPTIONAL"),
    ("pktmon", "PACKET", "Windows packet/event capture", "pktmon", "PASSIVE", "OPTIONAL"),
    ("tcpdump", "PACKET", "Linux/WSL packet capture", "tcpdump", "PASSIVE", "OPTIONAL"),
    ("Zeek", "NETWORK_SECURITY", "structured protocol and network-security metadata", "zeek", "PASSIVE", "RECOMMENDED"),
    ("Suricata", "NETWORK_SECURITY", "IDS signatures, anomalies and protocol events", "suricata", "PASSIVE", "RECOMMENDED"),
    ("Snort", "NETWORK_SECURITY", "signature-based IDS validation", "snort", "PASSIVE", "OPTIONAL"),
    ("Arkime", "FORENSICS", "indexed packet/session forensics", "capture", "PASSIVE", "RECOMMENDED"),
    ("ntopng", "FLOW", "traffic and flow observability", "ntopng", "PASSIVE", "OPTIONAL"),
    ("nfdump", "FLOW", "NetFlow/IPFIX analysis", "nfdump", "PASSIVE", "RECOMMENDED"),
    ("pmacct", "FLOW", "flow/accounting telemetry", "pmacctd", "PASSIVE", "OPTIONAL"),
    ("softflowd", "FLOW", "flow export from interfaces", "softflowd", "PASSIVE", "OPTIONAL"),
    ("SNMP walk", "INFRASTRUCTURE", "switch/router inventory and counters", "snmpwalk", "READ_ONLY", "RECOMMENDED"),
    ("SNMP get", "INFRASTRUCTURE", "targeted infrastructure telemetry", "snmpget", "READ_ONLY", "RECOMMENDED"),
    ("LLDP CLI", "INFRASTRUCTURE", "local LLDP neighbor inspection", "lldpcli", "READ_ONLY", "OPTIONAL"),
    ("gNMI client", "INFRASTRUCTURE", "OpenConfig/YANG streaming telemetry client", "gnmic", "READ_ONLY", "OPTIONAL"),
    ("NETCONF client", "INFRASTRUCTURE", "NETCONF/YANG device telemetry helper", "netconf-console", "READ_ONLY", "OPTIONAL"),
    ("Nmap", "DISCOVERY", "authorized host/service discovery and verification", "nmap", "ACTIVE_AUTH_REQUIRED", "RECOMMENDED"),
    ("Angry IP Scanner", "DISCOVERY", "authorized fast host inventory and reachability scan", "ipscan", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("arp-scan", "DISCOVERY", "authorized local-segment ARP inventory", "arp-scan", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("traceroute", "DISCOVERY", "authorized route/path verification", "traceroute", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("tracert", "DISCOVERY", "Windows route/path verification", "tracert", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("osquery", "ENDPOINT", "endpoint state interrogation", "osqueryi", "READ_ONLY", "RECOMMENDED"),
    ("Velociraptor", "DFIR", "managed endpoint collection and hunting", "velociraptor", "MANAGED", "RECOMMENDED"),
    ("Sysmon", "ENDPOINT", "Windows process, network and security telemetry", "sysmon", "PASSIVE", "RECOMMENDED"),
    ("Sysinternals Autoruns", "DFIR", "persistence and startup inspection", "autorunsc", "READ_ONLY", "OPTIONAL"),
    ("Sysinternals TCPView", "DFIR", "endpoint connection inspection", "tcpvcon", "READ_ONLY", "OPTIONAL"),
    ("Sigma", "DETECTION", "portable detection-rule execution", "sigma", "PASSIVE", "RECOMMENDED"),
    ("YARA", "MALWARE", "file and memory rule matching", "yara", "READ_ONLY", "RECOMMENDED"),
    ("ClamAV", "MALWARE", "secondary malware file scanning", "clamscan", "READ_ONLY", "OPTIONAL"),
    ("Wazuh Agent", "ENDPOINT", "host telemetry and security monitoring", "wazuh-agentd", "PASSIVE", "OPTIONAL"),
    ("Volatility 3", "DFIR", "memory-forensics analysis", "vol", "OFFLINE_ANALYSIS", "OPTIONAL"),
    ("Plaso/log2timeline", "DFIR", "forensic timeline generation", "log2timeline.py", "OFFLINE_ANALYSIS", "OPTIONAL"),
    ("jq", "UTILITY", "structured JSON inspection", "jq", "READ_ONLY", "OPTIONAL"),
    ("curl", "UTILITY", "API and HTTP health validation", "curl", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("OpenSSL", "CRYPTO", "TLS certificate and cryptographic inspection", "openssl", "READ_ONLY", "OPTIONAL"),
    ("dig", "DNS", "DNS resolver inspection", "dig", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
    ("nslookup", "DNS", "DNS resolver inspection", "nslookup", "ACTIVE_AUTH_REQUIRED", "OPTIONAL"),
)


def _targets_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def telemetry_fabric_status() -> dict[str, Any]:
    tools: list[ToolCapability] = []
    for name, plane, purpose, command, mode, tier in TOOLS:
        native = _which(command)
        wsl = None if native else _wsl_which(command)
        state = "READY_NATIVE" if native else ("READY_WSL" if wsl else "NOT_INSTALLED")
        tools.append(ToolCapability(name, plane, purpose, command, native, wsl, state, mode, tier))

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
        "netflow_ipfix": {
            "state": "CONFIGURED" if os.environ.get("CAMPUS_OPS_FLOW_PORT", "").strip() else "NOT_CONFIGURED",
            "targets": 0,
            "model": "NetFlow/IPFIX flow telemetry",
        },
        "radius_nac": {
            "state": "CONFIGURED" if os.environ.get("CAMPUS_OPS_NAC_URL", "").strip() else "NOT_CONFIGURED",
            "targets": 1 if os.environ.get("CAMPUS_OPS_NAC_URL", "").strip() else 0,
            "model": "RADIUS/NAC identity and quarantine control",
        },
    }

    ready = sum(1 for tool in tools if tool.state.startswith("READY"))
    core = [tool for tool in tools if tool.tier == "CORE"]
    core_ready = sum(1 for tool in core if tool.state.startswith("READY"))
    by_plane: dict[str, dict[str, int]] = {}
    for tool in tools:
        plane = by_plane.setdefault(tool.plane, {"ready": 0, "total": 0})
        plane["total"] += 1
        if tool.state.startswith("READY"):
            plane["ready"] += 1

    return {
        "state": "READY" if core_ready == len(core) and ready >= 8 else ("PARTIAL" if ready else "BASELINE_ONLY"),
        "ready_tools": ready,
        "total_tools": len(tools),
        "core_ready": core_ready,
        "core_total": len(core),
        "tools": [asdict(tool) for tool in tools],
        "planes": by_plane,
        "streaming_telemetry": protocols,
        "design_rules": [
            "Passive collection remains the default.",
            "Active discovery and service verification require explicit operator action and authorized private/lab scope.",
            "Physical topology is asserted only from infrastructure evidence such as LLDP/CDP/SNMP/controller telemetry.",
            "Missing sensors are reported as unavailable rather than inferred.",
            "Tool presence is capability readiness, not permission to execute it.",
        ],
    }


def _ready(fabric: dict[str, Any], *, names: set[str] | None = None, planes: set[str] | None = None) -> bool:
    return any(
        str(tool.get("state", "")).startswith("READY")
        and (names is None or tool.get("name") in names)
        and (planes is None or tool.get("plane") in planes)
        for tool in fabric["tools"]
    )


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
        protocols = fabric["streaming_telemetry"]
        return {
            "engines": [
                {"name": "Packet Decode", "state": "READY" if _ready(fabric, names={"TShark"}) else "CORE_SENSOR_MISSING"},
                {"name": "Network Security Metadata", "state": "READY" if _ready(fabric, names={"Zeek"}) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "IDS", "state": "READY" if _ready(fabric, names={"Suricata", "Snort"}) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Flow Analytics", "state": "READY" if _ready(fabric, planes={"FLOW"}) or protocols["netflow_ipfix"]["state"] == "CONFIGURED" else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Infrastructure Telemetry", "state": "READY" if _ready(fabric, planes={"INFRASTRUCTURE"}) or any(protocols[k]["state"] == "CONFIGURED" for k in ("gnmi", "netconf", "restconf", "syslog")) else "NOT_CONFIGURED"},
                {"name": "Endpoint / DFIR", "state": "READY" if _ready(fabric, planes={"ENDPOINT", "DFIR"}) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Malware Analysis", "state": "READY" if _ready(fabric, planes={"MALWARE"}) else "OPTIONAL_SENSOR_MISSING"},
                {"name": "Authorized Discovery", "state": "READY" if _ready(fabric, planes={"DISCOVERY"}) else "OPTIONAL_TOOL_MISSING"},
                {"name": "NAC / Isolation", "state": "READY" if protocols["radius_nac"]["state"] == "CONFIGURED" else "NOT_CONFIGURED"},
            ],
            "fabric": fabric,
        }

    return app
