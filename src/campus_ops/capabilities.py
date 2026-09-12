from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any

from fastapi import FastAPI, HTTPException

from campus_ops.tooling.registry import resolve_executable


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    key: str
    label: str
    plane: str
    purpose: str
    tool_groups: tuple[tuple[str, ...], ...] = ()
    workers: tuple[str, ...] = ()
    priority: str = "RECOMMENDED"


CAPABILITIES: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        "live_packet_visibility",
        "Live Packet Visibility",
        "NETWORK",
        "Continuous packet metadata, protocol decoding and live flow construction.",
        (("npcap",), ("tshark",)),
        ("capture", "flow-engine", "protocol-engine"),
        "CORE",
    ),
    CapabilitySpec(
        "forensic_packet_evidence",
        "Forensic Packet Evidence",
        "EVIDENCE",
        "Bounded rolling PCAP-NG evidence for incident reconstruction.",
        (("npcap",), ("dumpcap",)),
        ("forensic-pcap",),
        "CORE",
    ),
    CapabilitySpec(
        "network_ids",
        "Network IDS",
        "INTELLIGENCE",
        "Signature-backed network alert telemetry in addition to behavioural detections.",
        (("suricata",),),
        ("suricata-feed", "threat-engine"),
    ),
    CapabilitySpec(
        "malware_triage",
        "Malware Triage",
        "INTELLIGENCE",
        "Hashing, YARA matching, signature trust and optional second-opinion scanning.",
        (("yara", "sigcheck", "clamscan"),),
        ("malware-analysis",),
    ),
    CapabilitySpec(
        "windows_endpoint_visibility",
        "Windows Endpoint Visibility",
        "ENDPOINT",
        "Native host telemetry, event logs and optional Sysmon/osquery enrichment.",
        (("powershell", "pwsh"), ("wevtutil",),),
        ("local-host-telemetry", "endpoint-identity"),
        "CORE",
    ),
    CapabilitySpec(
        "endpoint_deep_analytics",
        "Endpoint Deep Analytics",
        "ENDPOINT",
        "Authenticated endpoint process, connection, listener, service and user correlation.",
        (),
        ("endpoint-identity", "endpoint-deep-monitor"),
        "CORE",
    ),
    CapabilitySpec(
        "lateral_movement_analytics",
        "Lateral Movement Analytics",
        "INTELLIGENCE",
        "Internal administrative-protocol fan-out detection with evidence-backed confidence.",
        (),
        ("lateral-movement-watch",),
    ),
    CapabilitySpec(
        "periodic_connection_analytics",
        "Periodic Connection Analytics",
        "INTELLIGENCE",
        "Detect repeated low-variation outbound connection starts without declaring malware.",
        (),
        ("beaconing-watch",),
    ),
    CapabilitySpec(
        "windows_security_posture",
        "Windows Security Posture",
        "ENDPOINT",
        "Live Defender, Firewall and Sysmon posture for the monitoring host.",
        (("powershell", "pwsh"),),
        ("windows-security-telemetry",),
    ),
    CapabilitySpec(
        "dfir_hunting",
        "DFIR Event Hunting",
        "EVIDENCE",
        "Fast Windows event-log hunting and persistence investigation.",
        (("hayabusa", "chainsaw", "sysmon", "autoruns"),),
        (),
    ),
    CapabilitySpec(
        "binary_trust",
        "Binary Trust & Process Triage",
        "ENDPOINT",
        "Signature verification, handle inspection and persistence inspection.",
        (("sigcheck", "handle", "autoruns"),),
        (),
    ),
    CapabilitySpec(
        "infrastructure_telemetry",
        "Infrastructure Telemetry",
        "NETWORK",
        "Syslog, flow export and SNMP/LLDP evidence for campus-wide context.",
        (),
        ("syslog-receiver", "flow-telemetry-receiver", "snmp-poller", "infrastructure-intelligence"),
        "CORE",
    ),
    CapabilitySpec(
        "topology_intelligence",
        "Topology Intelligence",
        "INTELLIGENCE",
        "Observed communication topology plus infrastructure-backed hierarchy when evidence exists.",
        (),
        ("topology-engine", "asset-engine", "identity-engine", "risk-graph"),
        "CORE",
    ),
    CapabilitySpec(
        "response_control",
        "Response Control",
        "CONTROL",
        "Policy-gated endpoint actions, scheduled response jobs and remote administration.",
        (("powershell", "pwsh"),),
        ("job-scheduler",),
        "CORE",
    ),
    CapabilitySpec(
        "authorized_discovery",
        "Authorized Discovery",
        "NETWORK",
        "Optional operator-initiated lab inventory and service verification. Never auto-runs.",
        (("nmap",),),
        (),
    ),
    CapabilitySpec(
        "native_packet_diagnostics",
        "Native Packet Diagnostics",
        "NETWORK",
        "Windows-native fallback diagnostics and packet collection support.",
        (("pktmon",), ("netsh",)),
        (),
    ),
)


DIAGNOSTICS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "capture-devices": ("tshark", ("-D",), "List packet-capture interfaces visible to TShark."),
    "dumpcap-devices": ("dumpcap", ("-D",), "List packet-capture interfaces visible to dumpcap."),
    "network-adapters": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress,InterfaceDescription | Format-Table -AutoSize",
        ),
        "Show Windows network adapters and link state.",
    ),
    "ipv4-routes": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 30 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -AutoSize",
        ),
        "Show the highest-priority IPv4 routes.",
    ),
    "tcp-connections": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-NetTCPConnection | Group-Object State | Sort-Object Count -Descending | Select-Object Count,Name | Format-Table -AutoSize",
        ),
        "Summarize local TCP connection states.",
    ),
    "defender-status": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated | Format-List",
        ),
        "Read Microsoft Defender protection state.",
    ),
    "defender-detections": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID,ThreatStatusID,InitialDetectionTime,Resources | Format-List",
        ),
        "Show recent Microsoft Defender threat detections when available.",
    ),
    "sysmon-status": (
        "powershell",
        (
            "-NoProfile",
            "-Command",
            "Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize",
        ),
        "Show Sysmon service state when installed.",
    ),
    "event-logs": ("wevtutil", ("el",), "List Windows event-log channels."),
    "wifi-link": ("netsh", ("wlan", "show", "interfaces"), "Show current Windows Wi-Fi link telemetry."),
    "pktmon-components": ("pktmon", ("list",), "Show Windows packet-monitor components."),
}


def _tool_map(tools: object) -> dict[str, dict[str, Any]]:
    if not isinstance(tools, list):
        return {}
    return {
        str(item.get("key")): item
        for item in tools
        if isinstance(item, dict) and item.get("key")
    }


def _worker_ready(worker: object) -> bool:
    if not isinstance(worker, dict):
        return False
    return str(worker.get("state") or "").upper() in {"HEALTHY", "RUNNING", "STARTING"}


def capability_status(snapshot: dict[str, Any]) -> dict[str, object]:
    tools = _tool_map(snapshot.get("tools"))
    workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), dict) else {}
    rows: list[dict[str, object]] = []

    for spec in CAPABILITIES:
        tool_groups_ready = [
            any(bool(tools.get(key, {}).get("available")) for key in group)
            for group in spec.tool_groups
        ]
        worker_ready = [_worker_ready(workers.get(name)) for name in spec.workers]
        checks = tool_groups_ready + worker_ready
        ready_count = sum(1 for item in checks if item)
        if not checks or ready_count == len(checks):
            state = "READY"
        elif ready_count:
            state = "PARTIAL"
        else:
            state = "MISSING"

        missing_tools = [
            " / ".join(group)
            for group, ready in zip(spec.tool_groups, tool_groups_ready, strict=False)
            if not ready
        ]
        missing_workers = [
            name for name, ready in zip(spec.workers, worker_ready, strict=False) if not ready
        ]
        rows.append(
            {
                **asdict(spec),
                "state": state,
                "ready_checks": ready_count,
                "total_checks": len(checks),
                "missing_tools": missing_tools,
                "missing_workers": missing_workers,
            }
        )

    core = [row for row in rows if row["priority"] == "CORE"]
    optional = [row for row in rows if row["priority"] != "CORE"]
    core_ready = sum(1 for row in core if row["state"] == "READY")
    optional_ready = sum(1 for row in optional if row["state"] == "READY")
    ready = sum(1 for row in rows if row["state"] == "READY")

    operational_readiness = round(core_ready / len(core) * 100) if core else 100
    coverage_score = round(ready / len(rows) * 100) if rows else 100

    core_gaps = [row for row in core if row["state"] != "READY"]
    optional_gaps = [row for row in optional if row["state"] != "READY"]
    core_gaps.sort(key=lambda row: (row["state"] != "MISSING", str(row["label"])))
    optional_gaps.sort(key=lambda row: (row["state"] != "MISSING", str(row["label"])))
    gaps = [*core_gaps, *optional_gaps]

    return {
        "score": min(100, operational_readiness),
        "operational_readiness": min(100, operational_readiness),
        "coverage_score": min(100, coverage_score),
        "core_ready": core_ready,
        "core_total": len(core),
        "optional_ready": optional_ready,
        "optional_total": len(optional),
        "ready": ready,
        "total": len(rows),
        "capabilities": rows,
        "core_gaps": core_gaps,
        "optional_gaps": optional_gaps,
        "next_gaps": gaps[:6],
        "diagnostics": [
            {"key": key, "tool": value[0], "description": value[2]}
            for key, value in DIAGNOSTICS.items()
        ],
    }


def run_diagnostic(key: str) -> dict[str, object]:
    spec = DIAGNOSTICS.get(key)
    if spec is None:
        raise KeyError(key)
    tool_key, args, description = spec
    executable = resolve_executable(tool_key)
    if not executable:
        return {
            "key": key,
            "description": description,
            "tool": tool_key,
            "status": "UNAVAILABLE",
            "exit_code": None,
            "output": f"{tool_key} is not available on this host.",
        }
    try:
        result = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "key": key,
            "description": description,
            "tool": tool_key,
            "status": "ERROR",
            "exit_code": None,
            "output": str(exc),
        }
    output = (result.stdout or result.stderr or "No output returned.").strip()
    return {
        "key": key,
        "description": description,
        "tool": tool_key,
        "status": "PASS" if result.returncode == 0 else "ERROR",
        "exit_code": result.returncode,
        "output": output[:24000],
    }


def install_capability_routes(app: FastAPI) -> FastAPI:
    if getattr(app.state, "capability_routes_installed", False):
        return app
    app.state.capability_routes_installed = True

    @app.get("/api/v1/system/capabilities")
    async def system_capabilities() -> dict[str, object]:
        return capability_status(app.state.orchestrator.snapshot())

    @app.post("/api/v1/system/diagnostics/{check}")
    async def system_diagnostic(check: str) -> dict[str, object]:
        if check not in DIAGNOSTICS:
            raise HTTPException(status_code=404, detail="Unknown diagnostic check")
        return run_diagnostic(check)

    return app
