"""Deployment inventory and live sensor supervision status; no privileged HTTP actions."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from campus_ops.linux_host import host_status

SENSORS = {
    "Zeek": "zeek", "Suricata": "suricata", "Falco": "falco", "OpenCanary": "opencanary",
}
WINDOWS_TOOLS = {"pktmon", "tracert", "Sysmon", "Sysinternals Autoruns", "Sysinternals TCPView"}

# Prerequisite classes are actionable scope, not claims of installed integrations.
EXTERNAL_TOOLS = {
    "Tetragon": ("ENDPOINT", "Linux BTF/eBPF deployment and a configured JSON export"),
    "Pixie": ("KUBERNETES", "Kubernetes cluster and Pixie deployment"),
    "Hubble": ("KUBERNETES", "Cilium/Hubble deployment and a configured flow export"),
    "Cilium": ("CONTROL", "Kubernetes/network dataplane deployment"),
    "Inspektor Gadget": ("KUBERNETES", "Compatible eBPF host or Kubernetes deployment"),
    "Neo4j": ("GRAPH", "Provisioned graph database; connector pending"),
    "BloodHound Enterprise": ("IDENTITY", "License, identity tenant and collection deployment"),
    "T-Pot": ("DECEPTION", "Dedicated honeypot host and resource budget"),
    "Wazuh": ("ENDPOINT", "Wazuh manager and configured alerts export"),
    "TheHive": ("CASES", "Provisioned service and authenticated API"),
    "MISP": ("INTELLIGENCE", "Provisioned service and authenticated API"),
    "OpenCTI": ("INTELLIGENCE", "Provisioned service and authenticated API"),
    "Velociraptor": ("DFIR", "Server/client enrollment, certificates and collection policy"),
    "Arkime": ("FORENSICS", "Capture deployment, OpenSearch backend, storage and retention budget"),
}
LAB_TOOLS = (
    "MITRE Caldera", "Infection Monkey", "Atomic Red Team", "VECTR", "DeTTECT", "PurpleSharp",
    "Chisel", "Ligolo-ng", "SSHuttle", "Sliver", "Mythic", "Havoc", "Cobalt Strike", "Covenant",
    "Metasploit Framework / Pro", "Burp Suite Professional", "CrackMapExec / NetExec", "Impacket",
    "Evil-WinRM", "Responder", "Brute Ratel C4", "Nighthawk", "Empire", "Merlin",
)
CONTROL_TOOLS = (
    "Teleport", "Ngrok", "Illumio", "Akamai Guardicore", "Cisco Secure Workload (Tetration)",
    "VMware NSX", "Zero Networks", "Zscaler Private Access (ZPA)", "AppGate SDP", "Elisity",
    "ColorTokens", "AccuKnox",
)


def read_json(path: Path) -> dict:
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def deployment_status(root: Path | None = None, runtime: Path | None = None) -> dict:
    root = root or Path(os.environ.get("CAMPUS_OPS_CONFIG_DIR", "/etc/campus-ops"))
    runtime = runtime or Path("/run/campus-ops-sensors")
    manifest = read_json(root / "deployment.json")
    sensors = {}
    for key in SENSORS.values():
        status = read_json(runtime / f"{key}.json")
        try:
            current = 0 <= time.time() - float(status.get("checked_at", 0)) < 15
        except (ValueError, TypeError):
            current = False
        if not current:
            installed = manifest.get("components", {}).get(key, {})
            state = installed.get("state", "NOT_INSTALLED")
            status = {"state": "NOT_RUNNING" if state == "INSTALLED" else state,
                      "detail": installed.get("detail") or "No current supervisor heartbeat"}
        sensors[key] = status
    return {"installed": bool(manifest), "installation": manifest, "sensors": sensors,
            "host": host_status(), "setup_command": "sudo bash scripts/install_ubuntu.sh"}


def enrich_tools(rows: list[dict], orch=None) -> list[dict]:
    deployment = deployment_status()
    fabric = getattr(orch, "operations_fabric", None) if orch else None
    for row in rows:
        if os.name != "nt" and row["name"] in WINDOWS_TOOLS:
            row["state"] = "NOT_APPLICABLE"
            row["purpose"] += ". Windows-only; not an Ubuntu prerequisite."
        sensor = SENSORS.get(row["name"])
        if sensor:
            state = deployment["sensors"][sensor]
            row["service_state"] = state["state"]
            row["service_detail"] = state.get("detail", "")
            row["feed_records"] = 0
            row["feed_state"] = "WAITING"
            if orch:
                worker = next((w for w in getattr(orch, "workers", [])
                               if w.name == f"{sensor}-feed"), None)
                metric = fabric.metrics.get(sensor, {}) if fabric else {}
                row["feed_records"] = getattr(worker, "records", 0) or metric.get("accepted", 0)
                last = getattr(worker, "last_received", None) or metric.get("last_received")
                row["last_received"] = last
                row["feed_errors"] = getattr(worker, "errors", 0) or metric.get("errors", 0)
                row["feed_state"] = ("RECEIVED" if last and 0 <= time.time() - last < 60
                                     else "IDLE" if last else "WAITING")
            if state["state"] == "RUNNING":
                row["state"] = "READY_RECEIVING" if row["feed_state"] == "RECEIVED" else "READY_LISTENING"
            elif deployment["installed"]:
                row["state"] = state["state"]
            row["purpose"] += (f". Service: {row['service_state']}; feed: {row['feed_state']}"
                               f" ({row['feed_records']} records). {state.get('detail', '')}")
    existing = {row["name"] for row in rows}
    external = dict(EXTERNAL_TOOLS)
    external.update({name: ("LAB_VALIDATION", "Separate scoped lab deployment; not a monitoring daemon")
                     for name in LAB_TOOLS})
    external.update({name: ("CONTROL", "Tenant/service configuration, credentials and applicable license")
                     for name in CONTROL_TOOLS})
    for name, (plane, reason) in external.items():
        if name in existing:
            for row in rows:
                if row["name"] == name and row["state"] == "NOT_INSTALLED":
                    row["state"] = "REQUIRES_DEPLOYMENT"
                    row["purpose"] += ". " + reason
            continue
        rows.append({"name": name, "plane": plane, "purpose": reason,
                     "command": "External deployment", "native_path": None, "wsl_path": None,
                     "state": "REQUIRES_DEPLOYMENT", "mode": "EXTERNAL", "tier": "OPTIONAL"})
    return rows
