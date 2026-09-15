from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import psutil

from campus_ops.linux_host import services as linux_services
from campus_ops.platform_paths import data_root

AGENT_VERSION = "0.3.0"
ISOLATION_GROUP = "CampusOps Isolation"


def _agent_root() -> Path:
    root = data_root(agent=True)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _network_addresses() -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            raw = address.address.split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                continue
            values.append(
                {
                    "interface": interface,
                    "address": raw,
                    "netmask": str(address.netmask or ""),
                }
            )
    return values


def _services() -> list[dict[str, str]]:
    if os.name != "nt":
        return linux_services()
    if not hasattr(psutil, "win_service_iter"):
        return []
    result = []
    try:
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except (psutil.Error, OSError):
                continue
            result.append(
                {
                    "name": str(info.get("name") or ""),
                    "display_name": str(info.get("display_name") or ""),
                    "status": str(info.get("status") or ""),
                    "start_type": str(info.get("start_type") or ""),
                }
            )
    except (psutil.Error, OSError):
        return []
    return result[:500]


def collect_telemetry() -> dict[str, Any]:
    disk_root = Path.home().anchor or "/"
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(disk_root)
    processes: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        processes.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "user": info.get("username"),
                "cpu_percent": info.get("cpu_percent"),
                "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
            }
        )
    processes.sort(key=lambda item: float(item.get("memory_percent") or 0.0), reverse=True)

    connections: list[dict[str, Any]] = []
    connection_counts = {"tcp": 0, "udp": 0, "listen": 0}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.type == socket.SOCK_STREAM:
                connection_counts["tcp"] += 1
                if conn.status == psutil.CONN_LISTEN:
                    connection_counts["listen"] += 1
            elif conn.type == socket.SOCK_DGRAM:
                connection_counts["udp"] += 1
            if len(connections) < 300:
                connections.append(
                    {
                        "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
    except (psutil.AccessDenied, OSError):
        pass

    users = []
    try:
        users = sorted({user.name for user in psutil.users() if user.name})
    except OSError:
        pass

    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_count": psutil.cpu_count(),
        "memory_percent": memory.percent,
        "memory_used": memory.used,
        "memory_total": memory.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "boot_time": psutil.boot_time(),
        "users": users,
        "network_addresses": _network_addresses(),
        "connections": connection_counts,
        "connection_sample": connections,
        "processes": processes[:150],
        "services": _services(),
        "isolation_state": "ISOLATED" if (_agent_root() / "isolation_state.json").exists() else "NORMAL",
    }


def _request(
    base_url: str,
    method: str,
    path: str,
    token: str,
    body: dict[str, Any] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"CampusCyberAgent/{AGENT_VERSION}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def _safe_pid(value: object) -> int:
    try:
        pid = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("pid must be an integer") from exc
    if pid <= 4 or pid == os.getpid():
        raise PermissionError("protected process")
    return pid


def _stop_process(arguments: dict[str, Any]) -> dict[str, Any]:
    pid = _safe_pid(arguments.get("pid"))
    proc = psutil.Process(pid)
    name = proc.name()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except psutil.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    return {"pid": pid, "name": name, "state": "STOPPED"}


def _quarantine_file(arguments: dict[str, Any]) -> dict[str, Any]:
    raw_path = str(arguments.get("path") or "").strip()
    if not raw_path:
        raise ValueError("path is required")
    source = Path(raw_path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError("path is not a regular file")
    digest = _sha256(source)
    quarantine = _agent_root() / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)
    target = quarantine / f"{digest[:16]}-{source.name}"
    shutil.move(str(source), str(target))
    return {"source": str(source), "quarantined": str(target), "sha256": digest}


def _block_remote_ip(arguments: dict[str, Any]) -> dict[str, Any]:
    remote_ip = str(arguments.get("remote_ip") or "").strip()
    if not remote_ip:
        raise ValueError("remote_ip is required")
    ipaddress.ip_address(remote_ip)
    if os.name != "nt":
        return {"remote_ip": remote_ip, "state": "UNSUPPORTED_ON_THIS_AGENT"}
    rule_name = f"CampusOps Block {remote_ip}"
    process = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$ErrorActionPreference='Stop'; "
                f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound "
                f"-RemoteAddress '{remote_ip}' -Action Block -Profile Any | Out-Null; "
                f"New-NetFirewallRule -DisplayName '{rule_name} In' -Direction Inbound "
                f"-RemoteAddress '{remote_ip}' -Action Block -Profile Any | Out-Null"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if process.returncode != 0:
        raise PermissionError(process.stderr.strip() or "firewall rule creation failed")
    return {"remote_ip": remote_ip, "state": "BLOCKED", "rule": rule_name}


def _run_powershell(script: str, timeout: float = 25.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _isolation_state_path() -> Path:
    return _agent_root() / "isolation_state.json"


def _isolate_host(arguments: dict[str, Any]) -> dict[str, Any]:
    if os.name != "nt":
        return {"state": "UNSUPPORTED_ON_THIS_AGENT"}
    raw_management = str(arguments.get("management_ip") or "").strip()
    if not raw_management:
        raise ValueError("management_ip is required to preserve the control channel")
    management_ip = str(ipaddress.ip_address(raw_management))
    state_path = _isolation_state_path()
    if state_path.exists():
        try:
            existing = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
        return {
            "state": "ALREADY_ISOLATED",
            "management_ip": existing.get("management_ip") or management_ip,
        }

    query = (
        "$ErrorActionPreference='Stop'; "
        "@(Get-NetFirewallProfile | ForEach-Object { "
        "[PSCustomObject]@{Name=$_.Name;Enabled=$_.Enabled;"
        "DefaultInboundAction=$_.DefaultInboundAction.ToString();"
        "DefaultOutboundAction=$_.DefaultOutboundAction.ToString()} "
        "}) | ConvertTo-Json -Depth 4 -Compress"
    )
    current = _run_powershell(query)
    if current.returncode != 0:
        raise PermissionError(current.stderr.strip() or "unable to read Windows Firewall profile state")
    try:
        profiles = json.loads((current.stdout or "[]").strip() or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError("unable to parse Windows Firewall profile state") from exc
    if isinstance(profiles, dict):
        profiles = [profiles]
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("Windows Firewall profile state is unavailable")

    apply_script = (
        "$ErrorActionPreference='Stop'; "
        f"Get-NetFirewallRule -Group '{ISOLATION_GROUP}' -ErrorAction SilentlyContinue | "
        "Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -DisplayName 'CampusOps Management Out' -Group '{ISOLATION_GROUP}' "
        f"-Direction Outbound -Action Allow -RemoteAddress '{management_ip}' -Profile Any | Out-Null; "
        f"New-NetFirewallRule -DisplayName 'CampusOps Management In' -Group '{ISOLATION_GROUP}' "
        f"-Direction Inbound -Action Allow -RemoteAddress '{management_ip}' -Profile Any | Out-Null; "
        "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True "
        "-DefaultInboundAction Block -DefaultOutboundAction Block"
    )
    applied = _run_powershell(apply_script)
    if applied.returncode != 0:
        raise PermissionError(applied.stderr.strip() or "host isolation firewall policy failed")

    state = {
        "management_ip": management_ip,
        "profiles": profiles,
        "group": ISOLATION_GROUP,
        "created_at": time.time(),
    }
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return {
        "state": "ISOLATED",
        "management_ip": management_ip,
        "policy": "DEFAULT_BLOCK_WITH_MANAGEMENT_EXCEPTION",
    }


def _restore_network(_arguments: dict[str, Any]) -> dict[str, Any]:
    if os.name != "nt":
        return {"state": "UNSUPPORTED_ON_THIS_AGENT"}
    state_path = _isolation_state_path()
    if not state_path.exists():
        return {"state": "NOT_ISOLATED"}
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("saved isolation state is unreadable") from exc
    profiles = state.get("profiles") if isinstance(state.get("profiles"), list) else []
    lines = [
        "$ErrorActionPreference='Stop'",
        f"Get-NetFirewallRule -Group '{ISOLATION_GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
    ]
    for item in profiles:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "").replace("'", "''")
        if name not in {"Domain", "Private", "Public"}:
            continue
        enabled = "$true" if bool(item.get("Enabled")) else "$false"
        inbound = str(item.get("DefaultInboundAction") or "NotConfigured")
        outbound = str(item.get("DefaultOutboundAction") or "NotConfigured")
        if inbound not in {"Allow", "Block", "NotConfigured"}:
            inbound = "NotConfigured"
        if outbound not in {"Allow", "Block", "NotConfigured"}:
            outbound = "NotConfigured"
        lines.append(
            f"Set-NetFirewallProfile -Profile '{name}' -Enabled {enabled} "
            f"-DefaultInboundAction {inbound} -DefaultOutboundAction {outbound}"
        )
    restored = _run_powershell("; ".join(lines))
    if restored.returncode != 0:
        raise PermissionError(restored.stderr.strip() or "network restoration failed")
    state_path.unlink(missing_ok=True)
    return {"state": "RESTORED", "restored_profiles": len(profiles)}


def execute_job(job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    action = str(job.get("action") or "").upper()
    arguments = job.get("arguments") if isinstance(job.get("arguments"), dict) else {}
    try:
        if action == "COLLECT_SNAPSHOT":
            return "SUCCEEDED", {"snapshot": collect_telemetry()}
        if action == "STOP_PROCESS":
            return "SUCCEEDED", _stop_process(arguments)
        if action == "QUARANTINE_FILE":
            return "SUCCEEDED", _quarantine_file(arguments)
        if action == "BLOCK_REMOTE_IP":
            return "SUCCEEDED", _block_remote_ip(arguments)
        if action == "ISOLATE_HOST":
            return "SUCCEEDED", _isolate_host(arguments)
        if action == "RESTORE_NETWORK":
            return "SUCCEEDED", _restore_network(arguments)
        return "REJECTED", {"reason": "action is not implemented by this agent"}
    except (OSError, ValueError, PermissionError, psutil.Error, subprocess.SubprocessError) as exc:
        return "FAILED", {"reason": str(exc), "type": type(exc).__name__}


def _management_ip(base_url: str) -> str:
    host = urllib.parse.urlsplit(base_url).hostname or ""
    if not host:
        raise ValueError("server URL has no hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    for info in infos:
        candidate = str(info[4][0]).split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    raise ValueError("unable to resolve management server address")


def run_agent(base_url: str, endpoint_id: str, token: str, interval: float) -> int:
    interval = max(2.0, interval)
    while True:
        telemetry = collect_telemetry()
        try:
            _request(
                base_url,
                "POST",
                f"/api/v1/agents/{endpoint_id}/heartbeat",
                token,
                {
                    "host": socket.gethostname(),
                    "version": AGENT_VERSION,
                    "telemetry": telemetry,
                },
            )
            payload = _request(
                base_url,
                "GET",
                f"/api/v1/agents/{endpoint_id}/jobs?limit=10",
                token,
            )
            for job in payload.get("jobs", []):
                executable_job = dict(job)
                if str(executable_job.get("action") or "").upper() == "ISOLATE_HOST":
                    arguments = (
                        dict(executable_job.get("arguments"))
                        if isinstance(executable_job.get("arguments"), dict)
                        else {}
                    )
                    arguments.setdefault("management_ip", _management_ip(base_url))
                    executable_job["arguments"] = arguments
                status, result = execute_job(executable_job)
                _request(
                    base_url,
                    "POST",
                    f"/api/v1/agents/{endpoint_id}/jobs/{job['job_id']}/result",
                    token,
                    {"status": status, "result": result},
                )
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"agent connection error: {exc}", file=sys.stderr)
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Campus Cyber Operations endpoint agent")
    parser.add_argument(
        "--server",
        required=True,
        help="Console base URL, for example http://10.0.0.10:8765",
    )
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--token", default=os.environ.get("CAMPUS_OPS_AGENT_TOKEN", ""))
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if not args.token:
        parser.error("--token or CAMPUS_OPS_AGENT_TOKEN is required")
    raise SystemExit(run_agent(args.server, args.endpoint_id, args.token, args.interval))


if __name__ == "__main__":
    main()
