from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import psutil

AGENT_VERSION = "0.3.0"


def _agent_root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberAgent"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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

    connection_counts = {"tcp": 0, "udp": 0, "listen": 0}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.type == socket.SOCK_STREAM:
                connection_counts["tcp"] += 1
                if conn.status == psutil.CONN_LISTEN:
                    connection_counts["listen"] += 1
            elif conn.type == socket.SOCK_DGRAM:
                connection_counts["udp"] += 1
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
        "connections": connection_counts,
        "processes": processes[:100],
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
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
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
    import ipaddress

    ipaddress.ip_address(remote_ip)
    if os.name != "nt":
        return {"remote_ip": remote_ip, "state": "UNSUPPORTED_ON_THIS_AGENT"}
    rule_name = f"CampusOps Block {remote_ip}"
    import subprocess

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
        return "REJECTED", {"reason": "action is not implemented by this agent"}
    except (OSError, ValueError, PermissionError, psutil.Error) as exc:
        return "FAILED", {"reason": str(exc), "type": type(exc).__name__}


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
                status, result = execute_job(job)
                _request(
                    base_url,
                    "POST",
                    f"/api/v1/agents/{endpoint_id}/jobs/{job['job_id']}/result",
                    token,
                    {"status": status, "result": result},
                )
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            print(f"agent connection error: {exc}", file=sys.stderr)
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Campus Cyber Operations endpoint agent")
    parser.add_argument("--server", required=True, help="Console base URL, for example http://10.0.0.10:8765")
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--token", default=os.environ.get("CAMPUS_OPS_AGENT_TOKEN", ""))
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if not args.token:
        parser.error("--token or CAMPUS_OPS_AGENT_TOKEN is required")
    raise SystemExit(run_agent(args.server, args.endpoint_id, args.token, args.interval))


if __name__ == "__main__":
    main()
