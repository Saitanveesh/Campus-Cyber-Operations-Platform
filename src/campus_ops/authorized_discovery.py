from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from campus_ops.admin_deep import _require_admin


class DiscoveryRequest(BaseModel):
    target: str = Field(min_length=3, max_length=64)
    authorized: bool = False
    mode: str = Field(default="HOSTS", max_length=16)


def _private_scope(value: str, *, network_allowed: bool) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    raw = value.strip()
    try:
        if "/" in raw:
            if not network_allowed:
                raise ValueError("this operation accepts one host only")
            net = ipaddress.ip_network(raw, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("IPv4 private lab scope is required")
            if not net.is_private:
                raise ValueError("active discovery is restricted to private lab networks")
            if net.num_addresses > 256:
                raise ValueError("discovery scope is limited to 256 addresses per operator action")
            return net
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(("this operation", "IPv4", "active discovery", "discovery scope")):
            raise
        raise ValueError("target must be a valid private IPv4 address or CIDR") from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError("active discovery is restricted to private lab IPv4 addresses")
    return ip


def _parse_nmap_grepable(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.startswith("Host: "):
            continue
        match = re.match(r"Host:\s+(\S+)\s+\((.*?)\)\s+Status:\s+(\S+)", line)
        if match:
            rows.append({"ip": match.group(1), "name": match.group(2), "state": match.group(3).upper()})
            continue
        match = re.match(r"Host:\s+(\S+)\s+\((.*?)\)\s+Ports:\s+(.+)", line)
        if match:
            ports: list[dict[str, Any]] = []
            for item in match.group(3).split(","):
                fields = item.strip().split("/")
                if len(fields) >= 5 and fields[0].isdigit():
                    ports.append(
                        {
                            "port": int(fields[0]),
                            "state": fields[1],
                            "transport": fields[2],
                            "service": fields[4] or "unknown",
                        }
                    )
            rows.append({"ip": match.group(1), "name": match.group(2), "ports": ports})
    return rows


def _run_nmap_hosts(scope: str) -> dict[str, Any]:
    nmap = shutil.which("nmap")
    if not nmap:
        return {"engine": "NMAP", "state": "NOT_INSTALLED", "hosts": []}
    process = subprocess.run(
        [nmap, "-sn", "-n", "--max-retries", "1", "--host-timeout", "3s", "-oG", "-", scope],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if process.returncode not in {0, 1}:
        raise RuntimeError((process.stderr or "Nmap host discovery failed").strip())
    rows = [row for row in _parse_nmap_grepable(process.stdout) if row.get("state") == "UP"]
    return {"engine": "NMAP", "state": "COMPLETE", "hosts": rows, "count": len(rows)}


def _run_nmap_services(host: str) -> dict[str, Any]:
    nmap = shutil.which("nmap")
    if not nmap:
        return {"engine": "NMAP", "state": "NOT_INSTALLED", "target": host, "ports": []}
    process = subprocess.run(
        [
            nmap,
            "-sT",
            "-n",
            "--top-ports",
            "25",
            "-T3",
            "--max-retries",
            "1",
            "--host-timeout",
            "15s",
            "-oG",
            "-",
            host,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if process.returncode not in {0, 1}:
        raise RuntimeError((process.stderr or "Nmap service verification failed").strip())
    rows = _parse_nmap_grepable(process.stdout)
    port_rows = next((row.get("ports", []) for row in rows if row.get("ports") is not None), [])
    return {"engine": "NMAP", "state": "COMPLETE", "target": host, "ports": port_rows}


def _socket_fallback(host: str) -> dict[str, Any]:
    ports = (22, 53, 80, 88, 135, 139, 389, 443, 445, 636, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443)
    open_ports: list[dict[str, Any]] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.18)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append({"port": port, "state": "open", "transport": "tcp", "service": "observed"})
        finally:
            sock.close()
    return {"engine": "SOCKET_FALLBACK", "state": "COMPLETE", "target": host, "ports": open_ports}


def install_authorized_discovery(app: FastAPI) -> FastAPI:
    if getattr(app.state, "authorized_discovery_installed", False):
        return app
    app.state.authorized_discovery_installed = True

    @app.post("/api/v1/admin/discovery")
    async def authorized_discovery(
        body: DiscoveryRequest,
        request: Request,
        x_campus_admin: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_admin(app, request, x_campus_admin)
        if not body.authorized:
            raise HTTPException(status_code=403, detail="explicit private-lab authorization is required")
        mode = body.mode.upper().strip()
        if mode not in {"HOSTS", "SERVICES"}:
            raise HTTPException(status_code=400, detail="mode must be HOSTS or SERVICES")
        try:
            parsed = _private_scope(body.target, network_allowed=mode == "HOSTS")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            if mode == "HOSTS":
                scope = str(parsed)
                if isinstance(parsed, ipaddress.IPv4Address):
                    scope = f"{parsed}/32"
                result = _run_nmap_hosts(scope)
            else:
                host = str(parsed)
                result = _run_nmap_services(host)
                if result["state"] == "NOT_INSTALLED":
                    result = _socket_fallback(host)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "authorized": True,
            "scope": str(parsed),
            "mode": mode,
            "result": result,
            "guardrail": "Results are active validation evidence for the explicitly authorized private/lab scope only.",
        }

    return app
