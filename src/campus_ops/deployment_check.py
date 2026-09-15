"""Post-install checks for the stable single-source runtime."""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from campus_ops.deployment import deployment_status
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.network_discovery import discover_candidates, elect_network

_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13
_REQUIRED_CAPTURE_MASK = (1 << _CAP_NET_ADMIN) | (1 << _CAP_NET_RAW)


def _managed_service_capability_check() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["systemctl", "show", "campus-ops.service", "--property=MainPID", "--value"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return False, "systemctl could not read campus-ops.service MainPID"
        pid = int(result.stdout.strip() or "0")
        if pid <= 0:
            return False, "campus-ops.service has no running MainPID"
        values: dict[str, str] = {}
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            key, sep, value = line.partition(":")
            if sep:
                values[key] = value.strip()
        effective = int(values.get("CapEff", "0"), 16)
        ambient = int(values.get("CapAmb", "0"), 16)
        ok = (
            effective & _REQUIRED_CAPTURE_MASK == _REQUIRED_CAPTURE_MASK
            and ambient & _REQUIRED_CAPTURE_MASK == _REQUIRED_CAPTURE_MASK
        )
        if ok:
            return True, f"service MainPID {pid} has packet-capture capabilities"
        return False, (
            f"service MainPID {pid} lacks capture capabilities "
            f"(CapEff={values.get('CapEff', '0')}, CapAmb={values.get('CapAmb', '0')})"
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return False, f"service capability check failed: {exc}"


def _tshark_capture_check(interface: str, tshark: str) -> tuple[bool, str]:
    """Exercise the exact external tool used by stable mode."""
    try:
        result = subprocess.run(
            [
                "runuser", "-u", "campus-ops", "--", tshark,
                "-n", "-i", interface, "-a", "duration:1",
                "-T", "fields", "-e", "frame.len",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    detail = result.stderr.decode(errors="replace").strip()[-500:]
    if result.returncode == 0:
        return True, "TShark opened the selected interface successfully"
    return False, detail or f"TShark exited with code {result.returncode}"


def check() -> dict:
    deployment = deployment_status()
    problems: list[str] = []
    tshark = resolve_executable("tshark")
    if not tshark:
        problems.append("TShark is missing")

    selected = elect_network(discover_candidates())
    if selected is None:
        problems.append("No eligible active network interface")

    console_status: dict[str, object] | None = None
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/api/v1/live/status", timeout=5) as response:
            console_status = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        problems.append(f"Console unavailable on 127.0.0.1:8765: {exc}")

    service_caps_ok, service_caps_detail = _managed_service_capability_check()
    if not service_caps_ok:
        problems.append(service_caps_detail)

    capture: dict[str, object] = {
        "backend": "tshark",
        "interface": selected.interface if selected else None,
        "service_capabilities_verified": service_caps_ok,
        "service_capabilities_detail": service_caps_detail,
        "verified": False,
    }

    if selected and tshark:
        verified, detail = _tshark_capture_check(selected.interface, tshark)
        capture["verified"] = verified
        capture["detail"] = detail
        if not verified:
            problems.append("TShark capture verification failed: " + detail)

    if isinstance(console_status, dict):
        live = console_status.get("live")
        if isinstance(live, dict):
            runtime_capture = live.get("capture")
            if isinstance(runtime_capture, dict):
                capture["runtime"] = runtime_capture
                state = str(runtime_capture.get("state") or "")
                if state in {"ERROR", "UNAVAILABLE"}:
                    problems.append(
                        "Runtime capture is not healthy: " + str(runtime_capture.get("detail") or state)
                    )

    if not deployment.get("installed"):
        problems.append("No installation manifest; run bash bootstrap.sh")

    return {
        "state": "READY" if not problems else "PARTIAL",
        "profile": "stable-single-source",
        "problems": problems,
        "capture": capture,
        "deployment": deployment,
    }


def main() -> None:
    report = check()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["state"] == "READY" else 2)


if __name__ == "__main__":
    main()
