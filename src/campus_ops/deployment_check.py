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
    """Fallback capture probe used only when the managed runtime is not active."""
    try:
        result = subprocess.run(
            [
                "runuser",
                "-u",
                "campus-ops",
                "--",
                tshark,
                "-n",
                "-i",
                interface,
                "-a",
                "duration:1",
                "-T",
                "fields",
                "-e",
                "frame.len",
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


def _tshark_process_check(pid: object, interface: str | None) -> tuple[bool, str]:
    try:
        numeric_pid = int(pid or 0)
    except (TypeError, ValueError):
        return False, "runtime capture PID is invalid"
    if numeric_pid <= 0:
        return False, "runtime capture PID is missing"
    try:
        raw = Path(f"/proc/{numeric_pid}/cmdline").read_bytes()
    except OSError as exc:
        return False, f"runtime capture PID {numeric_pid} is not alive: {exc}"
    args = [part.decode(errors="replace") for part in raw.split(b"\0") if part]
    if not args or Path(args[0]).name not in {"tshark", "tshark.exe"}:
        return False, f"runtime capture PID {numeric_pid} is not TShark"
    if interface and "-i" in args:
        index = args.index("-i")
        if index + 1 >= len(args):
            return False, "runtime TShark command has an incomplete -i argument"
        capture_device = args[index + 1]
        if capture_device != interface:
            return False, (
                f"runtime TShark PID {numeric_pid} is bound to {capture_device}, "
                f"expected {interface}"
            )
    return True, f"runtime TShark PID {numeric_pid} is alive"


def _console_status() -> tuple[dict[str, object] | None, str | None]:
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:8765/api/v1/live/status", timeout=5
        ) as response:
            value = json.load(response)
        if isinstance(value, dict):
            return value, None
        return None, "Console returned a non-object live status"
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return None, f"Console unavailable on 127.0.0.1:8765: {exc}"


def check() -> dict:
    deployment = deployment_status()
    problems: list[str] = []
    tshark = resolve_executable("tshark")
    if not tshark:
        problems.append("TShark is missing")

    console_status, console_error = _console_status()
    if console_error:
        problems.append(console_error)

    runtime_interface: str | None = None
    runtime_capture: dict[str, object] | None = None
    runtime_process_ok = False
    runtime_process_detail = "runtime capture process not checked"

    if isinstance(console_status, dict):
        runtime_profile = str(console_status.get("runtime_profile") or "")
        if runtime_profile != "stable-single-source":
            problems.append(f"Unexpected runtime profile: {runtime_profile or 'missing'}")

        session_id = console_status.get("session_id")
        if not session_id:
            problems.append("Runtime has no active monitoring session")

        network = console_status.get("network")
        if isinstance(network, dict):
            runtime_interface = str(network.get("interface") or "") or None
        if not runtime_interface:
            problems.append("Runtime has no selected monitoring interface")

        workers = console_status.get("workers")
        if isinstance(workers, dict):
            for worker_name in ("network-discovery", "capture"):
                raw = workers.get(worker_name)
                state = (
                    str(raw.get("state") or "UNKNOWN").upper()
                    if isinstance(raw, dict)
                    else "MISSING"
                )
                if state != "HEALTHY":
                    problems.append(f"Runtime worker {worker_name} is {state}, expected HEALTHY")

        live = console_status.get("live")
        if isinstance(live, dict):
            raw_capture = live.get("capture")
            if isinstance(raw_capture, dict):
                runtime_capture = raw_capture
                state = str(runtime_capture.get("state") or "UNKNOWN").upper()
                backend = str(runtime_capture.get("backend") or "")
                capture_interface = str(runtime_capture.get("interface") or "") or None
                process_pid = runtime_capture.get("process_pid")

                if state != "ACTIVE":
                    problems.append(
                        "Runtime capture is not ACTIVE: "
                        + str(runtime_capture.get("detail") or state)
                    )
                if backend != "tshark":
                    problems.append(
                        f"Runtime capture backend is {backend or 'missing'}, expected tshark"
                    )
                if not capture_interface:
                    problems.append("Runtime capture has no bound interface")
                if (
                    runtime_interface
                    and capture_interface
                    and runtime_interface != capture_interface
                ):
                    problems.append(
                        "Runtime network/capture interface mismatch: "
                        f"network={runtime_interface} capture={capture_interface}"
                    )
                runtime_process_ok, runtime_process_detail = _tshark_process_check(
                    process_pid, capture_interface
                )
                if not runtime_process_ok:
                    problems.append(runtime_process_detail)
            else:
                problems.append("Runtime capture status is missing")
        else:
            problems.append("Runtime live status is missing")

    try:
        selected = elect_network(discover_candidates())
    except (OSError, ValueError) as exc:
        selected = None
        if runtime_interface is None:
            problems.append(f"Network discovery check failed: {exc}")

    if selected is None and runtime_interface is None:
        problems.append("No eligible active network interface")

    service_caps_ok, service_caps_detail = _managed_service_capability_check()
    if not service_caps_ok:
        problems.append(service_caps_detail)

    verification_interface = runtime_interface or (selected.interface if selected else None)
    capture: dict[str, object] = {
        "backend": "tshark",
        "interface": verification_interface,
        "service_capabilities_verified": service_caps_ok,
        "service_capabilities_detail": service_caps_detail,
        "runtime_process_verified": runtime_process_ok,
        "runtime_process_detail": runtime_process_detail,
        "verified": False,
    }
    if runtime_capture is not None:
        capture["runtime"] = runtime_capture

    if runtime_process_ok and runtime_capture is not None:
        state = str(runtime_capture.get("state") or "").upper()
        backend = str(runtime_capture.get("backend") or "")
        capture["verified"] = state == "ACTIVE" and backend == "tshark"
        capture["detail"] = runtime_process_detail
    elif verification_interface and tshark:
        # The healthy path above validates the real managed TShark process and avoids
        # opening a second capture handle. This fallback is only diagnostic when MON is
        # not yet active.
        verified, detail = _tshark_capture_check(verification_interface, tshark)
        capture["verified"] = verified
        capture["detail"] = detail
        if not verified:
            problems.append("TShark capture verification failed: " + detail)

    if not capture["verified"]:
        problems.append("Managed TShark runtime is not verified")

    if not deployment.get("installed"):
        problems.append("No installation manifest; run bash bootstrap.sh")

    # Preserve order while avoiding duplicate root-cause lines.
    problems = list(dict.fromkeys(problems))
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
