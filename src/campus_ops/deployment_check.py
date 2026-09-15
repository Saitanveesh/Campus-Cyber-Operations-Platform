"""Read-only post-install checks. Exit 2 for a partial or unhealthy deployment."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from campus_ops.deployment import deployment_status
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.network_discovery import discover_candidates, elect_network

# Linux capability numbers from linux/capability.h.
_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13
_REQUIRED_CAPTURE_MASK = (1 << _CAP_NET_ADMIN) | (1 << _CAP_NET_RAW)


def _capture_pipeline_check(interface: str, dumpcap: str, tshark: str) -> tuple[bool, str]:
    """Exercise the file-capability path used outside the managed service."""
    acquire = None
    decode = None
    try:
        acquire = subprocess.Popen(
            ["runuser", "-u", "campus-ops", "--", dumpcap,
             "-q", "-i", interface, "-a", "duration:1", "-w", "-"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert acquire.stdout is not None
        decode = subprocess.Popen(
            ["runuser", "-u", "campus-ops", "--", tshark, "-n", "-r", "-"],
            stdin=acquire.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        acquire.stdout.close()
        _, decode_stderr = decode.communicate(timeout=8)
        acquire_stderr = acquire.stderr.read() if acquire.stderr is not None else b""
        acquire_code = acquire.wait(timeout=3)
        decode_code = decode.returncode
        if acquire_code == 0 and decode_code == 0:
            return True, "dumpcap+tshark pipeline verified outside service sandbox"
        detail = (
            f"dumpcap={acquire_code}, tshark={decode_code}; "
            f"dumpcap stderr={acquire_stderr.decode(errors='replace')[-350:]}; "
            f"tshark stderr={decode_stderr.decode(errors='replace')[-350:]}"
        )
        return False, detail
    except (OSError, subprocess.TimeoutExpired) as exc:
        for process in (decode, acquire):
            if process is not None and process.poll() is None:
                process.kill()
        return False, str(exc)


def _managed_service_capability_check() -> tuple[bool, str]:
    """Prove the running campus-ops process has capture rights in systemd's sandbox.

    A runuser/dumpcap test can pass while the long-running systemd service still lacks
    CAP_NET_RAW/CAP_NET_ADMIN. That exact split produced a green installer but a red
    Overview capture card on hardened/WSL-style Ubuntu hosts.
    """
    try:
        result = subprocess.run(
            ["systemctl", "show", "campus-ops.service", "--property=MainPID", "--value"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode != 0:
            return False, "systemctl could not read campus-ops.service MainPID"
        pid = int(result.stdout.strip() or "0")
        if pid <= 0:
            return False, "campus-ops.service has no running MainPID"
        status = Path(f"/proc/{pid}/status").read_text()
        values: dict[str, str] = {}
        for line in status.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                values[key] = value.strip()
        effective = int(values.get("CapEff", "0"), 16)
        ambient = int(values.get("CapAmb", "0"), 16)
        effective_ok = effective & _REQUIRED_CAPTURE_MASK == _REQUIRED_CAPTURE_MASK
        ambient_ok = ambient & _REQUIRED_CAPTURE_MASK == _REQUIRED_CAPTURE_MASK
        if effective_ok and ambient_ok:
            return True, f"service MainPID {pid} has CAP_NET_RAW+CAP_NET_ADMIN effective/ambient"
        return False, (
            f"service MainPID {pid} lacks packet-capture capabilities "
            f"(CapEff={values.get('CapEff', '0')}, CapAmb={values.get('CapAmb', '0')})"
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return False, f"service capability check failed: {exc}"


def check() -> dict:
    deployment = deployment_status()
    problems = []
    if not deployment["installed"]:
        problems.append("No installation manifest; run bash bootstrap.sh")
    tools = {name: resolve_executable(name) for name in ("tshark", "dumpcap", "tcpdump")}
    for name in ("tshark", "dumpcap"):
        if not tools[name]:
            problems.append(f"Missing executable: {name}")

    console_status: dict[str, object] | None = None
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/api/v1/system/deployment", timeout=5) as response:
            console = json.load(response)
        if not console.get("installed"):
            problems.append("Console is using a different deployment configuration")
        with urllib.request.urlopen("http://127.0.0.1:8765/api/v1/live/status", timeout=5) as response:
            console_status = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        problems.append(f"Console unavailable or old manual instance on port 8765: {exc}")

    expected = ["zeek", "suricata"]
    if deployment["installation"].get("profile") == "full":
        expected += ["falco", "opencanary"]
    for name in expected:
        status = deployment["sensors"][name]
        if status["state"] != "RUNNING":
            problems.append(f"{name}: {status['state']} {status.get('detail', '')}")
        elif time.time() - (status.get("started_at") or time.time()) < 5:
            problems.append(f"{name}: still starting; rerun health check shortly")

    bound = next((deployment["sensors"][name].get("interface") for name in ("zeek", "suricata")
                  if deployment["sensors"][name].get("interface")), None)
    selected = elect_network(discover_candidates(), requested=bound)
    capture: dict[str, object] = {
        "interface": selected.interface if selected else None,
        "verified": False,
        "backend": "dumpcap+tshark",
    }

    service_caps_ok, service_caps_detail = _managed_service_capability_check()
    capture["service_capabilities_verified"] = service_caps_ok
    capture["service_capabilities_detail"] = service_caps_detail
    if not service_caps_ok:
        problems.append(
            "Managed service lacks packet-capture capabilities. Pull monitor-v1 and run bash bootstrap.sh: "
            + service_caps_detail
        )

    dumpcap = tools["dumpcap"]
    tshark = tools["tshark"]
    if selected and dumpcap and tshark:
        verified, detail = _capture_pipeline_check(selected.interface, dumpcap, tshark)
        capture["verified"] = verified
        capture["detail"] = detail
        if not verified:
            problems.append(
                "Capture pipeline check failed. Run 'bash bootstrap.sh' to repair capture privileges: " + detail
            )
    else:
        problems.append("No eligible network interface or dumpcap/TShark unavailable")

    if isinstance(console_status, dict):
        live = console_status.get("live")
        if isinstance(live, dict):
            runtime_capture = live.get("capture")
            if isinstance(runtime_capture, dict):
                capture["runtime"] = runtime_capture
                if runtime_capture.get("state") == "ERROR":
                    problems.append("Runtime capture worker reports ERROR: " + str(runtime_capture.get("detail") or ""))

    for name, item in deployment["installation"].get("components", {}).items():
        if item["state"] == "FAILED":
            problems.append(f"Installation failed: {name}")
    return {"state": "PARTIAL" if problems else "READY", "problems": problems,
            "capture": capture, "deployment": deployment}


def main() -> None:
    report = check()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["state"] == "READY" else 2)


if __name__ == "__main__":
    main()
