"""Read-only post-install checks. Exit 2 for a partial or unhealthy deployment."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

from campus_ops.deployment import deployment_status
from campus_ops.tooling.registry import resolve_executable
from campus_ops.workers.network_discovery import discover_candidates, elect_network


def _capture_pipeline_check(interface: str, dumpcap: str, tshark: str) -> tuple[bool, str]:
    """Exercise the same privilege boundary used by the Linux runtime.

    dumpcap opens the interface as campus-ops and writes pcap to stdout. TShark is
    deliberately only a decoder reading stdin; it never requests capture privilege.
    """
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
        # The decoder owns its duplicate of the pipe now. Closing the parent copy is
        # required so EOF propagates when dumpcap exits.
        acquire.stdout.close()
        _, decode_stderr = decode.communicate(timeout=8)
        acquire_stderr = acquire.stderr.read() if acquire.stderr is not None else b""
        acquire_code = acquire.wait(timeout=3)
        decode_code = decode.returncode
        if acquire_code == 0 and decode_code == 0:
            return True, "dumpcap+tshark pipeline verified"
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


def check() -> dict:
    deployment = deployment_status()
    problems = []
    if not deployment["installed"]:
        problems.append("No installation manifest; run bash bootstrap.sh")
    tools = {name: resolve_executable(name) for name in ("tshark", "dumpcap", "tcpdump")}
    for name in ("tshark", "dumpcap"):
        if not tools[name]:
            problems.append(f"Missing executable: {name}")
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/api/v1/system/deployment", timeout=5) as response:
            console = json.load(response)
        if not console.get("installed"):
            problems.append("Console is using a different deployment configuration")
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
    capture = {
        "interface": selected.interface if selected else None,
        "verified": False,
        "backend": "dumpcap+tshark",
    }
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
