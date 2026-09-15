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


def check() -> dict:
    deployment = deployment_status()
    problems = []
    if not deployment["installed"]:
        problems.append("No installation manifest; run sudo bash scripts/install_ubuntu.sh")
    for name in ("tshark", "dumpcap"):
        if not resolve_executable(name):
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
    selected = elect_network(discover_candidates())
    capture = {"interface": selected.interface if selected else None, "verified": False}
    dumpcap = resolve_executable("dumpcap")
    if selected and dumpcap:
        # Verify capture permissions as the actual service account, without traffic injection.
        try:
            result = subprocess.run(["runuser", "-u", "campus-ops", "--", dumpcap,
                                     "-i", selected.interface, "-a", "duration:1", "-w", "/dev/null"],
                                    capture_output=True, text=True, timeout=8, check=False)
            capture["verified"] = result.returncode == 0
            if result.returncode:
                problems.append("Capture permission/device check failed: " + result.stderr[-500:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            problems.append(f"Capture check unavailable (run health check with sudo): {exc}")
    else:
        problems.append("No eligible network interface or dumpcap unavailable")
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
