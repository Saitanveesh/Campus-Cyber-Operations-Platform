"""Render root-owned configuration without overwriting existing operator settings."""
from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path

import psutil
import yaml


def write_new(path: Path, text: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o640)


def configure(root: Path, interface: str, canary_defaults: dict, suricata_defaults: dict,
              replace_interface: bool = False) -> None:
    config = root / "etc/campus-ops"
    sensors = config / "sensors"
    write_new(config / "sensors.env", f"CAMPUS_OPS_INTERFACE={interface}\n")
    if replace_interface:
        (config / "sensors.env").write_text(f"CAMPUS_OPS_INTERFACE={interface}\n")
    write_new(config / "campus-ops.env", "CAMPUS_OPS_DATA_DIR=/var/lib/campus-ops\n"
              "CAMPUS_OPS_NO_BROWSER=1\nCAMPUS_OPS_AUTONOMY_MODE=observe\n"
              "CAMPUS_OPS_SYSLOG_BIND=127.0.0.1\nCAMPUS_OPS_SYSLOG_PORT=5514\n")
    # A distinct generated file wires deployed feeds without rewriting user configuration.
    feeds = {}
    for sensor, key, path in (
        ("zeek", "CAMPUS_OPS_ZEEK_LOG_DIR", "/var/log/campus-ops/zeek"),
        ("suricata", "CAMPUS_OPS_SURICATA_EVE", "/var/log/campus-ops/suricata/eve.json"),
    ):
        if (root / f"var/lib/campus-ops/install/{sensor}.ok").exists():
            feeds[key] = path
    # Migrate only the two defaults from the previous installer; retain custom feeds.
    operator = config / "campus-ops.env"
    lines = operator.read_text().splitlines()
    old_defaults = {"CAMPUS_OPS_ZEEK_LOG_DIR=/opt/zeek/logs/current": "CAMPUS_OPS_ZEEK_LOG_DIR",
                    "CAMPUS_OPS_SURICATA_EVE=/var/log/suricata/eve.json": "CAMPUS_OPS_SURICATA_EVE"}
    lines = [line for line in lines if old_defaults.get(line) not in feeds]
    operator.write_text("\n".join(lines) + "\n")
    for name in ("falco", "opencanary"):
        if (root / f"var/lib/campus-ops/install/{name}.ok").exists():
            feeds[f"CAMPUS_OPS_{name.upper()}_LOG"] = f"/var/log/campus-ops/{name}/events.jsonl"
    write_new(config / "managed-feeds.env", "")
    (config / "managed-feeds.env").write_text("".join(f"{k}={v}\n" for k, v in feeds.items()))
    write_new(sensors / "local.zeek", "@load policy/tuning/json-logs\n"
              "redef Log::default_rotation_interval = 0secs;\n"
              "redef Log::default_logdir = \"/var/log/campus-ops/zeek\";\n")
    suricata_defaults.pop("run-as", None)
    suricata_defaults["default-log-dir"] = "/var/log/campus-ops/suricata"
    suricata_defaults["unix-command"] = {"enabled": False}
    suricata_defaults["outputs"] = [{"eve-log": {
        "enabled": True, "filetype": "regular", "filename": "eve.json",
        "types": ["alert", "dns", "http", "tls", "flow", "stats"],
    }}]
    write_new(sensors / "suricata.yaml", "%YAML 1.1\n---\n" + yaml.safe_dump(suricata_defaults))
    canary = dict(canary_defaults)
    for key in canary:
        if key.endswith(".enabled"):
            canary[key] = False
    canary.update({"device.node_id": socket.gethostname(), "device.listen_addr": "0.0.0.0",
                   "http.enabled": True, "http.port": 8081,
                   "ssh.enabled": True, "ssh.port": 8022})
    canary["logger"] = {"class": "PyLogger", "kwargs": {"formatters": {
        "plain": {"format": "%(message)s"}}, "handlers": {"file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/campus-ops/opencanary/events.jsonl",
            "maxBytes": 16777216, "backupCount": 5,
            "formatter": "plain"}}}}
    write_new(sensors / "opencanary.conf", json.dumps(canary, indent=2) + "\n")


def stop_previous_console() -> None:
    """Migrate only this user's verified manual campus_ops listener to systemd."""
    owner = int(os.environ.get("SUDO_UID", "0"))
    for connection in psutil.net_connections(kind="tcp"):
        if connection.status != "LISTEN" or connection.laddr.port != 8765 or not connection.pid:
            continue
        try:
            process = psutil.Process(connection.pid)
            args = process.cmdline()
            is_console = any(args[i:i + 2] == ["-m", "campus_ops"] for i in range(len(args) - 1))
            if process.uids().real not in {0, owner} or not is_console:
                raise RuntimeError("Port 8765 is already in use. Stop its owner before starting campus-ops.service.")
            process.terminate()
            # Allow normal cleanup. Never kill an unrelated listener or discard its data.
            process.wait(timeout=30)
        except psutil.NoSuchProcess:
            pass
    time.sleep(0.2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--replace-interface", action="store_true")
    parser.add_argument("--stop-previous-console", action="store_true")
    parser.add_argument("--canary-defaults", type=Path)
    parser.add_argument("--suricata-defaults", type=Path, default=Path("/etc/suricata/suricata.yaml"))
    args = parser.parse_args()
    if args.stop_previous_console:
        stop_previous_console()
        return
    if any(c.isspace() for c in args.interface) or "=" in args.interface or "\x00" in args.interface:
        parser.error("invalid interface name")
    canary = json.loads(args.canary_defaults.read_text()) if args.canary_defaults else {}
    suricata = yaml.safe_load(args.suricata_defaults.read_text()) if args.suricata_defaults.exists() else {}
    configure(args.root, args.interface, canary, suricata, args.replace_interface)


if __name__ == "__main__":
    main()
