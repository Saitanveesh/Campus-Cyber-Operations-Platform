import importlib.util
import json
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_network_discovery import candidate

from campus_ops.capabilities import capability_status, diagnostics_for
from campus_ops.deployment import deployment_status, enrich_tools
from campus_ops.event_bus import EventBus
from campus_ops.fabric.runtime import OperationsFabric
from campus_ops.sensor_runner import Supervisor
from campus_ops.workers.network_discovery import NetworkDiscoveryWorker, elect_network
from campus_ops.workers.wifi_telemetry import parse_iw_link


def load_configurator():
    path = Path(__file__).resolve().parents[1] / "scripts/configure_ubuntu.py"
    spec = importlib.util.spec_from_file_location("configure_ubuntu", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_unplugged_ethernet_cannot_block_wifi_failover():
    worker = NetworkDiscoveryWorker(EventBus(), confirmations=2)
    eth = candidate("enp0s3", default_route=True, route_metric=1)
    wifi = candidate("wlp2s0", default_route=True, route_metric=600, category="wireless")
    worker.selected = elect_network([eth])
    worker.candidates = [replace(eth, is_up=False), wifi]
    proposed = elect_network(worker.candidates)
    await worker._consider(proposed)
    assert worker.selected is None  # Never keep capturing on the disconnected device.
    await worker._consider(proposed)
    assert worker.selected.interface == "wlp2s0"


async def test_route_loss_rechecks_old_score_before_switching():
    worker = NetworkDiscoveryWorker(EventBus(), confirmations=1)
    eth = candidate("enp0s3", default_route=True, route_metric=1)
    worker.selected = elect_network([eth])
    worker.candidates = [replace(eth, default_route=False, route_metric=None),
                         candidate("wlan0", default_route=True, category="wireless")]
    await worker._consider(elect_network(worker.candidates))
    assert worker.selected.interface == "wlan0"


def test_explicit_interface_supports_unnumbered_tap_and_never_silently_falls_back():
    rows = [candidate("tap-lab", ipv4=(), ipv6=(), prefixes=(), category="tunnel"),
            candidate("eth0", default_route=True)]
    assert elect_network(rows, "tap-lab").interface == "tap-lab"
    assert elect_network(rows, "missing") is None


def test_any_includes_wifi_ethernet_vpn_and_ipv6_but_not_down_links():
    rows = [candidate("eth0"), candidate("wlan0", ipv4=("10.0.0.2",)),
            candidate("wg0", ipv4=(), ipv6=("2001:db8::2",)),
            candidate("usb0", ipv4=("10.0.0.3",), is_up=False)]
    choice = elect_network(rows, "any")
    assert choice.interface == "any"
    assert choice.ipv4 == ("10.0.0.2", "192.0.2.10")
    assert choice.ipv6 == ("2001:db8::2",)
    assert elect_network([replace(row, is_up=False) for row in rows], "any") is None


def test_linux_capabilities_do_not_require_windows_capture_driver():
    state = capability_status({"platform": "Linux", "tools": [{"key": "tshark", "available": True}],
        "workers": {name: {"state": "HEALTHY"} for name in ("capture", "flow-engine", "protocol-engine")}})
    rows = {row["key"]: row for row in state["capabilities"]}
    assert rows["live_packet_visibility"]["state"] == "READY"
    assert "windows_endpoint_visibility" not in rows
    assert "linux_endpoint_visibility" in rows
    assert diagnostics_for("Linux")["network-adapters"][0] == "ip"
    assert "defender-status" not in diagnostics_for("Linux")


def test_wifi_telemetry_keeps_ssid_and_real_signal_units():
    row = parse_iw_link("Connected to aa:bb:cc:dd:ee:ff (on wlp1s0)\n"
                        "\tSSID: Campus Wi Fi\n\tfreq: 5180\n\tsignal: -53 dBm\n"
                        "\ttx bitrate: 866.7 MBit/s VHT-MCS 9\n", "wlp1s0")
    assert row["ssid"] == "Campus Wi Fi"
    assert row["signal"] == "-53 dBm"
    assert row["frequency_mhz"] == "5180"
    assert parse_iw_link("Not connected.", "wlp1s0") == {}


def test_generated_config_preserves_custom_settings_and_wires_only_installed_feeds(tmp_path):
    configure = load_configurator().configure
    installed = tmp_path / "var/lib/campus-ops/install"
    installed.mkdir(parents=True)
    (installed / "zeek.ok").touch()
    (installed / "opencanary.ok").touch()
    configure(tmp_path, "any", {"ftp.enabled": True, "ssh.version": "example"}, {"run-as": {"user": "suricata"}})
    config = tmp_path / "etc/campus-ops"
    generated = (config / "managed-feeds.env").read_text()
    assert "ZEEK_LOG_DIR" in generated
    assert "OPENCANARY_LOG" in generated
    assert "SURICATA_EVE" not in generated
    canary = json.loads((config / "sensors/opencanary.conf").read_text())
    assert canary["http.port"] == 8081 and canary["ssh.port"] == 8022
    assert canary["ftp.enabled"] is False
    assert canary["logger"]["kwargs"]["handlers"]["file"]["maxBytes"] > 0
    custom = "CAMPUS_OPS_SURICATA_EVE=/srv/existing/eve.json\n"
    (config / "campus-ops.env").write_text(custom)
    configure(tmp_path, "eth0", {}, {})
    assert (config / "sensors.env").read_text() == "CAMPUS_OPS_INTERFACE=any\n"
    assert (config / "campus-ops.env").read_text() == custom
    assert json.loads((config / "sensors/opencanary.conf").read_text()) == canary
    configure(tmp_path, "eth0", {}, {}, replace_interface=True)
    assert (config / "sensors.env").read_text() == "CAMPUS_OPS_INTERFACE=eth0\n"


def test_stale_heartbeat_and_kernel_block_are_never_ready(tmp_path):
    root, runtime = tmp_path / "config", tmp_path / "run"
    root.mkdir()
    runtime.mkdir()
    (root / "deployment.json").write_text(json.dumps({"components": {
        "falco": {"state": "BLOCKED", "detail": "No BTF"}, "zeek": {"state": "INSTALLED"}}}))
    (runtime / "zeek.json").write_text(json.dumps({"state": "RUNNING", "checked_at": time.time() - 60}))
    state = deployment_status(root, runtime)
    assert state["sensors"]["zeek"]["state"] == "NOT_RUNNING"
    assert state["sensors"]["falco"]["state"] == "BLOCKED"


def test_tool_hub_separates_process_alive_from_recent_feed(monkeypatch):
    monkeypatch.setattr("campus_ops.deployment.deployment_status", lambda: {
        "installed": True, "sensors": {"zeek": {"state": "RUNNING"}}})
    worker = SimpleNamespace(name="zeek-feed", records=100, errors=0, last_received=time.time() - 600)
    orch = SimpleNamespace(workers=[worker])
    row = {"name": "Zeek", "state": "NOT_INSTALLED", "purpose": "Network sensor"}
    assert enrich_tools([dict(row)], orch)[0]["state"] == "READY_LISTENING"
    worker.last_received = time.time()
    assert enrich_tools([dict(row)], orch)[0]["state"] == "READY_RECEIVING"


def test_supervisor_rebinds_and_stops_on_interface_loss(tmp_path, monkeypatch):
    class Child:
        pid = 123
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout):
            return self.returncode

    children, commands = [], []

    def launch(command, **kwargs):
        commands.append(command)
        child = Child()
        children.append(child)
        return child

    monkeypatch.setattr("campus_ops.sensor_runner.LOG_ROOT", tmp_path / "logs")
    monkeypatch.setattr("campus_ops.sensor_runner.subprocess.Popen", launch)
    supervisor = Supervisor("zeek", tmp_path / "run")
    supervisor.tick("eth0")
    supervisor.tick("wlan0")
    assert children[0].returncode == 0
    assert "wlan0" in commands[-1]
    supervisor.tick(None)
    assert children[-1].returncode == 0
    assert json.loads((tmp_path / "run/zeek.json").read_text())["state"] == "WAITING_INTERFACE"


def test_canary_alive_without_listeners_is_not_ready(tmp_path, monkeypatch):
    child = Mock(pid=123)
    child.poll.return_value = None
    monkeypatch.setattr("campus_ops.sensor_runner.LOG_ROOT", tmp_path / "logs")
    monkeypatch.setattr("campus_ops.sensor_runner.subprocess.Popen", lambda *a, **kw: child)
    reader = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/etc/campus-ops/sensors/opencanary.conf":
            return json.dumps({"http.enabled": True, "http.port": 8081,
                               "ssh.enabled": True, "ssh.port": 8022})
        return reader(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    process = Mock()
    process.net_connections.return_value = []
    monkeypatch.setattr("campus_ops.sensor_runner.psutil.Process", lambda pid: process)
    supervisor = Supervisor("opencanary", tmp_path / "run")
    supervisor.tick(None)
    status = tmp_path / "run/opencanary.json"
    assert json.loads(status.read_text())["state"] == "STARTING"
    process.net_connections.return_value = [
        SimpleNamespace(status="LISTEN", laddr=SimpleNamespace(port=port)) for port in (8081, 8022)]
    supervisor.tick(None)
    assert json.loads(status.read_text())["state"] == "RUNNING"
    process.net_connections.return_value = []
    supervisor.started_at = time.time() - 20
    supervisor.tick(None)
    assert json.loads(status.read_text())["state"] == "FAILED"
    child.terminate.assert_called_once()


async def test_missing_quiet_feed_and_canary_boot_do_not_poison_error_gate(tmp_path, monkeypatch):
    path = tmp_path / "canary.jsonl"
    monkeypatch.setenv("CAMPUS_OPS_OPENCANARY_LOG", str(path))
    orch = SimpleNamespace(bus=EventBus(), session_id="s", agents=SimpleNamespace(list=list))
    fabric = OperationsFabric(orch, tmp_path / "fabric.db")
    await fabric.poll_exports()
    assert fabric.metrics["opencanary"]["state"] == "WAITING_FILE"
    assert fabric.metrics["opencanary"]["errors"] == 0
    path.touch()
    await fabric.poll_exports()
    with path.open("a") as stream:
        stream.write(json.dumps({"logtype": 1001, "logdata": "Canary running"}) + "\n")
    await fabric.poll_exports()
    assert fabric.metrics["opencanary"]["ignored"] == 1
    assert fabric.metrics["opencanary"]["errors"] == 0
    await fabric.stop()


def test_installer_plan_needs_no_root_or_system_changes():
    result = subprocess.run(["bash", "scripts/install_ubuntu.sh", "--plan", "--interface", "any"],
                            capture_output=True, text=True, check=True)
    assert "interface: any" in result.stdout and "OpenCanary" in result.stdout


@pytest.mark.parametrize("name", ["../eth0", "eth0;id", "bad interface"])
def test_installer_rejects_unsafe_interface_names(name):
    result = subprocess.run(["bash", "scripts/install_ubuntu.sh", "--plan", "--interface", name],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 64
