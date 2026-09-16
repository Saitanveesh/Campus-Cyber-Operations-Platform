from pathlib import Path


def test_ubuntu_installer_is_single_source_and_recreates_environment():
    source = Path("scripts/install_ubuntu_stable.sh").read_text()
    assert "Ubuntu 22.04 or newer is required" in source
    assert "apt-get install -y tshark" in source
    assert "rm -rf /opt/campus-ops/venv" in source
    assert "--no-cache-dir" in source
    assert "pip check" in source
    assert "runuser -u campus-ops -- tshark -D" in source
    assert "setcap cap_net_raw,cap_net_admin=eip" in source
    assert "CAMPUS_OPS_INTERFACE=$interface" in source
    assert "wait_for_console.sh" in source
    assert "campus_ops.deployment_check" in source


def test_ubuntu_installer_purges_previous_multi_sensor_state():
    source = Path("scripts/install_ubuntu_stable.sh").read_text()
    for legacy in (
        "/etc/campus-ops/managed-feeds.env",
        "/etc/campus-ops/agents.env",
        "/etc/campus-ops/response.env",
        "/etc/campus-ops/tools.env",
        "/etc/campus-ops/voice.env",
        "/var/lib/campus-ops/zeek",
        "/var/lib/campus-ops/suricata",
        "/var/lib/campus-ops/opencanary",
        "/var/lib/campus-ops/falco",
        "/etc/systemd/system/campus-ops-sensor@.service",
        "/etc/systemd/system/campus-ops-falco.service",
    ):
        assert legacy in source
    assert "legacy-sensors" in source
    assert "REMOVED" in source


def test_kali_installer_uses_same_stable_runtime_contract():
    source = Path("scripts/install_kali.sh").read_text()
    assert "stable single-source monitor" in source
    assert "tshark" in source
    assert "rm -rf /opt/campus-ops/venv" in source
    assert "managed-feeds.env" in source
    assert "campus-ops-sensor@zeek.service" in source
    assert "campus_ops.deployment_check" in source
    for forbidden in ("suricata-feed", "zeek-feed", "OpenCanary", "Falco installation"):
        assert forbidden not in source


def test_bootstrap_has_no_legacy_or_duplicate_install_path():
    source = Path("bootstrap.sh").read_text()
    assert 'ubuntu) installer="scripts/install_ubuntu_stable.sh"' in source
    assert 'kali) installer="scripts/install_kali.sh"' in source
    assert "stable_mode=false" not in source
    assert "installer_status" not in source
    assert "--force-reinstall" not in source
    assert "pip install" not in source
    assert "runtime_profile\": \"stable-single-source" in source


def test_service_runs_only_main_mon_process_with_capture_capabilities():
    source = Path("deploy/campus-ops.service").read_text()
    assert "ExecStart=/opt/campus-ops/venv/bin/campus-ops" in source
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in source
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in source
    assert "SupplementaryGroups=wireshark" in source
    assert "Restart=on-failure" in source
