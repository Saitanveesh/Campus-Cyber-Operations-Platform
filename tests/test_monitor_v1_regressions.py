from pathlib import Path

from campus_ops.version import build_info


def test_bootstrap_uses_stable_single_source_installer():
    script = Path("bootstrap.sh").read_text()
    assert 'ubuntu) installer="scripts/install_ubuntu_stable.sh"' in script
    assert "stable-single-source" in script
    assert "--force-reinstall --no-deps" in script
    assert "wait_for_console.sh" in script
    assert script.index("wait_for_console.sh") < script.index("campus_ops.deployment_check")


def test_stable_installer_uses_tshark_as_only_live_packet_engine():
    script = Path("scripts/install_ubuntu_stable.sh").read_text()
    assert "apt-get install -y tshark" in script
    assert "setcap cap_net_raw,cap_net_admin=eip" in script
    assert "external-sensors" in script
    assert "campus-ops-sensor@zeek.service" in script
    assert "campus-ops-sensor@suricata.service" in script
    assert "systemctl disable --now" in script
    assert "apt-get install -y suricata" not in script
    assert "apt-get install -y zeek" not in script


def test_runtime_does_not_mount_experimental_console_layers():
    main = Path("src/campus_ops/main.py").read_text()
    assert "StableOrchestrator" in main
    assert "install_stable_ui" in main
    for forbidden in (
        "install_runtime_extensions",
        "install_enterprise_layer",
        "install_enterprise_soc",
        "install_zeek_integration",
        "install_autonomy_engine",
        "install_red_panel",
    ):
        assert forbidden not in main


def test_stable_orchestrator_does_not_start_parallel_or_heuristic_capture_feeds():
    stable = Path("src/campus_ops/stable_orchestrator.py").read_text()
    assert "self.capture," in stable
    assert 'result["authoritative_packet_source"] = "tshark"' in stable
    assert 'result["capture_state_policy"] = "process-health-only"' in stable
    for forbidden in (
        "self.capture_health,",
        "self.suricata,",
        "self.forensic_capture,",
        "self.syslog,",
        "self.flow_receiver,",
        "self.snmp,",
        "self.windows_security,",
        "self.wifi,",
        "self.voice,",
        "self.watchdog,",
    ):
        assert forbidden not in stable


def test_capture_worker_has_one_managed_process_and_quiet_link_stays_active():
    capture = Path("src/campus_ops/workers/capture.py").read_text()
    assert 'backend="tshark"' in capture
    assert '"-i",' in capture
    assert "tcpdump" not in capture
    assert "_linux_backends" not in capture
    assert "_spawn_linux_pipeline" not in capture
    assert "REBINDING" not in capture
    assert "LINK_UP_IDLE" not in capture
    assert 'traffic_activity="QUIET"' in capture
    assert "capture remains ACTIVE" in capture


def test_assets_require_repeated_local_source_frame_evidence():
    source = Path("src/campus_ops/workers/asset_engine.py").read_text()
    assert "_LOCAL_ASSET_ROLES" in source
    assert "_valid_unicast_mac" in source
    assert "if count < 2" in source
    assert "CONFIRMED_LOCAL_SOURCE_FRAMES" in source
    assert '"confidence": "HIGH"' in source


def test_flows_are_packet_observed_and_tied_to_local_scope():
    source = Path("src/campus_ops/workers/flow_engine.py").read_text()
    assert '!= "PACKET"' in source
    assert "_LOCAL_ROLES" in source
    assert "_REJECT_ROLES" in source
    assert "OBSERVED_PACKET_CONVERSATION" in source
    assert "FLOW_TELEMETRY" not in source


def test_stable_ui_exposes_only_core_consoles():
    source = Path("src/campus_ops/stable_ui.py").read_text()
    assert "'overview','network','assets','traffic','security','system'" in source
    for hidden in ("topology", "endpoints", "response", "evidence", "history"):
        assert f'data-view=\\"{hidden}\\"' in source
    assert "Stable 0.4" in source


def test_bootstrap_records_exact_deployed_branch_and_commit():
    script = Path("bootstrap.sh").read_text()
    assert 'build_commit="$(git rev-parse HEAD)"' in script
    assert 'build_branch="$(git branch --show-current)"' in script
    assert "/etc/campus-ops/build.json" in script
    assert '"source_dirty": $build_dirty' in script
    assert '"runtime_profile": "stable-single-source"' in script


def test_build_info_reads_provenance_without_trusting_missing_fields(tmp_path: Path):
    path = tmp_path / "build.json"
    path.write_text(
        '{"branch":"monitor-v1","commit":"0123456789abcdef","installed_at":"2026-09-15T00:00:00Z","source_dirty":false}'
    )
    info = build_info(path)
    assert info["branch"] == "monitor-v1"
    assert info["commit"] == "0123456789abcdef"
    assert info["commit_short"] == "0123456789ab"
    assert info["source_dirty"] is False


def test_repository_excludes_credentials_and_evidence():
    ignore = Path(".gitignore").read_text()
    for pattern in ("*.pcap", "*.pcapng", "*.evtx", "*.pem", "*.key", "*.p12", "secrets/"):
        assert pattern in ignore


def test_readiness_gate_hides_normal_connection_refused_race_and_reports_real_failure():
    wait = Path("scripts/wait_for_console.sh").read_text()
    assert "curl --silent --fail --max-time 2" in wait
    assert ">/dev/null 2>&1" in wait
    assert "systemctl is-failed --quiet" in wait
    assert "journalctl -u" in wait
    assert "timeout_seconds=60" in wait


def test_managed_console_inherits_linux_capture_capabilities():
    unit = Path("deploy/campus-ops.service").read_text()
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "SupplementaryGroups=wireshark" in unit

    check = Path("src/campus_ops/deployment_check.py").read_text()
    assert "_managed_service_capability_check" in check
    assert "_tshark_capture_check" in check
    assert '"backend": "tshark"' in check


def test_dependency_constraints_do_not_reintroduce_invalid_websockets_pin():
    constraints = Path("requirements.lock").read_text()
    assert "websockets==17.1" not in constraints


def test_package_version_is_stable_0_4_1():
    project = Path("pyproject.toml").read_text()
    assert 'version = "0.4.1"' in project
