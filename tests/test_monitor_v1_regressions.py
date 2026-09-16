from pathlib import Path

from campus_ops.version import build_info


def test_bootstrap_uses_one_stable_installer_per_supported_linux():
    script = Path("bootstrap.sh").read_text()
    assert 'ubuntu) installer="scripts/install_ubuntu_stable.sh"' in script
    assert 'kali) installer="scripts/install_kali.sh"' in script
    assert "stable-single-source" in script
    assert "--force-reinstall" not in script
    assert "wait_for_console.sh" in script
    assert script.index("wait_for_console.sh") < script.index("campus_ops.deployment_check")


def test_stable_installers_use_tshark_only_and_purge_old_sensor_state():
    for name in ("scripts/install_ubuntu_stable.sh", "scripts/install_kali.sh"):
        script = Path(name).read_text()
        assert "tshark" in script
        assert "setcap cap_net_raw,cap_net_admin=eip" in script
        assert "legacy-sensors" in script
        assert "campus-ops-sensor@zeek.service" in script
        assert "systemctl disable --now" in script
        assert "/etc/campus-ops/managed-feeds.env" in script
        assert "rm -rf /opt/campus-ops/venv" in script
        assert "suricata-feed" not in script
        assert "apt-get install -y suricata" not in script
        assert "apt-get install -y zeek" not in script


def test_main_mounts_only_stable_passive_stack():
    main = Path("src/campus_ops/main.py").read_text()
    assert "create_stable_app" in main
    assert "StableOrchestrator" in main
    assert "install_stable_ui" in main
    assert "install_path_analysis" in main
    assert "install_watchdog_api" in main
    for forbidden in (
        "create_app(",
        "install_operational_core",
        "install_runtime_extensions",
        "install_enterprise_layer",
        "install_enterprise_soc",
        "install_zeek_integration",
        "install_autonomy_engine",
        "install_red_panel",
    ):
        assert forbidden not in main


def test_stable_orchestrator_is_standalone_and_single_source():
    stable = Path("src/campus_ops/stable_orchestrator.py").read_text()
    assert "class StableOrchestrator:" in stable
    assert "class StableOrchestrator(Orchestrator)" not in stable
    assert "from campus_ops.orchestrator import" not in stable
    assert "self.capture," in stable
    assert "self.topology_engine," in stable
    assert '"authoritative_packet_source": "tshark"' in stable
    assert '"topology_source": "same-tshark-packet-stream"' in stable
    assert '"capture_state_policy": "process-health-only"' in stable
    assert '"session_control_plane": "network-events-only"' in stable
    assert "predicate=self._session_control_event" in stable
    for forbidden in (
        "CaptureHealthWorker",
        "SuricataFeedWorker",
        "ForensicCaptureWorker",
        "SyslogReceiverWorker",
        "FlowTelemetryReceiverWorker",
        "SnmpPollerWorker",
        "WindowsSecurityTelemetryWorker",
        "WifiTelemetryWorker",
        "VoiceAlertWorker",
        "ResponseEngine",
        "AgentRegistry",
    ):
        assert forbidden not in stable


def test_stable_api_excludes_control_and_secondary_sensor_routes():
    source = Path("src/campus_ops/stable_api.py").read_text()
    assert "/api/v1/live/status" in source
    assert "/api/v1/live/ws" in source
    assert "/api/v1/system/health" in source
    for forbidden in (
        "/api/v1/control",
        "/api/v1/agents",
        "/api/v1/response",
        "/api/v1/sensors",
        "/api/v1/voice",
        "/isolate",
        "/quarantine",
        "/remote",
    ):
        assert forbidden not in source


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


def test_console_is_stable_only_without_legacy_panels():
    html = Path("src/campus_ops/ui/index.html").read_text()
    stable_ui = Path("src/campus_ops/stable_ui.py").read_text()
    operator_ui = Path("src/campus_ops/stable_operator_ui.py").read_text()
    operator_routes = Path("src/campus_ops/stable_operator.py").read_text()

    for label in ("Overview", "Network", "Topology", "Assets", "Traffic", "Security", "System"):
        assert label in html
    for forbidden in ("Endpoint Control", "Cyberbit", "Voice Console", "Response Console", "Admin Panel"):
        assert forbidden not in html

    assert "TOPOLOGY_EXTENSION" in stable_ui
    assert "PATHSPACE_EXTENSION" in stable_ui
    assert "STABLE_OPERATOR_EXTENSION" in stable_ui
    assert "Stable 0.5.0" in stable_ui
    assert "Investigation Workspace" in operator_ui
    assert "Forensics Workbench" in operator_ui
    assert "PASSIVE_ONLY" in operator_routes
    assert "campus_ops.admin" not in operator_routes
    for forbidden in ("/probe", "/snapshot", "/isolate", "/restore", "/connect", "remote/enroll"):
        assert forbidden not in operator_routes


def test_passive_investigation_contains_no_command_execution():
    source = Path("src/campus_ops/investigation.py").read_text()
    for forbidden in (
        "subprocess",
        "deep_probe",
        "resolve_executable",
        "nmap",
        "tracert",
        "powershell",
        "Get-Net",
    ):
        assert forbidden not in source
    assert "PASSIVE_ONLY" in source


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


def test_managed_console_inherits_linux_capture_capabilities():
    unit = Path("deploy/campus-ops.service").read_text()
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "SupplementaryGroups=wireshark" in unit
    check = Path("src/campus_ops/deployment_check.py").read_text()
    assert "_managed_service_capability_check" in check
    assert "_tshark_capture_check" in check
    assert '"backend": "tshark"' in check
    assert "campus_ops.deployment" not in check


def test_dependency_constraints_do_not_reintroduce_invalid_websockets_pin():
    constraints = Path("requirements.lock").read_text()
    assert "websockets==17.1" not in constraints


def test_package_version_is_stable_0_5_0_and_has_no_agent_entry_point():
    project = Path("pyproject.toml").read_text()
    assert 'version = "0.5.0"' in project
    assert "campus-ops-agent" not in project
