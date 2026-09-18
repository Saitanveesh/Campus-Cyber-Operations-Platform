from pathlib import Path


def test_windows_bootstrap_is_native_and_single_source():
    script = Path("bootstrap.ps1").read_text()
    assert "native Windows" in script or "Windows-only" in script
    assert "WiresharkFoundation.Wireshark" in script
    assert "Npcap" in script
    assert "tshark" in script.lower()
    assert "MONWindows" in script
    assert "windows-native-single-source" in script
    assert "current-session-packet-evidence-only" in script
    assert "bootstrap.sh" not in script


def test_main_uses_windows_orchestrator_only():
    source = Path("src/campus_ops/main.py").read_text()
    assert "WindowsOrchestrator" in source
    assert "create_stable_app" in source
    assert "install_path_analysis" in source
    assert "install_watchdog_api" in source
    assert "install_history_api" in source
    assert "install_sensor_identity_api" in source
    assert "StableOrchestrator" not in source


def test_windows_orchestrator_owns_one_capture_source():
    source = Path("src/campus_ops/windows_orchestrator.py").read_text()
    assert "class WindowsOrchestrator:" in source
    assert "WindowsNetworkDiscoveryWorker" in source
    assert "WindowsCaptureWorker" in source
    assert '"authoritative_packet_source": "tshark"' in source
    assert '"capture_stack": "tshark+npcap"' in source
    assert '"ip_truth_policy": "current-session-packet-evidence-only"' in source
    assert "EvidenceStoreWorker" in source
    for forbidden in (
        "Suricata",
        "Zeek",
        "tcpdump",
        "FlowTelemetryReceiver",
        "SyslogReceiver",
        "ResponseEngine",
        "AgentRegistry",
    ):
        assert forbidden not in source


def test_windows_capture_maps_alias_to_npcap_guid():
    source = Path("src/campus_ops/workers/windows_capture.py").read_text()
    assert "Get-NetAdapter" in source
    assert "InterfaceGuid" in source
    assert "NPF_{GUID}" in source
    assert "class WindowsCaptureWorker" in source


def test_capture_worker_remains_one_tshark_process_and_quiet_is_active():
    source = Path("src/campus_ops/workers/capture.py").read_text()
    assert 'backend="tshark"' in source
    assert "tcpdump" not in source
    assert "_spawn_linux_pipeline" not in source
    assert "LINK_UP_IDLE" not in source
    assert 'traffic_activity="QUIET"' in source


def test_assets_require_real_repeated_packet_source_evidence():
    source = Path("src/campus_ops/workers/asset_engine.py").read_text()
    assert "_valid_unicast_mac" in source
    assert "if count < 2" in source
    assert "CONFIRMED_LOCAL_SOURCE_FRAMES" in source
    assert '"confidence": "HIGH"' in source


def test_flows_and_topology_are_packet_observed_only():
    flows = Path("src/campus_ops/workers/flow_engine.py").read_text()
    topology = Path("src/campus_ops/workers/topology_engine.py").read_text()
    assert '!= "PACKET"' in flows
    assert "OBSERVED_PACKET_CONVERSATION" in flows
    assert "FLOW_TELEMETRY" not in flows
    assert '!= "PACKET"' in topology
    assert "TSHARK_PACKET_OBSERVED" in topology
    assert "FLOW_TELEMETRY" not in topology


def test_investigation_refuses_unseen_ips():
    routes = Path("src/campus_ops/stable_operator.py").read_text()
    investigation = Path("src/campus_ops/investigation.py").read_text()
    assert "current TShark capture" in routes
    assert "will not fabricate an investigation" in routes
    assert "NOT_OBSERVED" in investigation
    assert "NO_SECURITY_VERDICT_WITHOUT_EVIDENCE" in investigation
    for forbidden in ("nmap", "tracert", "subprocess", "deep_probe"):
        assert forbidden not in investigation


def test_console_has_no_admin_or_forensics_workspace():
    ui = Path("src/campus_ops/stable_ui.py").read_text()
    operator = Path("src/campus_ops/stable_operator_ui.py").read_text()
    assert "There is no Admin panel" in ui
    assert "Investigation" in operator
    assert "Watchdog" in operator
    assert "Forensics Workbench" not in operator
    assert "Admin Panel" not in operator


def test_system_diagnostics_are_windows_specific():
    source = Path("src/campus_ops/watchdog_api.py").read_text()
    assert "Get-NetAdapter" in source or "Windows" in source
    assert "Npcap" in source or "npcap" in source
    assert "systemctl" not in source
    assert "journalctl" not in source


def test_metadata_history_is_bounded_and_payload_free():
    source = Path("src/campus_ops/workers/evidence_store.py").read_text()
    assert "RETENTION_DAYS = 7" in source
    assert "MAX_ROWS" in source
    assert "metadata" in source.lower()
    assert "Raw packet payloads" in source
    assert "packet_feed" not in source


def test_windows_service_is_single_instance_and_auto_recovers():
    source = Path("scripts/install_windows_service.ps1").read_text()
    assert "MONWindows" in source
    assert "delayed-auto" in source
    assert "restart/5000/restart/15000/restart/30000" in source
    assert "CAMPUS_OPS_INTERFACE=auto" in source
    assert "CampusCyberOperationsPlatform" in source


def test_windows_diagnostics_script_exists():
    source = Path("scripts/diagnose_windows.ps1").read_text()
    for required in (
        "Get-NetAdapter",
        "Get-NetIPConfiguration",
        "Get-NetRoute",
        "Get-NetNeighbor",
        "tshark",
        "MONWindows",
    ):
        assert required in source


def test_windows_only_repository_does_not_ship_linux_installers():
    for path in (
        "bootstrap.sh",
        "scripts/install_kali.sh",
        "scripts/install_ubuntu_stable.sh",
        "scripts/diagnose_runtime.sh",
        "scripts/wait_for_console.sh",
        "deploy/campus-ops.service",
    ):
        assert not Path(path).exists()


def test_dependency_constraints_do_not_reintroduce_invalid_websockets_pin():
    constraints = Path("requirements.lock").read_text()
    assert "websockets==17.1" not in constraints


def test_package_is_windows_release_and_has_no_agent_entry_point():
    project = Path("pyproject.toml").read_text()
    assert 'version = "1.0.0"' in project
    assert "campus-ops-agent" not in project


def test_console_does_not_flap_offline_on_one_transport_miss():
    source = Path("src/campus_ops/ui/index.html").read_text()
    assert "TRANSPORT_GRACE_MS=12000" in source
    assert "last known state retained" in source
    assert "markTransportFailure()" in source
    assert "catch(e){markTransportFailure()}" in source


def test_unmeasured_interface_rates_are_not_rendered_as_zero():
    ui = Path("src/campus_ops/ui/index.html").read_text()
    telemetry = Path("src/campus_ops/workers/telemetry.py").read_text()
    assert "telemetry_rate_valid===true" in ui
    assert "'— / —'" in ui
    assert '"telemetry_rate_valid": rate_valid' in telemetry
    assert '"rx_bps": None' in telemetry
    assert "if session_id and rate_valid:" in telemetry


def test_windows_route_aliases_are_case_normalized():
    source = Path("src/campus_ops/workers/windows_network.py").read_text()
    assert "key = name.casefold()" in source
    assert "routes.get(name.casefold()" in source
