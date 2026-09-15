from pathlib import Path

import pytest

from campus_ops.admin_layout_ui import ADMIN_LAYOUT_EXTENSION
from campus_ops.operator_refinement import OPERATOR_REFINEMENT_EXTENSION
from campus_ops.version import build_info


@pytest.mark.parametrize(
    ("view", "label"),
    [
        ("admin-command", "Operations"),
        ("admin-forensics", "Investigation"),
        ("admin-red", "Validation"),
        ("admin-infra", "Infrastructure"),
    ],
)
def test_admin_extensions_use_one_canonical_label_set(view: str, label: str):
    marker = f"'{view}':'{label}'"
    assert marker in ADMIN_LAYOUT_EXTENSION
    assert marker in OPERATOR_REFINEMENT_EXTENSION


def test_secondary_admin_tabs_have_stronger_hide_rule():
    assert "#adminWorkspaceNav button.tab.admin-secondary{display:none!important}" in ADMIN_LAYOUT_EXTENSION


def test_bootstrap_forces_real_interface_election_and_finishes_repairs():
    script = Path("bootstrap.sh").read_text()
    assert 'sudo bash "$installer" --interface auto || installer_status=$?' in script
    assert '"$installer_status" -ne 0 && "$installer_status" -ne 2' in script
    assert "repair_capture_permissions.sh" in script
    assert "--force-reinstall --no-deps" in script
    assert "wait_for_console.sh" in script
    assert script.index("wait_for_console.sh") < script.index("campus_ops.deployment_check")


def test_bootstrap_records_exact_deployed_branch_and_commit():
    script = Path("bootstrap.sh").read_text()
    assert 'build_commit="$(git rev-parse HEAD)"' in script
    assert 'build_branch="$(git branch --show-current)"' in script
    assert "/etc/campus-ops/build.json" in script
    assert '"source_dirty": $build_dirty' in script


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


def test_installers_use_shared_readiness_gate():
    ubuntu = Path("scripts/install_ubuntu.sh").read_text()
    kali = Path("scripts/install_kali.sh").read_text()
    assert "wait_for_console.sh" in ubuntu
    assert "wait_for_console.sh" in kali
    assert "curl -fsS http://127.0.0.1:8765" not in ubuntu
    assert "curl -fsS http://127.0.0.1:8765" not in kali


def test_managed_console_inherits_linux_capture_capabilities():
    unit = Path("deploy/campus-ops.service").read_text()
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "SupplementaryGroups=wireshark" in unit

    check = Path("src/campus_ops/deployment_check.py").read_text()
    assert "_managed_service_capability_check" in check
    assert 'values.get("CapEff", "0")' in check
    assert 'values.get("CapAmb", "0")' in check


def test_linux_capture_does_not_ask_tshark_for_raw_capture():
    capture = Path("src/campus_ops/workers/capture.py").read_text()
    assert 'self._decoder_command(tshark, ["-r", "-"])' in capture
    assert 'self._active_backend = f"{backend_name}+tshark"' in capture
    assert 'rows.append(("dumpcap", dumpcap))' in capture
    assert 'rows.append(("tcpdump", tcpdump))' in capture


def test_capture_repair_verifies_real_service_identity_and_packet_open():
    repair = Path("scripts/repair_capture_permissions.sh").read_text()
    assert 'runuser -u "$capture_user" -- "$dumpcap_path"' in repair
    assert 'duration:1' in repair
    assert 'setcap cap_net_raw,cap_net_admin=eip "$tcpdump_path"' in repair


def test_default_documentation_does_not_recommend_any_capture():
    readme = Path("README.md").read_text()
    assert "sudo bash scripts/install_ubuntu.sh --interface auto" in readme
    assert "--interface any remains" not in readme.lower()


def test_dependency_constraints_do_not_reintroduce_invalid_websockets_pin():
    constraints = Path("requirements.lock").read_text()
    assert "websockets==17.1" not in constraints
