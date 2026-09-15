from pathlib import Path

import pytest

from campus_ops.admin_layout_ui import ADMIN_LAYOUT_EXTENSION
from campus_ops.operator_refinement import OPERATOR_REFINEMENT_EXTENSION


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
    # operator_refinement has a generic display:block!important rule, so this selector
    # must remain more specific or the hidden workspaces return to the navigation row.
    assert "#adminWorkspaceNav button.tab.admin-secondary{display:none!important}" in ADMIN_LAYOUT_EXTENSION


def test_bootstrap_forces_real_interface_election_and_finishes_repairs():
    script = Path("bootstrap.sh").read_text()
    assert 'sudo bash "$installer" --interface auto || installer_status=$?' in script
    assert '"$installer_status" -ne 0 && "$installer_status" -ne 2' in script
    assert "repair_capture_permissions.sh" in script
    assert "--force-reinstall --no-deps" in script
    assert "wait_for_console.sh" in script
    assert script.index("wait_for_console.sh") < script.index("campus_ops.deployment_check")


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
