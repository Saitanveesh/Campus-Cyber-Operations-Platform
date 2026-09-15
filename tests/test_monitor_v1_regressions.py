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


def test_bootstrap_forces_real_interface_election():
    script = Path("bootstrap.sh").read_text()
    assert 'sudo bash "$installer" --interface auto' in script
    assert "repair_capture_permissions.sh" in script


def test_default_documentation_does_not_recommend_any_capture():
    readme = Path("README.md").read_text()
    assert "sudo bash scripts/install_ubuntu.sh --interface auto" in readme
    assert "--interface any remains" not in readme.lower()


def test_dependency_constraints_do_not_reintroduce_invalid_websockets_pin():
    constraints = Path("requirements.lock").read_text()
    assert "websockets==17.1" not in constraints
