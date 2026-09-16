from pathlib import Path


def test_deployment_check_requires_windows_service_npcap_session_and_tshark():
    source = Path("src/campus_ops/deployment_check.py").read_text()
    assert 'SERVICE_NAME = "MONWindows"' in source
    assert 'sc.exe", "query", "npcap"' in source
    assert "runtime_profile" in source
    assert "windows-native-single-source" in source
    assert "current-session-packet-evidence-only" in source
    assert "MON has no active monitoring session" in source
    assert "MON capture is not ACTIVE" in source
    assert "runtime TShark PID is missing" in source
    assert "network/capture adapter mismatch" in source


def test_bootstrap_runs_readiness_check_after_service_install():
    source = Path("bootstrap.ps1").read_text()
    assert "install_windows_service.ps1" in source
    assert "Write-DeploymentManifest" in source
    assert "campus_ops.deployment_check" in source
    assert source.index("install_windows_service.ps1") < source.index("campus_ops.deployment_check")


def test_windows_ci_checks_product_branch():
    source = Path(".github/workflows/windows-ci.yml").read_text()
    assert "windows-native-v2" in source
    assert "python-version" in source
    assert "ruff check src tests" in source
    assert "pytest -q" in source
