from pathlib import Path


def test_readiness_gate_requires_real_active_capture():
    source = Path("scripts/wait_for_console.sh").read_text()
    assert 'state == "ACTIVE"' in source
    assert 'backend == "tshark"' in source
    assert "process_pid" in source
    assert "session and interface" in source
    assert "Monitor ready:" in source


def test_deployment_check_refuses_waiting_or_pidless_runtime_capture():
    source = Path("src/campus_ops/deployment_check.py").read_text()
    assert 'if state != "ACTIVE"' in source
    assert 'Runtime has no active monitoring session' in source
    assert 'Runtime has no selected monitoring interface' in source
    assert 'Runtime capture has no live TShark process PID' in source
    assert 'Runtime network/capture interface mismatch' in source


def test_ubuntu_ci_checks_live_capture_not_only_http_server():
    source = Path(".github/workflows/ubuntu-ci.yml").read_text()
    assert "runtime.get('state') == 'ACTIVE'" in source
    assert "runtime.get('backend') == 'tshark'" in source
    assert "runtime.get('process_pid')" in source
    assert "status.get('session_id')" in source
