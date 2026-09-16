from pathlib import Path


def test_windows_service_installs_exact_release_executable_name():
    build = Path("scripts/build_windows.ps1").read_text()
    service = Path("scripts/install_windows_service.ps1").read_text()

    assert "--name CampusOperationalConsole" in build
    assert "dist\\CampusOperationalConsole.exe" in build
    assert "dist\\CampusOperationalConsole.exe" in service
    assert "dist\\CampusCyberOperationsPlatform.exe" not in service


def test_windows_service_runs_headless_with_auto_interface_selection():
    service = Path("scripts/install_windows_service.ps1").read_text()
    assert "CAMPUS_OPS_NO_BROWSER=1" in service
    assert "CAMPUS_OPS_INTERFACE=auto" in service
