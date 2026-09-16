from pathlib import Path


def test_windows_release_paths_use_one_canonical_executable_name():
    build = Path("scripts/build_windows.ps1").read_text()
    service = Path("scripts/install_windows_service.ps1").read_text()
    workflow = Path(".github/workflows/windows-build.yml").read_text()

    assert "--name MONWindows" in build
    assert "dist\\MONWindows.exe" in build
    assert "dist\\MONWindows.exe" in service
    assert "--name MONWindows" in workflow
    assert "dist/MONWindows.exe" in workflow
    assert "CampusOperationalConsole.exe" not in build
    assert "CampusOperationalConsole.exe" not in service


def test_windows_service_runs_headless_with_auto_interface_selection():
    service = Path("scripts/install_windows_service.ps1").read_text()
    assert "CAMPUS_OPS_NO_BROWSER=1" in service
    assert "CAMPUS_OPS_INTERFACE=auto" in service
    assert "start= delayed-auto" in service
