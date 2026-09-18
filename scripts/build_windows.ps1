param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host 'MON Windows - Release Build'
Write-Host '==========================='

if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
    throw 'Python launcher py.exe is required. Run .\bootstrap.ps1 as Administrator.'
}

& py.exe -3.12 -c "import sys; assert sys.version_info[:2] == (3, 12)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 is required for the release build.' }

if (Test-Path '.venv-build') { Remove-Item -Recurse -Force '.venv-build' }
& py.exe -3.12 -m venv .venv-build
$Python = '.\.venv-build\Scripts\python.exe'
$Pip = '.\.venv-build\Scripts\pip.exe'
$PyInstaller = '.\.venv-build\Scripts\pyinstaller.exe'

& $Python -m pip install --upgrade pip
& $Pip install -r requirements.lock
& $Pip install -e '.[build]'
& $Python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Python dependency validation failed.' }

if (-not $SkipTests) {
    Write-Host '[MON] Running Windows release quality gate...'
    & $Python -m ruff check src tests
    if ($LASTEXITCODE -ne 0) { throw 'Ruff quality gate failed.' }
    & $Python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Windows test suite failed.' }
} else {
    Write-Warning 'Build tests were skipped by explicit request.'
}

if (Test-Path 'build') { Remove-Item -Recurse -Force 'build' }
if (Test-Path 'dist') { Remove-Item -Recurse -Force 'dist' }

Write-Host '[MON] Building MONWindows.exe...'
& $PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --noconsole `
  --name MONWindows `
  --paths src `
  --add-data 'src/campus_ops/ui/index.html;campus_ops/ui' `
  --collect-submodules campus_ops `
  --collect-all uvicorn `
  --collect-all fastapi `
  --hidden-import servicemanager `
  --hidden-import win32service `
  --hidden-import win32serviceutil `
  --hidden-import win32event `
  --hidden-import win32timezone `
  src/campus_ops/__main__.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }

$Exe = Resolve-Path 'dist\MONWindows.exe'
$Hash = (Get-FileHash $Exe -Algorithm SHA256).Hash
Write-Host ''
Write-Host 'Build complete:'
Write-Host $Exe
Write-Host "SHA-256: $Hash"
Write-Host 'Runtime capture dependency: installed Wireshark TShark + Npcap. They are not bundled into MONWindows.exe.'
