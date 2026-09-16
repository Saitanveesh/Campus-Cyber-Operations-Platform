$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host 'Campus Cyber Operations Platform - Release Build'
Write-Host '================================================='

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher (py.exe) is required.'
}

if (Test-Path '.venv-build') { Remove-Item -Recurse -Force '.venv-build' }
py -3.12 -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install --upgrade pip
.\.venv-build\Scripts\pip.exe install -e '.[dev,build]'

Write-Host 'Running release quality gate...'
.\.venv-build\Scripts\python.exe -m ruff check src tests
.\.venv-build\Scripts\python.exe -m pytest -q

if (Test-Path 'build') { Remove-Item -Recurse -Force 'build' }
if (Test-Path 'dist') { Remove-Item -Recurse -Force 'dist' }

Write-Host 'Building CampusCyberOperationsPlatform.exe...'
.\.venv-build\Scripts\pyinstaller.exe `
  --noconfirm `
  --clean `
  --onefile `
  --noconsole `
  --name CampusCyberOperationsPlatform `
  --paths src `
  --add-data 'src/campus_ops/ui/index.html;campus_ops/ui' `
  --collect-submodules campus_ops `
  --collect-all uvicorn `
  --collect-all fastapi `
  src/campus_ops/__main__.py

$Exe = Resolve-Path 'dist\CampusCyberOperationsPlatform.exe'
$Hash = (Get-FileHash $Exe -Algorithm SHA256).Hash
Write-Host ''
Write-Host 'Build complete:'
Write-Host $Exe
Write-Host "SHA-256: $Hash"
Write-Host 'External packet/security tools remain separate runtime capabilities and are not embedded in the executable.'
