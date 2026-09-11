$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

if (Test-Path '.venv-build') { Remove-Item -Recurse -Force '.venv-build' }
py -3.12 -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install --upgrade pip
.\.venv-build\Scripts\pip.exe install -e '.[build]'

if (Test-Path 'build') { Remove-Item -Recurse -Force 'build' }
if (Test-Path 'dist') { Remove-Item -Recurse -Force 'dist' }

.\.venv-build\Scripts\pyinstaller.exe `
  --noconfirm `
  --clean `
  --onefile `
  --noconsole `
  --name CampusCyberOperationsPlatform `
  --add-data 'src/campus_ops/ui/index.html;campus_ops/ui' `
  --collect-all uvicorn `
  --collect-all fastapi `
  src/campus_ops/__main__.py

Write-Host ''
Write-Host 'Build complete:'
Write-Host (Resolve-Path 'dist\CampusCyberOperationsPlatform.exe')
