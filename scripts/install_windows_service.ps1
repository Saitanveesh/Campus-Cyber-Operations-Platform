param(
    [string]$ServiceName = 'MONWindows',
    [string]$DisplayName = 'MON Windows Network Monitor',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$sourceExe = Join-Path $root 'dist\MONWindows.exe'
$installDir = Join-Path $env:ProgramFiles 'MON'
$installedExe = Join-Path $installDir 'MONWindows.exe'
$dataDir = Join-Path $env:ProgramData 'MON'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator to install or remove MON Windows service.'
}

function Test-ServiceScmPresent([string]$Name) {
    $null = & sc.exe query $Name 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Wait-ServiceScmDeleted([string]$Name, [int]$TimeoutSeconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $output = (& sc.exe query $Name 2>&1 | Out-String)
        $code = $LASTEXITCODE

        # ERROR_SERVICE_DOES_NOT_EXIST (1060) means SCM has fully released the name.
        if ($code -eq 1060 -or $output -match 'FAILED\s+1060') {
            return
        }

        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Windows service $Name is still registered or pending deletion after $TimeoutSeconds seconds. Close Services.msc/Event Viewer handles or reboot once, then rerun bootstrap.ps1."
}

function Remove-ServiceIfPresent([string]$Name) {
    if (-not (Test-ServiceScmPresent $Name)) {
        # A just-deleted service may already be invisible to Get-Service but still be
        # pending deletion inside SCM. Give SCM a brief chance to release the name.
        $probe = (& sc.exe query $Name 2>&1 | Out-String)
        if ($probe -match 'FAILED\s+1072') {
            Wait-ServiceScmDeleted $Name 30
        }
        return
    }

    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    $deleteOutput = (& sc.exe delete $Name 2>&1 | Out-String).Trim()
    $deleteCode = $LASTEXITCODE
    if ($deleteCode -ne 0 -and $deleteCode -ne 1060 -and $deleteOutput -notmatch 'FAILED\s+1060') {
        throw "Failed to delete Windows service $Name. sc.exe: $deleteOutput"
    }

    Wait-ServiceScmDeleted $Name 30
}

function New-MonServiceWithRetry(
    [string]$Name,
    [string]$BinaryPath,
    [string]$ServiceDisplayName,
    [int]$Attempts = 10
) {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $createOutput = (
            & sc.exe create $Name binPath= $BinaryPath start= delayed-auto DisplayName= $ServiceDisplayName 2>&1 |
                Out-String
        ).Trim()
        $createCode = $LASTEXITCODE

        if ($createCode -eq 0) {
            return
        }

        $pendingDeletion = (
            $createCode -eq 1072 -or
            $createOutput -match 'FAILED\s+1072' -or
            $createOutput -match 'marked for deletion'
        )

        if (-not $pendingDeletion) {
            throw "sc.exe create failed with exit code $createCode. Output: $createOutput"
        }

        Write-Host "[MON] Service name is pending deletion; retrying registration ($attempt/$Attempts)..."
        Start-Sleep -Seconds 2
    }

    throw "sc.exe create could not register $Name because Windows kept the previous service marked for deletion. Reboot Windows once, then rerun .\bootstrap.ps1."
}

if ($Remove) {
    Remove-ServiceIfPresent $ServiceName
    Write-Host "Removed service $ServiceName"
    Write-Host "Program data was preserved at $dataDir"
    exit 0
}

if (-not (Test-Path $sourceExe)) {
    throw "Executable not found: $sourceExe. Run scripts\build_windows.ps1 first."
}

# Remove legacy service names so two MON processes cannot compete for port 8765 or the
# selected Npcap adapter.
$legacy = 'CampusCyberOperationsPlatform'
if ($legacy -ne $ServiceName) { Remove-ServiceIfPresent $legacy }
Remove-ServiceIfPresent $ServiceName

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Copy-Item -Path $sourceExe -Destination $installedExe -Force

if (-not (Test-Path $installedExe)) {
    throw "Installed executable is missing: $installedExe"
}
$sourceHash = (Get-FileHash $sourceExe -Algorithm SHA256).Hash
$installedHash = (Get-FileHash $installedExe -Algorithm SHA256).Hash
if ($sourceHash -ne $installedHash) {
    throw 'Installed MONWindows.exe hash does not match the built artifact.'
}

# MONWindows.exe contains a pywin32 ServiceFramework host. --service enters the
# Service Control Manager dispatcher instead of starting the interactive/browser mode.
$bin = '"' + $installedExe + '" --service'
New-MonServiceWithRetry -Name $ServiceName -BinaryPath $bin -ServiceDisplayName $DisplayName

$descriptionOutput = (& sc.exe description $ServiceName 'Native Windows MON: one TShark/Npcap packet source, evidence-backed network monitoring.' 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Failed to set service description: $descriptionOutput" }

$failureOutput = (& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Failed to configure service recovery: $failureOutput" }

$flagOutput = (& sc.exe failureflag $ServiceName 1 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Failed to enable failure actions: $flagOutput" }

$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
New-ItemProperty `
    -Path $serviceKey `
    -Name Environment `
    -PropertyType MultiString `
    -Value @(
        'CAMPUS_OPS_NO_BROWSER=1',
        'CAMPUS_OPS_INTERFACE=auto',
        "CAMPUS_OPS_DATA_DIR=$dataDir"
    ) `
    -Force | Out-Null

Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$service = Get-Service -Name $ServiceName
if ($service.Status -ne 'Running') {
    $log = Join-Path $dataDir 'mon-service.log'
    throw "Service $ServiceName did not reach RUNNING state. Check $log and Windows Event Viewer."
}

Write-Host "Installed and started $ServiceName"
Write-Host "Executable: $installedExe --service"
Write-Host "SHA-256: $installedHash"
Write-Host "Data: $dataDir"
Write-Host "Log: $(Join-Path $dataDir 'mon-service.log')"
Write-Host 'Interface selection: auto (native Windows Wi-Fi/Ethernet preferred over virtual adapters)'
