# Install octravpn-node as a Windows service.
# Run from an elevated PowerShell prompt.
#
# Usage:
#   .\install-service.ps1                    # default config path
#   .\install-service.ps1 -ConfigPath C:\... # custom config path
[CmdletBinding()]
param(
    [string]$BinaryPath = "C:\Program Files\OctraVPN\octravpn-node.exe",
    [string]$ConfigPath = "C:\ProgramData\OctraVPN\node.toml",
    [string]$ServiceName = "OctraVPN-Node",
    [string]$DisplayName = "OctraVPN Node",
    [string]$Description = "OctraVPN validator-side node daemon."
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found at $BinaryPath. Install the package first or pass -BinaryPath."
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config not found at $ConfigPath. Run 'octravpn init' or pass -ConfigPath."
}

# Ensure log dir exists.
$logDir = "C:\ProgramData\OctraVPN\logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# wintun driver discovery — issue a warning if not found.
$wintun = Get-ChildItem -Path "C:\Windows\System32\wintun.dll" -ErrorAction SilentlyContinue
if (-not $wintun) {
    Write-Warning "wintun.dll not found in System32. The service will fail to open a TUN device until you install the WireGuard wintun driver."
}

# Stop + remove any existing service.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing $ServiceName ..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Build the binPath= argument. sc.exe requires the space after `binPath=`.
$binArgs = "`"$BinaryPath`" --config `"$ConfigPath`" run"
$result = sc.exe create $ServiceName binPath= "$binArgs" DisplayName= "$DisplayName" start= auto
Write-Host $result

sc.exe description $ServiceName $Description | Out-Null
# Restart on failure: first restart after 5s, second after 10s, give up after 60s of total bad time.
sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/10000/restart/60000 | Out-Null

Write-Host "Starting $ServiceName ..."
Start-Service -Name $ServiceName

Get-Service -Name $ServiceName | Format-Table -AutoSize
Write-Host ""
Write-Host "Logs: $logDir"
Write-Host "Status: sc.exe query $ServiceName"
Write-Host "Stop:   Stop-Service $ServiceName"
