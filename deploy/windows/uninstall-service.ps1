[CmdletBinding()]
param([string]$ServiceName = "OctraVPN-Node")

$ErrorActionPreference = "Stop"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Service $ServiceName not installed."
    exit 0
}

Write-Host "Stopping $ServiceName ..."
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
sc.exe delete $ServiceName | Out-Null
Write-Host "Removed $ServiceName."
