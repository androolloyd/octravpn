<#
.SYNOPSIS
    Remove the `oct://` URL-scheme handler installed by
    `dist\windows\install-handler.ps1`.

.DESCRIPTION
    Removes HKCU:\Software\Classes\oct and everything beneath it.

    Idempotent: running this when nothing is installed prints a status
    message and exits 0.

    Touches only the per-user HKCU subtree we created. Never HKLM.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
    Write-Error "this script targets Windows; got platform: $($PSVersionTable.OS)"
    exit 1
}

$ClassRoot = 'HKCU:\Software\Classes\oct'

if (Test-Path $ClassRoot) {
    Write-Host "removing $ClassRoot (recursive)"
    Remove-Item -Path $ClassRoot -Recurse -Force
    Write-Host "done."
}
else {
    Write-Host "note: $ClassRoot already absent; nothing to do."
}
