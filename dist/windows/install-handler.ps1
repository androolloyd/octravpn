<#
.SYNOPSIS
    Register `octravpn open-url` as the Windows handler for `oct://` URLs.

.DESCRIPTION
    Renders `dist\windows\octravpn-oct-handler.reg` with the absolute
    path of the located `octravpn.exe` substituted in, applies it via
    `reg import`, then reads the keys back to verify.

    Per-user only. Touches HKCU:\Software\Classes\oct exclusively.
    Never writes to HKLM. Never requires admin.

    Symmetric uninstaller: `dist\windows\uninstall-handler.ps1`.

    Not run during scaffolding. To test manually:
      1.  cargo build --release -p octravpn-client
      2.  Copy or symlink target\release\octravpn.exe onto PATH (or
          set $env:OCTRAVPN_EXE to its absolute path).
      3.  powershell -ExecutionPolicy Bypass -File dist\windows\install-handler.ps1
      4.  cmd /c start "" "oct://octdeadbeef00000000000000000000000000000000/policy.json"
      5.  Expect a console window from octravpn.exe printing
          "would open oct://..." (stub behaviour; see open_url.rs).

    Read the design doc before changing anything here:
      docs\oct-url-handler.md

.NOTES
    Idempotent: re-running rewrites the same keys.
#>

[CmdletBinding()]
param(
    # Optional override; takes precedence over PATH lookup.
    [string]$OctravpnExe = $env:OCTRAVPN_EXE
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Refuse to run on non-Windows hosts. PowerShell Core runs on Linux
# and macOS now, but the registry paths below mean nothing there.
if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
    Write-Error "this script targets Windows; got platform: $($PSVersionTable.OS)"
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir '..\..')
$Template  = Join-Path $ScriptDir 'octravpn-oct-handler.reg'

if (-not (Test-Path $Template)) {
    Write-Error "registry template not found at $Template"
    exit 1
}

# Locate octravpn.exe. Precedence:
#   1. -OctravpnExe parameter / $env:OCTRAVPN_EXE.
#   2. `octravpn` on PATH (Get-Command).
#   3. <repo>\target\release\octravpn.exe (cargo artifact).
function Resolve-OctravpnExe {
    param([string]$Override)

    if ($Override) {
        if (Test-Path $Override) {
            return (Resolve-Path $Override).Path
        }
        throw "OctravpnExe override '$Override' does not exist"
    }

    $cmd = Get-Command octravpn -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $fallback = Join-Path $RepoRoot 'target\release\octravpn.exe'
    if (Test-Path $fallback) {
        return (Resolve-Path $fallback).Path
    }

    throw @"
octravpn.exe not found.
  pass -OctravpnExe <path>, set `$env:OCTRAVPN_EXE`, install on PATH,
  or run: cargo build --release -p octravpn-client
"@
}

$ExePath = Resolve-OctravpnExe -Override $OctravpnExe
Write-Host "using octravpn binary: $ExePath"

# Read the template (UTF-16 LE w/ BOM). Get-Content -Raw with the
# `Unicode` encoding (PowerShell's name for UTF-16 LE) handles the
# BOM transparently.
$Template = Resolve-Path $Template
$reg = Get-Content -Raw -Path $Template -Encoding Unicode

# .reg REG_SZ values encode `\` as `\\`. Double every backslash in
# the path before substituting it into the template.
$ExePathForReg = $ExePath -replace '\\', '\\'
$rendered = $reg -replace '__OCTRAVPN_EXE__', $ExePathForReg

# Write the rendered .reg to a temp file in the same UTF-16 LE / BOM
# encoding `reg import` expects. `Out-File -Encoding Unicode` writes
# UTF-16 LE with BOM by default in Windows PowerShell.
$tmp = [System.IO.Path]::GetTempFileName()
$tmpReg = [System.IO.Path]::ChangeExtension($tmp, '.reg')
Move-Item -Path $tmp -Destination $tmpReg -Force
try {
    # Force Windows-style CRLF line endings — `reg import` is picky.
    $rendered = $rendered -replace "`r?`n", "`r`n"
    [System.IO.File]::WriteAllText($tmpReg, $rendered, [System.Text.Encoding]::Unicode)

    Write-Host "applying registry import from $tmpReg"
    $regCmd = Get-Command reg.exe -ErrorAction Stop
    & $regCmd.Source import $tmpReg | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reg import failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -Path $tmpReg -ErrorAction SilentlyContinue
}

Write-Host "verifying registration"
$ClassRoot = 'HKCU:\Software\Classes\oct'
$CmdKey    = "$ClassRoot\shell\open\command"

$defaultName = (Get-ItemProperty -Path $ClassRoot -Name '(default)' -ErrorAction Stop).'(default)'
$urlProto    = (Get-ItemProperty -Path $ClassRoot -Name 'URL Protocol' -ErrorAction Stop).'URL Protocol'
$cmdValue    = (Get-ItemProperty -Path $CmdKey -Name '(default)' -ErrorAction Stop).'(default)'

if ($defaultName -ne 'URL:OctraVPN Protocol') {
    Write-Error "verification failed: HKCU:\Software\Classes\oct (default) = '$defaultName'"
    exit 1
}
if ($urlProto -ne '') {
    Write-Error "verification failed: 'URL Protocol' should be empty, got '$urlProto'"
    exit 1
}
if ($cmdValue -notmatch [regex]::Escape($ExePath)) {
    Write-Error "verification failed: shell\open\command does not contain '$ExePath'`n  got: $cmdValue"
    exit 1
}

Write-Host "ok: oct: scheme registered"
Write-Host "  $ClassRoot (default)      = $defaultName"
Write-Host "  $ClassRoot URL Protocol   = (empty)"
Write-Host "  $CmdKey (default) = $cmdValue"
Write-Host ""
Write-Host "test with:"
Write-Host '  cmd /c start "" "oct://octdeadbeef00000000000000000000000000000000/policy.json"'
