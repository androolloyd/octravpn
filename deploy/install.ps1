# OctraVPN Windows installer.
#
# Usage:
#   iex (irm https://octravpn.org/install.ps1)
#   iex (irm https://octravpn.org/install.ps1); Install-OctraVPN -Node
#
# Run from an elevated PowerShell prompt for system-service installation.
[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$Node,
    [switch]$NoService,
    [string]$Prefix = "$env:ProgramFiles\OctraVPN",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Warning $m }

$ReleasesUrl = if ($env:OCTRAVPN_RELEASES_URL) { $env:OCTRAVPN_RELEASES_URL } else { "https://github.com/octra-labs/octravpn/releases" }

# Resolve target triple.
if (-not [Environment]::Is64BitOperatingSystem) {
    throw "OctraVPN requires 64-bit Windows."
}
$arch = (Get-CimInstance Win32_Processor).Architecture
$Target = "x86_64-pc-windows-msvc"
if ($arch -eq 12) {
    # 12 = ARM64
    $Target = "aarch64-pc-windows-msvc"
}

# Resolve version.
if (-not $Version) {
    Say "Resolving latest release"
    $resp = Invoke-WebRequest -Uri "$ReleasesUrl/latest" -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
    if (-not $resp -or -not $resp.Headers.Location) {
        # PowerShell follows redirects by default; grab from URI.
        $resp = Invoke-WebRequest -Uri "$ReleasesUrl/latest" -UseBasicParsing
        $Version = ($resp.BaseResponse.ResponseUri.Segments | Select-Object -Last 1).TrimEnd('/')
    } else {
        $Version = ($resp.Headers.Location.Split('/') | Select-Object -Last 1)
    }
    if (-not $Version) {
        throw "Could not resolve latest version. Pass -Version X.Y.Z."
    }
}

Say "Installing OctraVPN $Version ($Target)"

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "octravpn-$(Get-Random)") -Force
try {
    $zipName = "octravpn-$Version-$Target.zip"
    $zipUrl = "$ReleasesUrl/download/$Version/$zipName"
    $zipPath = Join-Path $tmp $zipName

    Say "Downloading $zipUrl"
    if (-not $DryRun) {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    }

    # Optional signature verification via signtool if the .cat is published.
    $catUrl = "$ReleasesUrl/download/$Version/$zipName.cat"
    try {
        if (-not $DryRun) {
            Invoke-WebRequest -Uri $catUrl -OutFile "$zipPath.cat" -UseBasicParsing -ErrorAction Stop
            Say "Verifying Authenticode signature"
            $verified = Get-AuthenticodeSignature -FilePath $zipPath
            if ($verified.Status -ne 'Valid') {
                throw "Authenticode verification failed: $($verified.Status)"
            }
        }
    } catch {
        Warn "Signature file not available; proceeding without verification."
    }

    if (-not (Test-Path $Prefix)) {
        New-Item -ItemType Directory -Path $Prefix | Out-Null
    }
    Say "Extracting to $Prefix"
    if (-not $DryRun) {
        Expand-Archive -Path $zipPath -DestinationPath $Prefix -Force
    }

    # Promote octravpn[.exe] and octravpn-node[.exe] to %PATH%.
    $bin = Join-Path $Prefix "octravpn.exe"
    $nodeBin = Join-Path $Prefix "octravpn-node.exe"
    if (Test-Path $bin) {
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if (-not ($machinePath.Split(';') -contains $Prefix)) {
            Say "Adding $Prefix to system PATH"
            if (-not $DryRun) {
                [Environment]::SetEnvironmentVariable("Path", "$machinePath;$Prefix", "Machine")
            }
        }
    }

    # Ensure ProgramData dir + log dir.
    $cfgDir = "$env:ProgramData\OctraVPN"
    $logDir = "$cfgDir\logs"
    foreach ($d in @($cfgDir, $logDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    if ($Node -and -not $NoService) {
        Say "Registering OctraVPN-Node as a Windows service"
        if (-not $DryRun) {
            $installScript = Join-Path $Prefix "install-service.ps1"
            if (-not (Test-Path $installScript)) {
                # Pull from the release if not bundled.
                Invoke-WebRequest -Uri "$ReleasesUrl/download/$Version/install-service.ps1" `
                    -OutFile $installScript -UseBasicParsing
            }
            & $installScript -BinaryPath $nodeBin -ConfigPath "$cfgDir\node.toml"
        }
    }

    Say "Installed."
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  octravpn init --rpc-url https://your.rpc/rpc --program-addr oct..."
    Write-Host "  octravpn doctor"
    Write-Host ""
    Write-Host "Documentation: https://github.com/octra-labs/octravpn/blob/main/docs/install.md"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

function Install-OctraVPN {
    param([switch]$Node, [string]$Version)
    & $PSCommandPath -Node:$Node -Version $Version
}
