# oct-curl.ps1 — curl-style fetch for oct:// URLs via the portal.
#
# Usage:
#   oct-curl.ps1 oct://<circle>/<path> [curl args...]
#
# Requires `octravpn portal` running (default 127.0.0.1:51823).
# Set $env:OCTRAVPN_PORTAL to override the loopback bind.

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$OctUrl,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CurlArgs
)

$ErrorActionPreference = 'Stop'

$Portal = if ($env:OCTRAVPN_PORTAL) { $env:OCTRAVPN_PORTAL } else { 'http://127.0.0.1:51823' }

if (-not $OctUrl.StartsWith('oct://')) {
    Write-Error "oct-curl: not an oct:// URL: $OctUrl"
    exit 2
}

Add-Type -AssemblyName System.Web
$encoded = [System.Web.HttpUtility]::UrlEncode($OctUrl)

# Mint approval token via /confirm?accept=cli.
try {
    $resp = Invoke-RestMethod -Uri "$Portal/confirm?u=$encoded&accept=cli" -Method GET
} catch {
    Write-Error "oct-curl: could not mint approval token: $_"
    exit 3
}

$token = $resp.token
if (-not $token) {
    Write-Error 'oct-curl: empty token in /confirm response'
    exit 3
}

$target = "$Portal/raw?u=$encoded&token=$token"
& curl.exe @CurlArgs $target
exit $LASTEXITCODE
