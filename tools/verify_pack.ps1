#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies a pack: manifest signature (ECDSA P-256 against the committed public key) then per-file SHA256.
    Exit 0 = PASS, exit 1 = FAIL.
#>
param(
    [Parameter(Mandatory = $true)][string]$PackDir,
    [string]$PublicKeyPath
)
$ErrorActionPreference = 'Stop'

if (-not $PublicKeyPath) { $PublicKeyPath = Join-Path $PSScriptRoot 'packs_public_key.pem' }

function Fail($msg) { Write-Host "VERIFY FAIL : $msg"; exit 1 }

$manifestPath = Join-Path $PackDir 'pack.manifest.json'
$sigPath      = Join-Path $PackDir 'pack.manifest.json.sig'
if (-not (Test-Path $manifestPath)) { Fail "manifest missing: $manifestPath" }
if (-not (Test-Path $sigPath))      { Fail "signature missing: $sigPath" }
if (-not (Test-Path $PublicKeyPath)) { Fail "public key missing: $PublicKeyPath" }

$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.manifest_version -ne 1) { Fail "unsupported manifest_version" }
if (-not $manifest.pack_id)           { Fail "manifest missing pack_id" }

# --- 1) per-file hashes ---
foreach ($f in $manifest.files) {
    $fp = Join-Path $PackDir $f.path
    if (-not (Test-Path $fp)) { Fail "listed file missing: $($f.path)" }
    $h = (Get-FileHash -Algorithm SHA256 $fp).Hash.ToLower()
    if ($h -ne $f.sha256.ToLower()) { Fail "SHA256 mismatch: $($f.path)" }
}

# --- 2) import public key (manual SPKI parse: skip 26-byte P-256 prefix, 0x04 + X(32) + Y(32)) ---
$raw = (Get-Content $PublicKeyPath -Raw) -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\s', ''
$spki = [Convert]::FromBase64String($raw)
if ($spki.Length -ne 91 -or $spki[26] -ne 0x04) { Fail "unexpected public key format" }
$x = New-Object byte[] 32; $y = New-Object byte[] 32
[Array]::Copy($spki, 27, $x, 0, 32)
[Array]::Copy($spki, 59, $y, 0, 32)

$ecdsa = New-Object System.Security.Cryptography.ECDsaCng
try {
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = $x; $q.Y = $y
    $p.Q = $q
    $ecdsa.ImportParameters($p)

    # --- 3) verify signature over exact manifest bytes ---
    $data = [IO.File]::ReadAllBytes($manifestPath)
    $sig  = [Convert]::FromBase64String((Get-Content $sigPath -Raw).Trim())
    if (-not $ecdsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) {
        Fail "signature invalid"
    }
}
catch { Fail "verification error: $($_.Exception.Message)" }
finally { $ecdsa.Dispose() }

Write-Host "VERIFY PASS : $($manifest.pack_id) v$($manifest.version)"
exit 0
