#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies a pack: manifest structure + path safety + per-file SHA256 + size + freshness, then the
    DER signature (ECDSA P-256) against the committed public key.
    Exit 0 = PASS, exit 1 = FAIL.

.NOTES
    Audit fixes (2026-11-17): H2 freshness/replay (issued+expires_hint_days enforced), H3 path
    traversal rejected, M1 required-field enforcement, M3 size validation, C1 strict DER signature
    parse (raw r||s rejected). Verification is runtime-agnostic: .NET Framework's ECDsa.VerifyData
    expects a raw r||s blob while .NET 8 expects DER, so we try raw first, then DER.
    Third-party verification (no repo tools needed) - .sig is Base64 text, decode to binary DER first:
      base64 -d pack.manifest.json.sig > sig.der
      openssl dgst -sha256 -verify packs_public_key.pem -signature sig.der pack.manifest.json
#>
param(
    [Parameter(Mandatory = $true)][string]$PackDir,
    [string]$PublicKeyPath,
    [datetime]$Now = (Get-Date)
)
$ErrorActionPreference = 'Stop'

if (-not $PublicKeyPath) { $PublicKeyPath = Join-Path $PSScriptRoot 'packs_public_key.pem' }

function Fail($msg) { Write-Host "VERIFY FAIL : $msg"; exit 1 }

function Add-Bytes([byte[]]$a, [byte[]]$b) {
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($x in $a) { $out.Add($x) }
    foreach ($x in $b) { $out.Add($x) }
    return $out.ToArray()
}

# Strict DER parse: SEQUENCE { INTEGER r, INTEGER s }, short-form lengths only (P-256 DER is <=72 bytes).
# Returns raw r||s (each zero-padded to keyBytes) for runtimes that expect raw; $null if malformed.
function ConvertFrom-DerSignature([byte[]]$sig, [int]$keyBytes) {
    if ($sig.Length -lt 8 -or $sig[0] -ne 0x30) { return $null }
    if ($sig[1] -ne ($sig.Length - 2)) { return $null }          # DER short-form length must cover the payload
    $idx = 2
    $parts = @()
    foreach ($dummy in 1, 2) {
        if ($idx -ge ($sig.Length - 1) -or $sig[$idx] -ne 0x02) { return $null }
        $idx++
        $ilen = $sig[$idx]; $idx++
        if ($ilen -lt 1 -or $ilen -gt ($keyBytes + 1)) { return $null }
        if (($idx + $ilen) -gt $sig.Length) { return $null }
        $val = $sig[$idx..($idx + $ilen - 1)]; $idx += $ilen
        if ($ilen -gt 1 -and $val[0] -eq 0x00 -and $val[1] -lt 0x80) { return $null }  # non-minimal INTEGER
        if ($val[0] -eq 0x00) { $val = if ($ilen -gt 1) { $val[1..($ilen - 1)] } else { [byte[]]@(0x00) } }
        if ($val.Length -gt $keyBytes) { return $null }
        # audit C2-fix: the pad MUST be empty when val is already keyBytes long —
        # [byte[]]@((0x00) * 0) yields ONE zero byte (scalar x 0 = scalar 0 -> @(0)),
        # which injected a phantom 0x00 into every half and broke the whole chain.
        $padLen = $keyBytes - $val.Length
        $pad = if ($padLen -gt 0) { [byte[]]::new($padLen) } else { [byte[]]@() }
        $parts += , (Add-Bytes $pad $val)
    }
    if ($idx -ne $sig.Length) { return $null }
    return Add-Bytes $parts[0] $parts[1]
}

$manifestPath = Join-Path $PackDir 'pack.manifest.json'
$sigPath      = Join-Path $PackDir 'pack.manifest.json.sig'
if (-not (Test-Path $manifestPath)) { Fail "manifest missing: $manifestPath" }
if (-not (Test-Path $sigPath))      { Fail "signature missing: $sigPath" }
if (-not (Test-Path $PublicKeyPath)) { Fail "public key missing: $PublicKeyPath" }

$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json

# --- 1) structure (required fields; audit M1) ---
if ($manifest.manifest_version -ne 1)                { Fail "unsupported manifest_version" }
if (-not $manifest.pack_id)                          { Fail "manifest missing pack_id" }
if ($manifest.pack_id -cnotmatch '^(network|detection|hunt)\.[a-z0-9-]+$') { Fail "bad pack_id" }
if (-not $manifest.family)                           { Fail "manifest missing family" }
if ($manifest.version -notmatch '^\d+\.\d+\.\d+$')   { Fail "bad semver version" }
if ($manifest.issued -notmatch '^\d{4}-\d{2}-\d{2}$'){ Fail "bad issued date" }
if ($manifest.license -cnotmatch '^(CC-BY-4.0|LicenseRef-[A-Za-z0-9.-]+)$') { Fail "bad license identifier" }
if (-not $manifest.files -or $manifest.files.Count -eq 0) { Fail "manifest lists no files" }

# --- 2) freshness / anti-replay (audit H2) ---
$issued = [datetime]::ParseExact($manifest.issued, 'yyyy-MM-dd', $null)
if (-not $manifest.expires_hint_days) { Fail "manifest missing expires_hint_days (freshness required)" }
if ($Now.Date -gt $issued.AddDays([int]$manifest.expires_hint_days)) {
    Fail "manifest expired (issued $($manifest.issued) + $($manifest.expires_hint_days)d < $($Now.ToString('yyyy-MM-dd'))) - fetch a newer release"
}

# --- 3) per-file path safety + hash + size (audit H3, M3) ---
foreach ($f in $manifest.files) {
    if ($f.path -match '(\.\.|\\|:)' -or $f.path -match '^/') { Fail "unsafe path in manifest: $($f.path)" }
    $fp = Join-Path $PackDir $f.path
    if (-not (Test-Path $fp)) { Fail "listed file missing: $($f.path)" }
    $h = (Get-FileHash -Algorithm SHA256 $fp).Hash.ToLower()
    if ($h -ne $f.sha256.ToLower()) { Fail "SHA256 mismatch: $($f.path)" }
    if ((Get-Item $fp).Length -ne $f.size) { Fail "size mismatch: $($f.path)" }
}

# --- 4) import public key (manual SPKI parse: skip 26-byte P-256 prefix, 0x04 + X(32) + Y(32)) ---
$raw = (Get-Content $PublicKeyPath -Raw) -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\s', ''
$spki = [Convert]::FromBase64String($raw)
if ($spki.Length -ne 91 -or $spki[26] -ne 0x04) { Fail "unexpected public key format" }
$x = New-Object byte[] 32; $y = New-Object byte[] 32
[Array]::Copy($spki, 27, $x, 0, 32)
[Array]::Copy($spki, 59, $y, 0, 32)

$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
try {
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = $x; $q.Y = $y
    $p.Q = $q
    $ecdsa.ImportParameters($p)

    # --- 5) strict DER signature (audit C1: raw r||s rejected) + runtime-agnostic verify ---
    $sigBytes = [Convert]::FromBase64String((Get-Content $sigPath -Raw).Trim())
    $sigRaw = ConvertFrom-DerSignature $sigBytes 32
    if ($null -eq $sigRaw) { Fail "signature is not a valid DER ECDSA signature" }

    $data = [IO.File]::ReadAllBytes($manifestPath)
    $ok = $ecdsa.VerifyData($data, $sigRaw, [System.Security.Cryptography.HashAlgorithmName]::SHA256) # .NET Framework wants raw
    if (-not $ok) { $ok = $ecdsa.VerifyData($data, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256) } # .NET 8 wants DER
    if (-not $ok) { Fail "signature invalid" }
}
catch { Fail "verification error: $($_.Exception.Message)" }
finally { $ecdsa.Dispose() }

Write-Host "VERIFY PASS : $($manifest.pack_id) v$($manifest.version)"
exit 0
