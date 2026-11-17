#Requires -Version 5.1
<#
.SYNOPSIS
    Signs a pack manifest (ECDSA P-256 / SHA-256, DER-encoded signature per RFC 5758) and writes pack.manifest.json.sig next to it.
    Validates every listed file hash BEFORE signing (refuses to sign a manifest whose content does not match).
.NOTES
    Audit fix C1 (2026-11-17): .NET Framework's ECDsa.SignData returns a raw 64-byte r||s blob while
    .NET 8 returns DER - raw is rejected by openssl/go/python third-party verifiers. We now normalize
    every signature to DER regardless of runtime. A third party verifies with plain openssl
    (.sig is Base64 text - decode to binary DER first):
      base64 -d pack.manifest.json.sig > sig.der
      openssl dgst -sha256 -verify packs_public_key.pem -signature sig.der pack.manifest.json
    Private key stays outside the repo (D:\CV\Github\.keys\packs-signing.json). Never copy it into CI.
#>
param(
    [Parameter(Mandatory = $true)][string]$PackDir,
    [Parameter(Mandatory = $true)][string]$KeysPath
)
$ErrorActionPreference = 'Stop'

function Add-Bytes([byte[]]$a, [byte[]]$b) {
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($x in $a) { $out.Add($x) }
    foreach ($x in $b) { $out.Add($x) }
    return $out.ToArray()
}

# Minimal big-endian DER INTEGER for a 256-bit value: strip leading zeros, prepend 0x00 if high bit set.
function ConvertTo-DerInteger([byte[]]$v) {
    $i = 0
    while ($i -lt $v.Length -and $v[$i] -eq 0x00) { $i++ }
    $body = if ($i -lt $v.Length) { $v[$i..($v.Length - 1)] } else { [byte[]]@(0x00) }
    if ($body[0] -ge 0x80) { $body = Add-Bytes ([byte[]]@(0x00)) $body }
    return Add-Bytes ([byte[]]@(0x02, [byte]$body.Length)) $body
}

# Detect DER (SEQUENCE of two INTEGERs) vs raw r||s; always return DER.
function ConvertTo-DerSignature([byte[]]$sig, [int]$keyBytes) {
    if ($sig.Length -ge 8 -and $sig[0] -eq 0x30 -and $sig[1] -eq ($sig.Length - 2)) {
        return $sig   # already DER (e.g. .NET 8 runtime)
    }
    if ($sig.Length -ne (2 * $keyBytes)) { throw "Signature is neither DER nor raw r||s (len=$($sig.Length))" }
    $r = $sig[0..($keyBytes - 1)]
    $s = $sig[$keyBytes..((2 * $keyBytes) - 1)]
    $payload = Add-Bytes (ConvertTo-DerInteger $r) (ConvertTo-DerInteger $s)
    return Add-Bytes ([byte[]]@(0x30, [byte]$payload.Length)) $payload
}

$manifestPath = Join-Path $PackDir 'pack.manifest.json'
if (-not (Test-Path $manifestPath)) { throw "Manifest not found: $manifestPath" }
if (-not (Test-Path $KeysPath))     { throw "Key file not found: $KeysPath" }

$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.manifest_version -ne 1) { throw "Unsupported manifest_version: $($manifest.manifest_version)" }
if (-not $manifest.files -or $manifest.files.Count -eq 0) { throw "Manifest lists no files" }

# --- 1) verify content integrity before signing ---
foreach ($f in $manifest.files) {
    if ($f.path -match '(\.\.|\\|:)' -or $f.path -match '^/') { throw "Unsafe path in manifest: $($f.path)" }
    $fp = Join-Path $PackDir $f.path
    if (-not (Test-Path $fp)) { throw "Listed file missing: $($f.path)" }
    $h = (Get-FileHash -Algorithm SHA256 $fp).Hash.ToLower()
    if ($h -ne $f.sha256.ToLower()) { throw "SHA256 mismatch for $($f.path) - update manifest hashes first" }
    if ((Get-Item $fp).Length -ne $f.size) { throw "Size mismatch for $($f.path) - update manifest first" }
}

# --- 2) load private key ---
$j = Get-Content $KeysPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($j.curve -ne 'P-256') { throw "Wrong curve: $($j.curve)" }
$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
try {
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = [Convert]::FromBase64String($j.x)
    $q.Y = [Convert]::FromBase64String($j.y)
    $p.Q = $q
    $p.D = [Convert]::FromBase64String($j.d)
    $ecdsa.ImportParameters($p)

    # --- 3) sign exact manifest bytes, normalize to DER ---
    $data = [IO.File]::ReadAllBytes($manifestPath)
    $sig  = $ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $der  = ConvertTo-DerSignature $sig 32
    [IO.File]::WriteAllText((Join-Path $PackDir 'pack.manifest.json.sig'), [Convert]::ToBase64String($der))
}
finally { $ecdsa.Dispose() }

Write-Host "SIGN OK (DER) : $($manifest.pack_id) v$($manifest.version) -> pack.manifest.json.sig"
exit 0
