#Requires -Version 5.1
<#
.SYNOPSIS
    Signs a pack manifest (ECDSA P-256 / SHA-256, DER signature, Base64) and writes pack.manifest.json.sig next to it.
    Validates every listed file hash BEFORE signing (refuses to sign a manifest whose content does not match).
.NOTES
    Private key stays outside the repo (D:\CV\Github\.keys\packs-signing.json). Never copy it into CI.
#>
param(
    [Parameter(Mandatory = $true)][string]$PackDir,
    [Parameter(Mandatory = $true)][string]$KeysPath
)
$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $PackDir 'pack.manifest.json'
if (-not (Test-Path $manifestPath)) { throw "Manifest not found: $manifestPath" }
if (-not (Test-Path $KeysPath))     { throw "Key file not found: $KeysPath" }

$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.manifest_version -ne 1) { throw "Unsupported manifest_version: $($manifest.manifest_version)" }
if (-not $manifest.files -or $manifest.files.Count -eq 0) { throw "Manifest lists no files" }

# --- 1) verify content integrity before signing ---
foreach ($f in $manifest.files) {
    $fp = Join-Path $PackDir $f.path
    if (-not (Test-Path $fp)) { throw "Listed file missing: $($f.path)" }
    $h = (Get-FileHash -Algorithm SHA256 $fp).Hash.ToLower()
    if ($h -ne $f.sha256.ToLower()) { throw "SHA256 mismatch for $($f.path) - update manifest hashes first" }
}

# --- 2) load private key ---
$j = Get-Content $KeysPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($j.curve -ne 'P-256') { throw "Wrong curve: $($j.curve)" }
$ecdsa = New-Object System.Security.Cryptography.ECDsaCng
try {
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = [Convert]::FromBase64String($j.x)
    $q.Y = [Convert]::FromBase64String($j.y)
    $p.Q = $q
    $p.D = [Convert]::FromBase64String($j.d)
    $ecdsa.ImportParameters($p)

    # --- 3) sign exact manifest bytes ---
    $data = [IO.File]::ReadAllBytes($manifestPath)
    $sig  = $ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    [IO.File]::WriteAllText((Join-Path $PackDir 'pack.manifest.json.sig'), [Convert]::ToBase64String($sig))
}
finally { $ecdsa.Dispose() }

Write-Host "SIGN OK : $($manifest.pack_id) v$($manifest.version) -> pack.manifest.json.sig"
exit 0
