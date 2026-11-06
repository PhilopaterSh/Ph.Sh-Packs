#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a fresh NIST P-256 ECDSA keypair for Ph.Sh-Packs signing.
    Private key JSON -> file outside the repo (same field layout as simplewall-signing.json: curve/d/x/y/created).
    Public key PEM   -> tools\packs_public_key.pem (committed to the repo).
    Refuses to overwrite existing files. Run once.
#>
param(
    [Parameter(Mandatory = $true)][string]$KeysPath,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath
)
$ErrorActionPreference = 'Stop'

if (Test-Path $KeysPath)    { throw "Refusing to overwrite existing key file: $KeysPath" }
if (Test-Path $PublicKeyPath) { throw "Refusing to overwrite existing public key: $PublicKeyPath" }

# Cross-platform P-256 key creation (avoids the ECDsaCng P-521 default gotcha and
# the CNG export-policy dance entirely; works the same on Windows/Linux pwsh).
$ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $p = $ecdsa.ExportParameters($true)   # include private D
    if ($null -eq $p.D -or $p.D.Length -ne 32 -or $p.Q.X.Length -ne 32 -or $p.Q.Y.Length -ne 32) {
        throw "Unexpected key parameters (expected 32-byte P-256 components)"
    }

    # --- private key JSON (mirrors simplewall-signing.json field names) ---
    $priv = [ordered]@{
        curve   = 'P-256'
        d       = [Convert]::ToBase64String($p.D)
        x       = [Convert]::ToBase64String($p.Q.X)
        y       = [Convert]::ToBase64String($p.Q.Y)
        created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [IO.File]::WriteAllText($KeysPath, ($priv | ConvertTo-Json))

    # --- public SPKI -> PEM (fixed 26-byte P-256 SPKI prefix + 0x04 + X + Y = 91 bytes) ---
    $prefix = [byte[]](0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                       0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00)
    $spki = New-Object System.Collections.Generic.List[byte]
    foreach ($b in $prefix)  { $spki.Add($b) }
    $spki.Add(0x04)
    foreach ($b in $p.Q.X)   { $spki.Add($b) }
    foreach ($b in $p.Q.Y)   { $spki.Add($b) }
    $b64 = [Convert]::ToBase64String($spki.ToArray())
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    $pem = "-----BEGIN PUBLIC KEY-----`n" + ($lines -join "`n") + "`n-----END PUBLIC KEY-----`n"
    [IO.File]::WriteAllText($PublicKeyPath, $pem)
}
finally { $ecdsa.Dispose() }

Write-Host "KEYGEN OK"
Write-Host "  private : $KeysPath (keep outside all repos)"
Write-Host "  public  : $PublicKeyPath (committed)"
