#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end self test of the signing chain. Two modes:
    - FULL (default, -KeysPath given): sign -> verify (PASS) -> tamper (payload, expiry, traversal,
      raw-sig) -> verify (expected FAIL in every case) + openssl cross-check when available.
    - VERIFY-ONLY (-VerifyOnly, or no -KeysPath): runs the key-free negative battery against the
      committed public key using garbage signatures - structure/freshness/path/size/case checks all
      fire BEFORE signature verification (verify_pack.ps1 stages 1-3), so every case is testable
      without a private key. This is the CI mode (audit goldfish B1: CI has no key and must not
      invoke the sign path).
    Cross-platform (Windows PowerShell 5.1 / pwsh on Linux CI). Exit 0 = chain healthy.
#>
param(
    [string]$KeysPath,
    [switch]$VerifyOnly,
    [switch]$SkipOpenssl
)
$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot

# runtime-appropriate child PowerShell (audit L1: hardcoded powershell.exe broke Linux CI)
$psExe = if ($env:OS -eq 'Windows_NT') { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
         elseif ($PSHOME) { (Join-Path $PSHOME 'pwsh') }
         else { 'pwsh' }

$fullMode = -not $VerifyOnly -and $KeysPath
if ($VerifyOnly) { Write-Host "SELFTEST MODE : verify-only (no private key required)" }
elseif (-not $KeysPath) { Write-Host "SELFTEST MODE : verify-only (no -KeysPath given)" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("phsh-selftest-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

function Invoke-ChildPs([string]$script, [string[]]$argList) {
    # NOTE: the param must NOT be named $args (reserved automatic variable - splatting silently ignores it)
    $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $script @argList 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host "  child: $_" }
    return $code
}

function Write-Manifest([hashtable]$m, [string]$dir) {
    $json = ($m | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $dir 'pack.manifest.json'), $json)
}

function Write-GarbageSig([string]$dir) {
    # 64 zero bytes = the canonical "raw r||s" shape; ConvertFrom-DerSignature must reject it
    [IO.File]::WriteAllText((Join-Path $dir 'pack.manifest.json.sig'), [Convert]::ToBase64String((New-Object byte[] 64)))
}

try {
    # temp pack: payload exactly 26 bytes so the old selftest's size lie (audit M3) can never recur silently
    $payload = "ph.sh packs selftest payload"
    [IO.File]::WriteAllText((Join-Path $tmp 'hello.txt'), $payload)
    $payloadBytes = [Text.Encoding]::UTF8.GetByteCount($payload)
    $h = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp 'hello.txt')).Hash.ToLower()
    $issued = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    # C-2 fix: schema caps expires_hint_days at 365 - the selftest must respect its own schema
    $m = [ordered]@{
        manifest_version  = 1
        pack_id           = 'network.selftest-phsh'
        family            = 'network'
        version           = '0.0.0'
        min_app_version   = '0.0.0'
        issued            = $issued
        license           = 'CC-BY-4.0'
        files             = @(@{ path = 'hello.txt'; sha256 = $h; size = $payloadBytes })
        sources           = @()
        expires_hint_days = 365
    }

    if ($fullMode) {
        # ---------- FULL MODE (private key available) ----------
        Write-Manifest $m $tmp
        # 1) sign
        if ((Invoke-ChildPs (Join-Path $tools 'sign_pack.ps1') @('-PackDir', $tmp, '-KeysPath', $KeysPath)) -ne 0) { throw "sign step failed" }

        # 2) verify -> must PASS
        if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -ne 0) { throw "verify should have PASSED" }

        # 3) tamper payload -> must FAIL
        [IO.File]::WriteAllText((Join-Path $tmp 'hello.txt'), "ph.sh packs selftest payload TAMPERED")
        if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify should have FAILED after payload tamper" }
        Write-Host "negative case OK : payload tamper rejected"

        # restore, then tamper freshness (audit H2) -> must FAIL
        [IO.File]::WriteAllText((Join-Path $tmp 'hello.txt'), $payload)
        $m.issued = '2020-01-01'; $m.expires_hint_days = 1
        Write-Manifest $m $tmp
        if ((Invoke-ChildPs (Join-Path $tools 'sign_pack.ps1') @('-PackDir', $tmp, '-KeysPath', $KeysPath)) -ne 0) { throw "expired-sign step failed" }
        if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify should have FAILED on expired manifest" }
        Write-Host "negative case OK : expired manifest rejected (anti-replay)"

        # path traversal (audit H3) -> sign must REFUSE, verify must FAIL
        # (EAP=Continue here: the child's expected refusal writes to stderr, and 2>&1 under EAP=Stop
        #  would otherwise make the PARENT throw on the expected error record)
        $m.issued = $issued; $m.expires_hint_days = 365
        $m.files = @(@{ path = '../outside.txt'; sha256 = $h; size = $payloadBytes })
        Write-Manifest $m $tmp
        $eap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tools 'sign_pack.ps1') -PackDir $tmp -KeysPath $KeysPath 2>&1
        $ErrorActionPreference = $eap
        if ($LASTEXITCODE -eq 0) { throw "sign should have REFUSED a traversal path" }
        Write-Host "negative case OK : traversal path refused at sign"
        if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify should have FAILED on traversal path" }
        Write-Host "negative case OK : traversal path rejected at verify"

        # raw (non-DER) signature must be rejected (audit C1) - craft a fake raw 64-byte blob
        $m.files = @(@{ path = 'hello.txt'; sha256 = $h; size = $payloadBytes })
        Write-Manifest $m $tmp
        Write-GarbageSig $tmp
        if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify should have REJECTED a raw non-DER signature" }
        Write-Host "negative case OK : raw non-DER signature rejected"

        # 4) openssl cross-check (audit C1: third-party standard tooling must accept DER) - needs a real signed manifest
        if ((Invoke-ChildPs (Join-Path $tools 'sign_pack.ps1') @('-PackDir', $tmp, '-KeysPath', $KeysPath)) -ne 0) { throw "final sign failed" }
        $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
        if (-not $SkipOpenssl -and $openssl) {
            $pem = Join-Path $tools 'packs_public_key.pem'
            # .sig is Base64 text; openssl -signature expects BINARY DER - decode first (audit root-cause #2)
            [IO.File]::WriteAllBytes((Join-Path $tmp 'sig.der'), [Convert]::FromBase64String((Get-Content (Join-Path $tmp 'pack.manifest.json.sig') -Raw).Trim()))
            $res = & $openssl dgst -sha256 -verify $pem -signature (Join-Path $tmp 'sig.der') (Join-Path $tmp 'pack.manifest.json') 2>&1
            if ($LASTEXITCODE -ne 0 -or "$res" -notmatch 'Verified OK') { throw "openssl cross-check FAILED: $res" }
            Write-Host "openssl cross-check OK : third-party verification accepts DER signatures (after base64 decode)"
        }
        elseif (-not $SkipOpenssl) { Write-Host "openssl not found in PATH - cross-check skipped (CI includes it)" }

        Write-Host "SELFTEST PASS (full) : sign -> verify PASS -> tamper/expiry/traversal/raw-sig rejected -> openssl OK"
        exit 0
    }

    # ---------- VERIFY-ONLY MODE (no private key; goldfish B1: the CI path) ----------
    # Garbage signature throughout: stages 1-3 (structure/freshness/path/size) fire BEFORE the
    # signature stage, so each negative case below is attributable to its own check.
    $failures = 0

    # a) fully valid manifest + garbage sig -> must FAIL at the signature stage (enforcement proof)
    Write-Manifest $m $tmp
    Write-GarbageSig $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted a garbage signature" }
    Write-Host "negative case OK : garbage signature rejected (no private key needed)"
    $failures++

    # b) expired manifest -> must FAIL at freshness (fires before signature)
    $m.issued = '2020-01-01'; $m.expires_hint_days = 14
    Write-Manifest $m $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted an expired manifest" }
    Write-Host "negative case OK : expired manifest rejected (anti-replay, key-free)"
    $failures++

    # c) traversal path -> must FAIL at path safety
    $m.issued = $issued; $m.expires_hint_days = 365
    $m.files = @(@{ path = '../outside.txt'; sha256 = $h; size = $payloadBytes })
    Write-Manifest $m $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted a traversal path" }
    Write-Host "negative case OK : traversal path rejected (key-free)"
    $failures++

    # d) missing files[] -> must FAIL at structure
    $m.files = $null
    Write-Manifest $m $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted a manifest without files[]" }
    Write-Host "negative case OK : missing files[] rejected (key-free)"
    $failures++

    # e) wrong size -> must FAIL at size check (hash correct, size off by one)
    $m.files = @(@{ path = 'hello.txt'; sha256 = $h; size = $payloadBytes + 1 })
    Write-Manifest $m $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted a wrong size" }
    Write-Host "negative case OK : size mismatch rejected (key-free)"
    $failures++

    # f) case-violating pack_id (goldfish C-1: -notmatch was case-insensitive) -> must FAIL
    $m.files = @(@{ path = 'hello.txt'; sha256 = $h; size = $payloadBytes })
    $m.pack_id = 'network.Selftest-Phsh'
    Write-Manifest $m $tmp
    if ((Invoke-ChildPs (Join-Path $tools 'verify_pack.ps1') @('-PackDir', $tmp)) -eq 0) { throw "verify accepted a case-violating pack_id" }
    Write-Host "negative case OK : case-violating pack_id rejected (key-free)"
    $failures++

    Write-Host "SELFTEST PASS (verify-only) : $failures negative cases rejected without a private key"
    exit 0
}
catch {
    Write-Host "SELFTEST FAIL : $($_.Exception.Message)"
    exit 1
}
finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
