#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end self test of the signing chain: sign -> verify (PASS) -> tamper -> verify (expected FAIL).
    Mirrors the simplewall Round-2 signer SelfTest discipline. Exit 0 = chain healthy.
#>
param(
    [Parameter(Mandatory = $true)][string]$KeysPath
)
$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("phsh-selftest-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    # temp pack
    [IO.File]::WriteAllText((Join-Path $tmp 'hello.txt'), "ph.sh packs selftest payload")
    $h = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp 'hello.txt')).Hash.ToLower()
    $m = [ordered]@{
        manifest_version = 1
        pack_id          = 'selftest.phsh'
        family           = 'test'
        version          = '0.0.0'
        min_app_version  = '0.0.0'
        issued           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
        license          = 'CC-BY-4.0'
        files            = @(@{ path = 'hello.txt'; sha256 = $h; size = 26 })
        sources          = @()
        expires_hint_days = 1
    }
    [IO.File]::WriteAllText((Join-Path $tmp 'pack.manifest.json'), ($m | ConvertTo-Json -Depth 5))

    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    # 1) sign
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tools 'sign_pack.ps1') -PackDir $tmp -KeysPath $KeysPath
    if ($LASTEXITCODE -ne 0) { throw "sign step failed" }

    # 2) verify -> must PASS
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tools 'verify_pack.ps1') -PackDir $tmp
    if ($LASTEXITCODE -ne 0) { throw "verify should have PASSED" }

    # 3) tamper payload -> verify must FAIL
    [IO.File]::WriteAllText((Join-Path $tmp 'hello.txt'), "ph.sh packs selftest payload TAMPERED")
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tools 'verify_pack.ps1') -PackDir $tmp 2>&1
    if ($LASTEXITCODE -eq 0) { throw "verify should have FAILED after tampering" }
    Write-Host "tamper detected as expected: $out"

    Write-Host "SELFTEST PASS : sign -> verify PASS -> tamper -> verify FAIL (chain healthy)"
    exit 0
}
catch {
    Write-Host "SELFTEST FAIL : $($_.Exception.Message)"
    exit 1
}
finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
