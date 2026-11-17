#Requires -Version 5.1
<#
.SYNOPSIS
    Lints every pack in the repository: manifest structure + pack_id/family consistency +
    per-file hashes + sizes + freshness presence + manifest-coverage (every non-exempt file in the
    pack directory must be listed in the manifest - audit M2) + signature verification against the
    committed public key.
    Designed to run in CI with ZERO secrets (public key only). Exit 0 = all green.
#>
param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$ToolsDir = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
$failed = 0; $checked = 0

$manifests = Get-ChildItem -Path (Join-Path $RepoRoot 'packs') -Recurse -Filter 'pack.manifest.json'
if ($manifests.Count -eq 0) { Write-Host "LINT FAIL : no manifests found"; exit 1 }

foreach ($mfile in $manifests) {
    $packDir = $mfile.DirectoryName
    $m = Get-Content $mfile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $checked++
    $errors = @()

    # structure checks (schema equivalent, no external deps)
    if ($m.manifest_version -ne 1) { $errors += 'manifest_version must be 1' }
    if ($m.pack_id -cnotmatch '^(network|detection|hunt)\.[a-z0-9-]+$') { $errors += 'bad pack_id' }
    $familyFromDir = Split-Path (Split-Path $packDir -Parent) -Leaf
    if ($familyFromDir -ne $m.family) { $errors += "family '$($m.family)' != folder '$familyFromDir'" }
    if ($m.version -notmatch '^\d+\.\d+\.\d+$') { $errors += 'bad semver' }
    if ($m.issued -notmatch '^\d{4}-\d{2}-\d{2}$') { $errors += 'bad issued date' }
    if ($m.license -cnotmatch '^(CC-BY-4.0|LicenseRef-[A-Za-z0-9.-]+)$') { $errors += 'license must be CC-BY-4.0 or LicenseRef-<id>' }
    if (-not $m.files -or $m.files.Count -eq 0) { $errors += 'files empty' }
    if (-not $m.expires_hint_days) { $errors += 'expires_hint_days required (freshness contract)' }
    if ($m.sources.Count -eq 0 -and $m.version -ne '0.1.0') { $errors += 'sources empty (allowed only for placeholder v0.1.0 builds)' }

    # placeholders must be obvious
    if ($m.sources.Count -eq 0 -and (Select-String -Path (Join-Path $packDir '*.xml') -Pattern 'DOC-NET|192\.0\.2\.' -Quiet)) { }
    elseif ($m.sources.Count -eq 0) { $errors += 'no sources and no placeholder markers found' }

    # hashes + sizes + path safety (audit M3, H3)
    foreach ($f in $m.files) {
        if ($f.path -match '(\.\.|\\|:)' -or $f.path -match '^/') { $errors += "unsafe path: $($f.path)"; continue }
        $fp = Join-Path $packDir $f.path
        if (-not (Test-Path $fp)) { $errors += "missing file: $($f.path)"; continue }
        $h = (Get-FileHash -Algorithm SHA256 $fp).Hash.ToLower()
        if ($h -ne $f.sha256.ToLower()) { $errors += "sha256 mismatch: $($f.path)" }
        if ((Get-Item $fp).Length -ne $f.size) { $errors += "size mismatch: $($f.path)" }
    }

    # manifest coverage: every file in the pack dir except exempt docs must be in files[] (audit M2)
    $exempt = @('pack.manifest.json', 'pack.manifest.json.sig', 'notes.md')
    $onDisk = Get-ChildItem -Path $packDir -Recurse -File | ForEach-Object {
        $_.FullName.Substring($packDir.Length + 1).Replace('\', '/')
    } | Where-Object { $exempt -notcontains $_ -and $_ -notmatch '^notes\.md$' }
    $listed = @($m.files | ForEach-Object { $_.path })
    foreach ($f in $onDisk) {
        if ($listed -notcontains $f) { $errors += "unsigned file in pack dir (add to manifest or remove): $f" }
    }
    foreach ($f in $listed) {
        if ($onDisk -notcontains $f) { $errors += "manifest lists a file that does not exist on disk: $f" }
    }

    if ($errors.Count -gt 0) {
        $failed++
        Write-Host ("LINT FAIL [{0}]" -f $m.pack_id)
        $errors | ForEach-Object { Write-Host ("  - " + $_) }
        continue
    }

    # signature (only meaningful once signed; placeholder v0.1.0 signed too)
    $sigFile = Join-Path $packDir 'pack.manifest.json.sig'
    if (Test-Path $sigFile) {
        & (Join-Path $ToolsDir 'verify_pack.ps1') -PackDir $packDir | Out-Null
        if ($LASTEXITCODE -ne 0) { $failed++; Write-Host "LINT FAIL [$($m.pack_id)] - signature"; continue }
    } else {
        $failed++; Write-Host "LINT FAIL [$($m.pack_id)] - unsigned"; continue
    }

    Write-Host ("LINT OK   [{0} v{1}] ({2} files, {3} sources)" -f $m.pack_id, $m.version, $m.files.Count, $m.sources.Count)
}

Write-Host ("LINT SUMMARY : {0}/{1} packs green" -f ($checked - $failed), $checked)
if ($failed -gt 0) { exit 1 }
exit 0
