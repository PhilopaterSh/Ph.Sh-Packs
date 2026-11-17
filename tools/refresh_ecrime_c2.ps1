#Requires -Version 5.1
<#
.SYNOPSIS
    Refreshes packs/network/common-ecrime-c2 from the Emerging Threats Open botcc ruleset
    (free-use with attribution; ET aggregates Feodo Tracker C2 data upstream).

    Why ET botcc and not the raw feeds? (verified 2026-11-06)
      - feodotracker.abuse.ch public downloads frozen since ~2026-03-04 (all lists).
      - urlhaus.abuse.ch download endpoints return 410 Gone.
      - cinsscore.com is live (15k IPs) but prohibits redistribution - documented as a
        consumer-side source only, never embedded here.

    Pipeline: fetch -> extract IPv4 from [IP] rules -> drop reserved ranges -> dedupe ->
    regenerate rules.xml + manifest vNext (hashes, sources) -> save provenance copy.
    Signing stays MANUAL on purpose (private key never leaves the .keys\ directory):
      tools\sign_pack.ps1 -PackDir packs\network\common-ecrime-c2 -KeysPath ..\.keys\packs-signing.json
#>
param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$Version = '0.3.0',
    [int]$MaxEntries = 250
)
$ErrorActionPreference = 'Stop'

$packDir = Join-Path $RepoRoot 'packs\network\common-ecrime-c2'
$provDir = Join-Path $RepoRoot 'provenance'
New-Item -ItemType Directory -Force -Path $provDir | Out-Null

# --- 1) fetch ET Open botcc ---
$url = 'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-botcc.rules'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object Net.WebClient
$wc.Headers.Add('User-Agent', 'Ph.Sh-Packs/0.2 (+https://github.com/PhilopaterSh/Ph.Sh-Packs)')
$raw = $wc.DownloadString($url)
$wc.Dispose()
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
[IO.File]::WriteAllText((Join-Path $provDir ("et_botcc_" + $stamp + ".rules")), $raw)

# --- 2) extract + filter IPv4s ---
# Audit M4 fix: proper CIDR-based exclusion of special-use ranges ONLY (RFC 1112/1918/5737/6598/8190...
# and multicast/reserved). The previous top-octet blocklist wrongly dropped entire /8s (172/8 = Google, 192/8, 203/8).
function ConvertTo-IPv4Int([string]$ip) {
    $o = $ip.Split('.')
    if ($o.Count -ne 4) { return [long]0 }
    # int64 arithmetic: PS 5.1 -shl on uint32 overflows into negative int32 (audit-found bug)
    return ([long]$o[0] -shl 24) -bor ([long]$o[1] -shl 16) -bor ([long]$o[2] -shl 8) -bor [long]$o[3]
}
function Test-IpInCidr([string]$ip, [string]$cidr) {
    $net, $bits = $cidr.Split('/')
    $bits = [int]$bits
    $mask = if ($bits -eq 0) { [long]0 } else { ([long]0xFFFFFFFF -shl (32 - $bits)) -band [long]0xFFFFFFFF }
    return ((ConvertTo-IPv4Int $ip) -band $mask) -eq ((ConvertTo-IPv4Int $net) -band $mask)
}
$reservedCidrs = @(
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
)
$ips = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($raw, '\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]')) { [void]$ips.Add($m.Groups[1].Value) }
foreach ($m in [regex]::Matches($raw, 'content:"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"')) { [void]$ips.Add($m.Groups[1].Value) }

$filtered = @($ips | Where-Object {
    $ip = $_
    $ok = $true
    foreach ($c in $reservedCidrs) { if (Test-IpInCidr $ip $c) { $ok = $false; break } }
    $ok
} | Sort-Object)
if ($filtered.Count -eq 0) { throw "No usable IPs extracted - aborting (would not sign an empty pack)" }
if ($filtered.Count -gt $MaxEntries) { $filtered = $filtered[0..($MaxEntries - 1)] }

# --- 3) regenerate rules.xml (simplewall internal profile v6 blocklist format) ---
$ts = [int][double]::Parse((Get-Date -UFormat %s))
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('<?xml version="1.0" ?>')
$lines.Add('<!-- Ph.Sh-Packs :: network/common-ecrime-c2 v' + $Version + ' -->')
$lines.Add('<!-- Format: simplewall internal profile (version 6) -->')
$lines.Add('<!-- Source: Emerging Threats Open botcc (free-use, attribution required) - feeds ET botcc aggregate Feodo Tracker data -->')
$lines.Add('<root timestamp="' + $ts + '" type="4" version="6">')
$lines.Add("`t<rules_blocklist>")
foreach ($ip in $filtered) { $lines.Add("`t`t" + '<item name="phsh_etbotcc_' + ($ip -replace '\.', '-') + '" rule="' + $ip + '" />') }
$lines.Add("`t</rules_blocklist>")
$lines.Add('</root>')
[IO.File]::WriteAllText((Join-Path $packDir 'rules.xml'), ($lines -join "`n") + "`n")   # LF only - .gitattributes enforces eol=lf; hashes must match repo bytes

# --- 4) regenerate manifest ---
$rulesPath = Join-Path $packDir 'rules.xml'
$hash = (Get-FileHash -Algorithm SHA256 $rulesPath).Hash.ToLower()
$size = (Get-Item $rulesPath).Length
# Audit M5 fix: anchor the upstream fetch - record the SHA-256 of the exact bytes pulled, so the
# manual diff-review before signing has a pinned reference (and a poisoned fetch is detectable).
$rawHash = (Get-FileHash -Algorithm SHA256 -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($raw)))).Hash.ToLower()
$m = [ordered]@{
    manifest_version = 1
    pack_id          = 'network.common-ecrime-c2'
    family           = 'network'
    version          = $Version
    min_app_version  = '3.7.0-r2'
    issued           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    license          = 'LicenseRef-ETOpen-1.1'
    files            = @(
        @{ path = 'rules.xml'; sha256 = $hash; size = $size },
        @{ path = 'LICENSE-ETOpen.txt'; sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $packDir 'LICENSE-ETOpen.txt')).Hash.ToLower(); size = (Get-Item (Join-Path $packDir 'LICENSE-ETOpen.txt')).Length }
    )
    sources          = @(
        @{ name = 'Emerging Threats Open - botcc ruleset'; url = 'https://rules.emergingthreats.net/'; retrieved = $stamp; license = 'LicenseRef-ETOpen-1.1 (redistribution permitted with copyright notice)'; upstream_sha256 = $rawHash },
        @{ name = 'Upstream: abuse.ch Feodo Tracker data via ET'; url = 'https://feodotracker.abuse.ch/'; retrieved = $stamp }
    )
    expires_hint_days = 14
}
# PS 5.1 ConvertTo-Json emits CRLF inside its output - normalize to LF BEFORE writing,
# otherwise the signature covers CRLF bytes while the repo stores LF (CI verify breaks).
$json = ($m | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[IO.File]::WriteAllText((Join-Path $packDir 'pack.manifest.json'), $json)

Write-Host ("REFRESH OK : {0} IPs -> rules.xml ({1} bytes, sha256 {2})" -f $filtered.Count, $size, $hash.Substring(0, 16))
Write-Host "NEXT : MANDATORY diff review of rules.xml vs the previous signed pack (audit M5), then sign_pack.ps1 -> verify_pack.ps1 (manual, local key)"
exit 0
