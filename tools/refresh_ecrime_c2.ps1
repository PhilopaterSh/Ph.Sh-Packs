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
    [string]$Version = '0.2.0',
    [int]$MaxEntries = 250,
    [int]$MinOctet = 1   # drop leading-octet 0 (0.0.0.0/8) and similar junk early
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
$reservedTopOctets = @(0, 10, 127, 169, 172, 192, 198, 203, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255)
$ips = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($raw, '\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]')) { [void]$ips.Add($m.Groups[1].Value) }
foreach ($m in [regex]::Matches($raw, 'content:"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"')) { [void]$ips.Add($m.Groups[1].Value) }

$filtered = @($ips | Where-Object {
    $o = $_.Split('.')
    ($o.Count -eq 4) -and
    ([int]$o[0] -ge $MinOctet) -and
    (-not $reservedTopOctets.Contains([int]$o[0])) -and
    (([int]$o[1]) -ne 100 -or [int]$o[0] -ne 100) -and   # drop 100.64.0.0/10 CGNAT partial guard
    (([int]$o[0]) -ne 100 -or [int]$o[1] -lt 64 -or [int]$o[1] -gt 127)
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
$m = [ordered]@{
    manifest_version = 1
    pack_id          = 'network.common-ecrime-c2'
    family           = 'network'
    version          = $Version
    min_app_version  = '3.7.0-r2'
    issued           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    license          = 'CC-BY-4.0'
    files            = @(@{ path = 'rules.xml'; sha256 = $hash; size = $size })
    sources          = @(
        @{ name = 'Emerging Threats Open - botcc ruleset'; url = 'https://rules.emergingthreats.net/'; retrieved = $stamp; license = 'ETOpen free-use, attribution required' },
        @{ name = 'Upstream: abuse.ch Feodo Tracker data via ET'; url = 'https://feodotracker.abuse.ch/'; retrieved = $stamp }
    )
    expires_hint_days = 14
}
[IO.File]::WriteAllText((Join-Path $packDir 'pack.manifest.json'), ($m | ConvertTo-Json -Depth 6))

Write-Host ("REFRESH OK : {0} IPs -> rules.xml ({1} bytes, sha256 {2})" -f $filtered.Count, $size, $hash.Substring(0, 16))
Write-Host "NEXT : sign_pack.ps1 -> verify_pack.ps1 (manual, local key)"
exit 0
