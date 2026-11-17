# Bad Signed Pack — Incident Runbook

A signed pack that turns out to be wrong (false positives blocking benign software, poisoned upstream
data, a malicious rule) is this project's worst-case incident: the signature that proves authenticity
also spreads the mistake. Respond on the clock, not on the calendar.

## Triage (first 30 minutes)

1. **Confirm** — reproduce the problem against the signed artifact (not a working-tree copy).
   If it can't be reproduced, it's a hypothesis: log it, don't escalate.
2. **Classify**:
   - **FP** (benign flagged / bad IP) → retire + re-release path below.
   - **Poisoned content** (upstream data was wrong and we signed it) → retire + re-release + post-mortem
     on the source pipeline (check `upstream_sha256` anchoring).
   - **Signing-chain compromise** (signatures we didn't make) → key compromise → `KEY_ROTATION.md`
     immediate path, and mark every pack inside the suspected window as suspect.

## Retire + re-release (the ClamAV/Talos pattern)

1. **Do not edit the old pack silently.** Bump the version and publish a corrective release:
   `vX.Y.(Z+1)` with the offending entries removed. The corrective manifest carries the same pack_id —
   verifiers that enforce freshness (`verify_pack.ps1` does since Batch-0) will refuse the stale one.
2. **Announce** in the release note: what was wrong, the affected version range, the fix version.
   For consumer-impacting FPs: also an issue tagged `fp-incident`.
3. **Restore-if-wrong** rule (Talos precedent): if the retired entries turn out to be correct after
   all, re-adding them later is acceptable — retirement is reversible, silent staleness is not.
4. **Feed the FP channel**: every incident produces a `fp-incident` issue with the reproduction steps;
   post-mortem (what let it through: corpus gap? refresh bug? review miss?) within 7 days, findings
   appended to `docs/FINDINGS_LEDGER.md`.

## Prevention hooks this runbook relies on

- `expires_hint_days` — stale packs are refused by verifiers even if nobody notices the incident.
- `upstream_sha256` in manifest sources — the exact upstream bytes that produced the pack are provable.
- Manual diff review before signing (`refresh_ecrime_c2.ps1` prints the reminder) — the human gate is
  where incidents are caught before release, not after.
