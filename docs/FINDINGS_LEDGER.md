# Findings Ledger

Append-only ledger of audit findings and their resolution. Every row cites the audit finding ID
(`audit-2026-11-17.md`) and the commit/PR that resolves it. Verdicts are hypotheses until a
reproduction lands — blocking claims require an empirical repro (goldfish-gate rule).

| # | Date | Finding | Severity | Status | Resolution / Evidence |
|---|---|---|---|---|---|
| A1 | 2026-11-17 | C1 — signatures raw r||s, not DER; openssl rejects; stated goal broken | CRITICAL | **FIXED (Batch-0, root cause corrected during goldfish loop)** | TWO layers: (1) .NET Framework SignData returns raw r||s → sign_pack now normalizes to DER; (2) the audit's "openssl rejects" was itself TWO artifacts: .sig files are **Base64 text** while `openssl -signature` needs **binary DER** (the audit PoC converted to DER binary before verifying), AND verify_pack's DER→raw parser injected a phantom 0x00 per half (`[byte[]]@((0x00)*0)` = one byte, not empty). Both fixed: DER normalization + corrected parser + base64-decode before every openssl step (selftest/CI/README) + python-ecdsa (sigdecode_der) library-verifies the committed signatures |
| A2 | 2026-11-17 | H1 — no out-of-band trust anchor; release had zero assets | HIGH | **PARTIAL → Batch-0** | Key fingerprint published in README + release body (owner must also pin it off-GitHub, e.g. profile/site); releases now ship assets; git commit signing = owner TODO |
| A3 | 2026-11-17 | H2 — no replay/freshness enforcement (expires_hint_days decorative) | HIGH | **FIXED (Batch-0)** | verify_pack fails on `issued + expires_hint_days < today`; selftest negative case proves rejection |
| A4 | 2026-11-17 | H3 — path traversal accepted end-to-end | HIGH | **FIXED (Batch-0)** | `..`/`\`/`:`/leading-`/` rejected in sign_pack, verify_pack, lint; selftest negative case; schema note |
| A5 | 2026-11-17 | M1 — verify without required-fields/schema checks | MEDIUM | **FIXED (Batch-0)** | verify_pack enforces structure before content checks |
| A6 | 2026-11-17 | M2 — unsigned files can ship in pack dir (lint no coverage) | MEDIUM | **FIXED (Batch-0)** | lint enforces dir contents == files[] (exempt: manifest, sig, notes.md) both directions |
| A7 | 2026-11-17 | M3 — `size` never validated; selftest wrote wrong size | MEDIUM | **FIXED (Batch-0)** | sign+verify+lint enforce size; selftest computes exact payload length |
| A8 | 2026-11-17 | M4 — refresh dropped whole /8s (172/8 etc.) vs documented scope | MEDIUM | **FIXED (Batch-0)** | proper CIDR exclusion list of special-use ranges only |
| A9 | 2026-11-17 | M5 — upstream fetch unanchored (poisoned feed → signed) | MEDIUM | **PARTIAL (Batch-0)** | upstream sha256 recorded in manifest sources; mandatory diff-review output reminder; full dual-source compare deferred (E1) |
| A10 | 2026-11-17 | M6 — ET-derived content mislabeled CC-BY-4.0 | MEDIUM | **FIXED (Batch-0)** | `LicenseRef-ETOpen-1.1` + LICENSE-ETOpen.txt shipped in-pack; LICENSE-RULES.md rewritten per-origin |
| A11 | 2026-11-17 | M7 — plaintext key, no key_id/rotation | MEDIUM | **OPEN → E3** | KEY_ROTATION.md drafted (Batch-0); at-rest encryption + key_id in manifest v2 deferred |
| A12 | 2026-11-17 | L1 — selftest Windows-only, not in CI | LOW | **FIXED (Batch-0)** | cross-platform child-PowerShell; negative cases incl. expiry/traversal/raw-sig; CI step |
| A13 | 2026-11-17 | L2 — CI hygiene (unpinned action/deps, no concurrency) | LOW | **FIXED (Batch-0)** | checkout SHA-pinned (v4.2.2), yara-x==1.23.0 pinned, sigma-cli/pysigma pinned, concurrency group |
| A14 | 2026-11-17 | L3 — YARA gate theater: Sigma never validated | LOW | **FIXED (Batch-0)** | sigma-cli `sigma check` step in CI on all hunt .yml |
| A15 | 2026-11-17 | L4 — Sigma quality (schtasks "Remote" title wrong; `status: stable` unearned) | LOW | **FIXED (Batch-0)** | retitled, `status: test`, license/modified meta added |
| A16 | 2026-11-17 | L5 — README drift (P0 status, local-only links, TOFU omitted) | LOW | **FIXED (Batch-0)** | README rewritten: honest TOFU section, fingerprint, openssl third-party verify instructions |
| A17 | 2026-11-17 | L6 — TRIAGE_QUEUE records lack hashes | LOW | **OPEN → E0** | to be enforced when the queue pipeline goes live with real samples |
| A18 | 2026-11-17 | L7 — tag behind HEAD; release without assets | LOW | **PARTIAL (Batch-0) → completes at push** | DER chain verified 3-way (openssl/python-ecdsa/verify_pack); tag `v0.3.0-p2` + release assets ship at the Batch-0 push — pre-commit "FIXED" claim was itself unverifiable (goldfish D1) |
| A19 | 2026-11-17 | Lab C1 — drafting heuristic produces OS fingerprints (1/12 yield) | CRITICAL | **OPEN → E2** | selection-policy rewrite queued (deny-list + tiers + UTF-16 + hashes) before first real detection pack |
| A20 | 2026-11-17 | Lab C2 — 10-binary corpus labeled absolute PASS | CRITICAL | **OPEN → E2** | verdict renamed plan + ≥1k diverse corpus queued with E2 |
| A21 | 2026-11-17 | Strategy — blueprint stale; 3 conflicting cadences; missing trust-ops docs | HIGH | **PARTIAL (Batch-0)** | cadence resolved (machine weekly / human monthly / ecrime biweekly); blueprint rewrite scheduled E1; runbooks drafted Batch-0 |

Rule: a row moves to FIXED only with the evidence column pointing at a reproduction (test, PoC, CI step) — not at an intention.
