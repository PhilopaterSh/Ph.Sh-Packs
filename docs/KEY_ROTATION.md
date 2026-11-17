# Key Rotation Runbook (Ph.Sh-Packs)

The signing key (`D:\CV\Github\.keys\packs-signing.json`, ECDSA P-256) is the root of the pack trust
chain. Its public half is embedded in the repo (`tools/packs_public_key.pem`) and pinned out-of-band by
its fingerprint — published in README and the release body:

```
SPKI DER SHA-256: f9153fc7d55bfa3c79eea23c771bce764e34f2f53db1aa4d87e9342bc456f115
```

## When to rotate

1. **Suspected key compromise** (the .keys\ file was exposed, copied, or the dev box is suspect) — rotate immediately.
2. **Planned periodic rotation** (recommended: yearly, or at each major manifest_version bump).
3. **Organizational change** (maintainer handover — see bus-factor note in the project hub).

## Rotation procedure (dual-key overlap)

1. Generate the new keypair:
   ```powershell
   tools\generate_packs_key.ps1 -KeysPath "D:\CV\Github\.keys\packs-signing-v2.json" -PublicKeyPath "tools\packs_public_key_v2.pem"
   ```
2. Announce **before** shipping v2-signed packs: a release note containing BOTH fingerprints, the
   cut-over release version, and the old key's revocation date. Never rotate silently.
3. Ship an overlap window (≥2 releases) where packs are **signed with both keys** (two .sig files:
   `pack.manifest.json.sig` + `pack.manifest.json.sig.v1`) so existing verifiers keep passing while
   new ones adopt `packs_public_key_v2.pem`.
4. Update `verify_pack.ps1`/README to the v2 key; keep v1 verification available until the overlap
   window closes.
5. Cut-over release: publish the new fingerprint out-of-band (release body + owner's profile/site),
   delete `packs_public_key.pem` v1 in the same commit that stops v1 signatures.
6. Archive the old private key (or destroy it) and record the rotation in `docs/FINDINGS_LEDGER.md`.

## If the old key must be treated as compromised

Skip the overlap window: cut over in ONE release, state the compromise window in the release note,
and mark every pack released inside that window as suspect (re-sign + re-release at a bumped version —
see `BAD_PACK_INCIDENT.md`).
