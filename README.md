# Ph.Sh-Packs

**قواعد أمنية نقيّة موقّعة** — detection/hunt/network packs فوق سلسلة ثقة ECDSA P-256. لا درايفرات، لا توقيع مايكروسوفت، لا حيل — محتوى وتوقيع فقط.

**الحالة:** v0.3.0-p2 — Batch-0 security hardening landed (DER signatures, freshness enforcement, path-safety, manifest coverage, per-pack licensing). Trust-model audit 2026-11-17: `docs/FINDINGS_LEDGER.md`.

## Trust model — read this honestly (TOFU)

```
pack.manifest.json  ──(ECDSA P-256 / SHA-256, DER)──►  pack.manifest.json.sig
        │ sha256 + size لكل ملف داخل الـ manifest               │ يُتحقق منه بالمفتاح العام المضمّن
        ▼                                                       ▼
  محتوى الحزمة                                    tools/packs_public_key.pem
```

**What this protects you from:** a tampered mirror or CDN cannot alter pack content or manifests without detection — signatures are DER-encoded and verify with standard tooling (openssl, Go `ecdsa.VerifyASN1`, python-ecdsa). Manifests carry an `issued` date and `expires_hint_days`; verifiers reject expired manifests (anti-replay/downgrade). Unsafe paths are rejected.

**What this does NOT protect you from (be honest — this is Trust-On-First-Use):** the public key is committed **in this same repository**. If someone compromises the repo itself, they could ship a new key + re-signed malicious packs and CI would stay green. Mitigations and their status:

- **Out-of-band key fingerprint** — pin this fingerprint in your own records; it must never change unless announced here first:

  ```
  SPKI DER SHA-256: f9153fc7d55bfa3c79eea23c771bce764e34f2f53db1aa4d87e9342bc456f115
  ```

  Verify locally: `openssl pkey -pubin -in packs_public_key.pem -outform DER | openssl dgst -sha256`
- **Git commit signing:** planned (owner-side); currently commits are NOT signed — check the audit ledger.
- **Releases carry assets** (pack zips + signatures + SHA256SUMS) so the tag itself is a verifiable artifact, not just a repo state.

**Key rotation:** runbook at `docs/KEY_ROTATION.md`; incident response for a bad signed pack at `docs/BAD_PACK_INCIDENT.md`.

## عائلات الحزم

| العائلة | المحتوى | المستهلك |
|---|---|---|
| `network.` | قواعد بتنسيق simplewall internal profile (متوافقة مع فورك simplewall — Round 3) | simplewall fork |
| `detection.` | YARA-X (.yar) + ClamAV (.ndb/.hdb) | clamscan / yara-x |
| `hunt.` | Sigma rules (متوافقة مع Hayabusa) | blue-team / DFIR |

## Third-party verification (no repo tooling required)

**IMPORTANT: `.sig` files are Base64-encoded DER — decode before feeding openssl.**

```bash
# 1. check the key fingerprint matches the value published above (and off-band)
openssl pkey -pubin -in packs_public_key.pem -outform DER | openssl dgst -sha256
# 2. verify a manifest signature (decode base64 -> binary DER first! decode OUTSIDE the pack dir)
base64 -d pack.manifest.json.sig > /tmp/sig.der
openssl dgst -sha256 -verify packs_public_key.pem -signature /tmp/sig.der pack.manifest.json
#    → "Verified OK"
# 3. check content integrity
sha256sum -c <(jq -r '.files[] | "\(.sha256)  \(.path)"' pack.manifest.json)
# 4. check freshness: issued + expires_hint_days must cover today
```

## الاستخدام (repo tooling)

```powershell
# فحص صحة السلسلة (sign → verify PASS → tamper/expiry/traversal/raw-sig rejected → openssl cross-check)
tools\selftest.ps1 -KeysPath "D:\CV\Github\.keys\packs-signing.json"

# توقيع حزمة (يتحقق من الـ hashes + sizes داخلها قبل التوقيع؛ التوقيع DER دائماً)
tools\sign_pack.ps1 -PackDir "packs\network\common-ecrime-c2" -KeysPath "D:\CV\Github\.keys\packs-signing.json"

# التحقق من حزمة (بنية + مسارات آمنة + hashes + sizes + freshness + توقيع DER) — exit 0 = PASS
tools\verify_pack.ps1 -PackDir "packs\network\common-ecrime-c2"

# تحديث حزمة C2 من المصدر الحي (ET Open botcc) — يولّد rules.xml + manifest (upstream sha256 anchor)،
# ثم: مراجعة diff إلزامية قبل التوقيع، ثم توقيع يدوي
tools\refresh_ecrime_c2.ps1

# فحص كل الحزم (بنية + مسارات + hashes + sizes + تغطية المانيفست + تواقيع) — نفس CI بلا أسرار
tools\lint.ps1
```

## الترخيص (per-pack — audit M6 fix)

- **القواعد كبيانات:** الرخصة تُعلن داخل كل `pack.manifest.json`. المحتوى **الذاتي فقط** هو CC-BY-4.0؛ المحتوى المشتق من منابع مرخصة يحمل `LicenseRef-<upstream>` مع نص الرخصة **داخل الحزمة نفسها** (مثال: `LICENSE-ETOpen.txt`). انظر `LICENSE-RULES.md`.
- **أدوات هذا المستودع (PowerShell/Python):** GPL-3.0، متسقة مع فورك simplewall.
