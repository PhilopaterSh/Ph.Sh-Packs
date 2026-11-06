# Ph.Sh-Packs

**قواعد أمنية نقيّة موقّعة** — detection/hunt/network packs فوق سلسلة ثقة ECDSA P-256. لا درايفرات، لا توقيع مايكروسوفت، لا حيل — محتوى وتوقيع فقط.

**الحالة:** P0 (هيكل + حزمتان بادئتان + سلسلة توقيع كاملة + SelfTest). المخطط الكامل والمراحل P1–P4 في `D:\CV\Github\packs-repo-blueprint.md`.

## عائلات الحزم

| العائلة | المحتوى | المستهلك |
|---|---|---|
| `network.` | قواعد بتنسيق simplewall internal profile (متوافقة مع فورك simplewall — Round 3) | simplewall fork |
| `detection.` | YARA-X (.yar) + ClamAV (.ndb/.hdb) | clamscan / yara-x |
| `hunt.` | Sigma rules (متوافقة مع Hayabusa) | blue-team / DFIR |

## نموذج الثقة (Trust Model)

```
pack.manifest.json  ──(ECDSA P-256 / SHA-256)──►  pack.manifest.json.sig
        │                                              │
        │ sha256 لكل ملف داخل الـ manifest              │ التوقيع يُتحقق منه بالمفتاح العام المضمّن
        ▼                                              ▼
  محتوى الحزمة                              tools/packs_public_key.pem (مُلتزم بالمستودع)
```

- المفتاح الخاص **خارج المستودعات نهائياً** (`D:\CV\Github\.keys\packs-signing.json`) — التوقيع محلي فقط، لا CI يحمل أسراراً.
- أي تغيير محتوى = bump إصدار + إعادة حساب hashes + إعادة توقيع. لا استثناءات.

## الاستخدام

```powershell
# (مرة واحدة) توليد زوج المفاتيح — رفض إعادة الكتابة تلقائي
tools\generate_packs_key.ps1 -KeysPath "D:\CV\Github\.keys\packs-signing.json" -PublicKeyPath "tools\packs_public_key.pem"

# فحص صحة السلسلة (sign → verify PASS → tamper → verify FAIL)
tools\selftest.ps1 -KeysPath "D:\CV\Github\.keys\packs-signing.json"

# توقيع حزمة (يتحقق من الـ hashes داخلها قبل التوقيع)
tools\sign_pack.ps1 -PackDir "packs\network\common-ecrime-c2" -KeysPath "D:\CV\Github\.keys\packs-signing.json"

# التحقق من حزمة (توقيع ثم hashes) — exit 0 = PASS
tools\verify_pack.ps1 -PackDir "packs\network\common-ecrime-c2"

# تحديث حزمة C2 من المصدر الحي (ET Open botcc) — يولّد rules.xml + manifest، التوقيع بعدها يدوي
tools\refresh_ecrime_c2.ps1

# فحص كل الحزم (بنية + hashes + تواقيع) — نفس ما يديره CI، بلا أسرار
tools\lint.ps1
```

## الترخيص

- **القواعد كبيانات:** CC-BY-4.0 — انظر `LICENSE-RULES.md` (الطزاجة والتحديث الآلي هما المنتج، لا الملفات الساكنة).
- **أدوات هذا المستودع (PowerShell):** GPL-3.0، متسقة مع فورك simplewall.
