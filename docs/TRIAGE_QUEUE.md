# TRIAGE QUEUE — مواصفة طابور الفحص (تحديث 4)

الغرض: ربط مخرجات **CAPEv2 ‏+ capa** (داخل VM التفجير) بمسودة القواعد عندنا، بحيث يصبح كل عينة سجلاً واحداً قابلاً للتتبع: وصلت → فُحصت → دُرست → صار لها draft → روجعت → وُقّعت.

## حالة التنفيذ (2026-11-17)
- **CAPEv2 يوفر المدمج أصلاً:** `utils/malwarebazaar.py` (ساحب عينات MalwareBazaar) + module الـ capa في المعالجة — ما نحتاجه لصقٌ فقط، لا بناء.
- **يعمل اليوم:** سكربت الجلب `_sample-lab/tools/step0_fetch_malwarebazaar.py` (هيكل — ينتظر `MB_AUTH_KEY` من `.keys\` خارج المستودعات).
- **ينتظر:** VM التفجير المعزولة (FLARE VM + CAPE + FakeNet) — العينات لا تُنزَّل على الجهاز المضيف أبداً.

## مخطط سجل الطابور (JSON لكل عينة)

```json
{
  "queue_version": 1,
  "sample": {
    "sha256": "<hex>",
    "source": "malwarebazaar|recon|community",
    "source_ref": "<MB tag/link أو مرجع داخلي>",
    "retrieved": "2026-11-17",
    "vm_artifacts": { "cape_json": "path", "pcap": "path", "screenshots": "path" }
  },
  "analysis": {
    "cape": { "family": "<إن حُدد>", "configs_extracted": [], "behavior_summary": "<سطران>" },
    "capa": { "capabilities": ["T1059.001 ..."], "mitre_tags": [] },
    "rea": { "evidence_id": "<من rea analyze>", "procedure_count": 0, "interesting_functions": [] }
  },
  "draft": { "yar": "path", "refine_rounds": 2, "corpus_size": 10, "verdict": "PASS" },
  "status": "queued|detonated|analyzed|drafted|reviewed|signed|rejected",
  "reviewer": "Philopater Shenouda",
  "decision_note": "<سبب القبول/الرفض — إلزامي عند reviewed/rejected>"
}
```

## القواعد الحاكمة
1. العينات وكل artifacts داخل VM فقط — المضيف يرى **التقارير** لا العينات.
2. لا ينتقل أي سجل من `drafted` إلى `signed` إلا بمراجعة بشرية موثقة بالاسم والسبب.
3. كل مرفوض يبقى في السجل — الرفض الموثق رأس مال curation.
