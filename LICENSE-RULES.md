# Ph.Sh-Packs — Rules Licenses (per pack)

## Rule packs (packs/**) — license depends on content origin (audit M6 fix)

| Pack | License | Basis |
|---|---|---|
| `network/common-ecrime-c2` | **LicenseRef-ETOpen-1.1** (text shipped in-pack as `LICENSE-ETOpen.txt`) | Derived from the Emerging Threats Open botcc ruleset — redistribution permitted provided the ET copyright notice accompanies it. NOT CC-BY-4.0: that license does not belong to us for derived content. |
| `hunt/windows-baseline` | **CC-BY-4.0** | Self-authored Sigma rules (citing MITRE ATT&CK references). |
| future `detection.*` packs | per-pack, declared in each `pack.manifest.json` | Self-authored rules → CC-BY-4.0; rules derived from licensed upstreams → the upstream's LicenseRef + in-pack license text. |

**Rule of the repo:** the license field in each manifest is the truth; `CC-BY-4.0` is only ever valid for content we authored ourselves.

Attribution for self-authored content:

> © 2026 Philopater Shenouda — Ph.Sh-Packs (https://github.com/PhilopaterSh)

**Why a data license and not GPL?** Rules are data, not code. The value of a rule feed is its freshness
and its update pipeline — not the static file. A permissive attribution license lets defenders (and
future paid-feed customers) adopt the packs without license friction, exactly like the Greenbone/OpenVAS
and Sigma/DRL precedents. For upstream-derived content we inherit the upstream terms verbatim instead.

## Tooling (tools/**, schema/**) — GPL-3.0

Verification and signing tooling in `tools/` and `schema/` is licensed under GPL-3.0, consistent with
the simplewall fork this repository integrates with.
