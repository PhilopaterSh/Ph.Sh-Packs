#!/usr/bin/env python
"""YARA-X quality gate: compile-check every committed .yar rule.
Fails (exit 1) on any rule that does not compile. Zero .yar files = pass (informational).
Runs locally AND in CI via `pip install yara-x` — no secrets, no binary downloads.
"""
import sys
from pathlib import Path

import yara_x


def main(repo_root: str) -> int:
    repo = Path(repo_root)
    rule_files = sorted(repo.glob("packs/**/*.yar")) + sorted(repo.glob("packs/**/*.yara"))
    if not rule_files:
        print("YARA GATE: no .yar/.yara rules committed yet — gate armed, nothing to check")
        return 0

    failures = 0
    for rf in rule_files:
        rel = rf.relative_to(repo)
        try:
            yara_x.compile(rf.read_text(encoding="utf-8"))
            print(f"YARA GATE OK   : {rel}")
        except Exception as exc:  # yara_x raises on any compile error
            failures += 1
            print(f"YARA GATE FAIL : {rel} -> {exc}")

    print(f"YARA GATE SUMMARY: {len(rule_files) - failures}/{len(rule_files)} rules compile clean")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
