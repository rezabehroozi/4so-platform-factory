#!/usr/bin/env python3
"""Deterministic Persian/RTL quality gate for the embedded Operator Console.

Inspired by Persian editorial tooling but intentionally product-owned and tiny:
no external lexicon or ODbL data is shipped. The gate validates Unicode
normalization, dangerous bidi controls, and a 4SO technical glossary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import unicodedata

AUTHORITY = "PERSIAN_UI_QA_V2"
GLOSSARY_AUTHORITY = "PERSIAN_PRODUCT_GLOSSARY_V1"
COPY_AUTHORITY = "PERSIAN_PRODUCT_COPY_QA_V1"
ARABIC_VARIANTS = {"ي": "Persian Yeh ی", "ك": "Persian Kaf ک", "ى": "Persian Yeh ی"}
DANGEROUS_BIDI = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}


def scan(root: Path) -> list[str]:
    glossary_path = root / "webconsole" / "persian_glossary.json"
    glossary = json.loads(glossary_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if glossary.get("authority") != GLOSSARY_AUTHORITY or glossary.get("externalLexiconShipped") is not False:
        errors.append("glossary authority/bundling boundary is invalid")
    copy_policy_path = root / "webconsole" / "persian_copy_quality.json"
    copy_policy = json.loads(copy_policy_path.read_text(encoding="utf-8"))
    if copy_policy.get("authority") != COPY_AUTHORITY:
        errors.append("Persian product-copy authority is invalid")
    files = [root / item for item in copy_policy.get("auditedSurfaces", [])]
    if not files:
        errors.append("Persian product-copy audited surfaces are empty")
    combined = ""
    for path in files:
        text = path.read_text(encoding="utf-8")
        combined += "\n" + text
        if text != unicodedata.normalize("NFC", text):
            errors.append(f"{path.relative_to(root)} is not NFC normalized")
        for char, preferred in ARABIC_VARIANTS.items():
            if char in text:
                errors.append(f"{path.relative_to(root)} contains Arabic codepoint {char!r}; use {preferred}")
        for char, name in DANGEROUS_BIDI.items():
            if char in text:
                errors.append(f"{path.relative_to(root)} contains hidden bidi control {name}; use explicit HTML dir/lang instead")
    if 'value="fa">فارسی<' not in combined:
        errors.append("Persian locale selector is missing")
    for item in glossary.get("preferredTerms", []):
        preferred = str(item.get("value", ""))
        if preferred and preferred not in combined:
            errors.append(f"preferred product term is not represented in UI copy: {preferred}")
        for avoid in item.get("avoid", []):
            if avoid and avoid in combined:
                errors.append(f"non-canonical Persian product term found: {avoid} (prefer {preferred})")
    if glossary.get("automaticLevel") != "safe-only":
        errors.append("automatic Persian rewrite level must remain safe-only")
    for phrase in copy_policy.get("forbiddenRoboticPhrases", []):
        if phrase and phrase in combined:
            errors.append(f"robotic/implementation-first Persian product copy found: {phrase}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors = scan(root)
    if errors:
        for error in errors:
            print("PERSIAN_UI_QA_ERROR", error)
        return 1
    print("PERSIAN_UI_QA_PASS", AUTHORITY, GLOSSARY_AUTHORITY, COPY_AUTHORITY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
