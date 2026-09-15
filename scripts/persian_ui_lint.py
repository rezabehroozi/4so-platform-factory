#!/usr/bin/env python3
"""Deterministic Persian/RTL quality gate for the embedded Operator Console.

Inspired by Persian editorial tooling but intentionally product-owned and tiny:
no external lexicon or ODbL data is shipped. The gate validates Unicode
normalization, dangerous bidi controls, and a 4SO technical glossary.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import unicodedata

AUTHORITY = "PERSIAN_UI_QA_V2"
GLOSSARY_AUTHORITY = "PERSIAN_PRODUCT_GLOSSARY_V1"
COPY_AUTHORITY = "PERSIAN_PRODUCT_COPY_QA_V1"
PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")
DICTIONARY_START = re.compile(r"\bconst\s+[A-Za-z_$][\w$]*\s*=\s*\{")
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


def _object_literal_keys(text: str, brace_index: int) -> tuple[list[tuple[str, int]], int] | None:
    """Collect depth-one ``("key", offset)`` pairs of an object literal.

    Returns None when the literal cannot be parsed conservatively, so a caller never
    reports a finding from a guess. Strings and comments are skipped as opaque, which
    keeps punctuation inside product copy from being mistaken for object structure.
    A template literal aborts the parse because its interpolation syntax can embed
    arbitrary executable structure.
    """
    keys: list[tuple[str, int]] = []
    depth = 0
    index = brace_index
    size = len(text)
    while index < size:
        char = text[index]
        if char in "\"'":
            quote = char
            cursor = index + 1
            while cursor < size:
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == quote:
                    break
                cursor += 1
            if cursor >= size:
                return None
            after = cursor + 1
            while after < size and text[after] in " \n\r\t":
                after += 1
            if depth == 1 and after < size and text[after] == ":":
                keys.append((text[index + 1 : cursor], index))
            index = cursor + 1
            continue
        if char == "`":
            return None
        if char == "/" and index + 1 < size and text[index + 1] == "/":
            newline = text.find("\n", index)
            index = size if newline < 0 else newline
            continue
        if char == "/" and index + 1 < size and text[index + 1] == "*":
            closer = text.find("*/", index + 2)
            index = size if closer < 0 else closer + 2
            continue
        if char.isalpha() or char in "_$":
            cursor = index
            while cursor < size and (text[cursor] == "_" or text[cursor].isalnum() or text[cursor] in "$_"):
                cursor += 1
            after = cursor
            while after < size and text[after] in " \n\r\t":
                after += 1
            if depth == 1 and after < size and text[after] == ":":
                keys.append((text[index:cursor], index))
            index = cursor
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return keys, index
        index += 1
    return None


def duplicate_translation_keys(text: str) -> list[str]:
    """Report shadowed keys inside the embedded Persian translation dictionaries.

    A repeated key silently replaces the entry an operator already sees, so a later
    definition can change or contradict reviewed product copy without any visible
    error. Copy QA therefore rejects duplicate keys outright.
    """
    findings: list[str] = []
    for match in DICTIONARY_START.finditer(text):
        parsed = _object_literal_keys(text, match.end() - 1)
        if parsed is None:
            continue
        keys, closing = parsed
        literal = text[match.start() : closing + 1]
        if not PERSIAN_RE.search(literal):
            continue
        offsets: dict[str, list[int]] = {}
        for key, offset in keys:
            offsets.setdefault(key, []).append(offset)
        for key, positions in offsets.items():
            if len(positions) > 1:
                lines = ", ".join(str(text.count("\n", 0, position) + 1) for position in positions)
                findings.append(f"duplicate translation key {key!r} at line {lines}")
    return findings


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
        if path.suffix == ".js":
            for finding in duplicate_translation_keys(text):
                errors.append(f"{path.relative_to(root)} {finding}")
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
