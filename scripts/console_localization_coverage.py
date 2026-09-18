#!/usr/bin/env python3
"""Fail closed on mandatory Operator Console localization gaps.

V2 is a closure authority: reviewed user-facing English source copy must either map
to a genuinely Persian value in faDynamic or be an explicitly protected technical
term. The baseline is zero-gap and cannot be rewritten to accept regressions.
"""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

AUTHORITY = "CONSOLE_LOCALIZATION_COVERAGE_V2"
SCHEMA_VERSION = 2
PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")
ATTRIBUTES = ("aria-label", "placeholder", "title")
SKIP_TAGS = {"script", "style", "pre", "code"}
TECHNICAL_EXACT = {
    "4SO", "4SO Platform Factory", "FA", "EN", "Esc", "Ctrl K", "html", "unknown",
    "amd64", "arm64", "kubernetes", "rke2", "gitops", "PlatformBlueprint",
    "platform.4so.io/v1alpha1", "QUERY", "TAIL", "DRAFT", "REVIEW", "PUBLISHED",
    "NEW DRAFT", "LOADING CONTRACT", "WORKSPACE_AUTHORITY_V1",
}
TECHNICAL_RE = re.compile(
    r"^(?:[A-Z0-9_.:/-]{2,}|[a-z0-9_.:/-]+(?:@[a-z0-9_.:-]+)?|sha256:[0-9a-f]+|v?\d+(?:\.\d+){1,3})$"
)


def parse_dynamic_entries(js: str) -> dict[str, str]:
    match = re.search(r"const faDynamic = \{(.*?)\n\};", js, re.S)
    if not match:
        raise SystemExit("LOCALIZATION_DYNAMIC_DICTIONARY_MISSING")
    entries: dict[str, str] = {}
    pair_re = re.compile(
        r'^\s*("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*")\s*,?\s*$',
        re.M,
    )
    for key_raw, value_raw in pair_re.findall(match.group(1)):
        key = json.loads(key_raw)
        # A repeated key silently replaces the reviewed entry, so a later copy could
        # change operator-facing Persian text while the coverage baseline still
        # reports zero gaps. The dictionary must declare each source string once.
        if key in entries:
            raise SystemExit(f"LOCALIZATION_DYNAMIC_DUPLICATE_KEY {key}")
        entries[key] = json.loads(value_raw)
    return entries


def protected_terms(root: Path) -> set[str]:
    glossary_path = root / "webconsole/persian_glossary.json"
    if not glossary_path.is_file():
        raise SystemExit("LOCALIZATION_PERSIAN_GLOSSARY_MISSING")
    glossary = json.loads(glossary_path.read_text(encoding="utf-8"))
    if glossary.get("authority") != "PERSIAN_PRODUCT_GLOSSARY_V1":
        raise SystemExit("LOCALIZATION_PERSIAN_GLOSSARY_AUTHORITY_INVALID")
    return set(glossary.get("protectedTechnicalTerms") or [])


def has_valid_translation(source: str, translated: str | None, protected: set[str]) -> bool:
    if not translated:
        return False
    if PERSIAN_RE.search(translated):
        return True
    # Exact product/protocol terms may intentionally remain untranslated.
    return source in protected and translated == source


def is_technical(value: str, tag: str, attrs: dict[str, str]) -> bool:
    if value in TECHNICAL_EXACT or TECHNICAL_RE.fullmatch(value):
        return True
    classes = set((attrs.get("class") or "").split())
    if "technical" in classes:
        return True
    # Exact machine-facing option values are not operator prose.
    if tag == "option" and value.lower() in {
        "connected", "restricted", "baseline", "privileged", "namespace", "low", "medium", "high", "critical"
    }:
        return True
    return False


VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}


class ConsoleHTMLCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.text_nodes: list[tuple[str, str, dict[str, str]]] = []
        self.attributes: list[tuple[str, str, str, dict[str, str]]] = []

    @staticmethod
    def _attrs(items: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(key): "" if value is None else str(value) for key, value in items}

    def _record_start(self, tag: str, items: list[tuple[str, str | None]], *, push: bool) -> None:
        attrs = self._attrs(items)
        for attr in ATTRIBUTES:
            raw = attrs.get(attr)
            if raw is not None:
                self.attributes.append((attr, raw, tag, attrs))
        if push:
            self.stack.append((tag, attrs))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record_start(tag, attrs, push=tag not in VOID_TAGS)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record_start(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        tag, attrs = self.stack[-1] if self.stack else ("", {})
        self.text_nodes.append((data, tag, attrs))


def collect(root: Path) -> dict[str, list[str]]:
    html_path = root / "webconsole/static/index.html"
    js_path = root / "webconsole/static/app.js"
    parser = ConsoleHTMLCollector()
    parser.feed(html_path.read_text(encoding="utf-8"))
    parser.close()
    dynamic = parse_dynamic_entries(js_path.read_text(encoding="utf-8"))
    protected = protected_terms(root)
    gaps: dict[str, set[str]] = {"text": set(), "attribute": set()}

    for raw, tag, attrs in parser.text_nodes:
        if tag in SKIP_TAGS or "data-i18n" in attrs:
            continue
        value = " ".join(raw.split())
        if not value or not re.search(r"[A-Za-z]", value):
            continue
        if value in dynamic and has_valid_translation(value, dynamic.get(value), protected):
            continue
        if is_technical(value, tag, attrs):
            continue
        gaps["text"].add(value)

    for attr, raw, tag, attrs in parser.attributes:
        if not raw or not re.search(r"[A-Za-z]", raw):
            continue
        value = " ".join(raw.split())
        if value in dynamic and has_valid_translation(value, dynamic.get(value), protected):
            continue
        if is_technical(value, tag, attrs):
            continue
        gaps["attribute"].add(f"{attr}:{value}")

    return {key: sorted(values) for key, values in gaps.items()}


def digest(gaps: dict[str, list[str]]) -> str:
    canonical = json.dumps(gaps, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / "webconsole/localization_coverage_baseline.json"
    gaps = collect(root)
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": AUTHORITY,
        "textGapCount": len(gaps["text"]),
        "attributeGapCount": len(gaps["attribute"]),
        "gapDigest": "sha256:" + digest(gaps),
        "complete": not gaps["text"] and not gaps["attribute"],
        "gaps": gaps,
    }
    if args.write_baseline:
        if not payload["complete"]:
            print(
                f"CONSOLE_LOCALIZATION_COVERAGE_ERROR refusing incomplete baseline "
                f"text={payload['textGapCount']} attributes={payload['attributeGapCount']}",
                file=sys.stderr,
            )
            return 1
        baseline_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"CONSOLE_LOCALIZATION_COVERAGE_BASELINE_WRITTEN text={payload['textGapCount']} attributes={payload['attributeGapCount']} digest={payload['gapDigest']}")
        return 0
    if not baseline_path.is_file():
        print("CONSOLE_LOCALIZATION_COVERAGE_ERROR baseline missing", file=sys.stderr)
        return 1
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if baseline.get("authority") != AUTHORITY or baseline.get("schemaVersion") != SCHEMA_VERSION:
        print("CONSOLE_LOCALIZATION_COVERAGE_ERROR baseline authority/schema invalid", file=sys.stderr)
        return 1
    if baseline.get("complete") is not True or baseline.get("textGapCount") != 0 or baseline.get("attributeGapCount") != 0:
        print("CONSOLE_LOCALIZATION_COVERAGE_ERROR baseline is not zero-gap closure", file=sys.stderr)
        return 1
    if baseline.get("gaps") != gaps:
        old = {k: set(baseline.get("gaps", {}).get(k, [])) for k in gaps}
        new = {k: set(gaps[k]) for k in gaps}
        added = sorted((new["text"] - old["text"]) | (new["attribute"] - old["attribute"]))
        removed = sorted((old["text"] - new["text"]) | (old["attribute"] - new["attribute"]))
        print(f"CONSOLE_LOCALIZATION_COVERAGE_ERROR drift added={len(added)} removed={len(removed)}", file=sys.stderr)
        for value in added[:20]:
            print("  NEW_GAP", value, file=sys.stderr)
        for value in removed[:20]:
            print("  RESOLVED_GAP_REQUIRES_BASELINE_REVIEW", value, file=sys.stderr)
        return 1
    print(
        f"CONSOLE_LOCALIZATION_COVERAGE_PASS authority={AUTHORITY} "
        f"knownTextGaps={payload['textGapCount']} knownAttributeGaps={payload['attributeGapCount']} "
        f"digest={payload['gapDigest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
