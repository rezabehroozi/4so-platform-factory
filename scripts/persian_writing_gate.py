#!/usr/bin/env python3
"""Pinned persian-writing inspired release gate for 4SO user-facing Persian copy.

Authority: PERSIAN_WRITING_GATE_V1
Upstream: ali2000hos/persian-writing 1.3.5 @ 118c2167f30cafe18df13c0ba85f98f50dad1894

The gate intentionally scans *product copy*, not the vendored reference examples,
because the upstream documentation contains intentionally-wrong examples.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import unicodedata
from pathlib import Path

AUTHORITY = "PERSIAN_WRITING_GATE_V1"
UPSTREAM_VERSION = "1.3.5"
UPSTREAM_COMMIT = "118c2167f30cafe18df13c0ba85f98f50dad1894"
UPSTREAM_TREE = "9fd2300bfee50ac7cc666a2e8cbffc47a71e8857"
REGISTER = "formal-but-human"
PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")
PERSIAN_LETTER = r"[ء-غف-یپچژگک]"

ARABIC_VARIANTS = {
    "ي": "ی",
    "ك": "ک",
    "ى": "ی",
    "ة": "ه/هٔ",
    "٠": "۰", "١": "۱", "٢": "۲", "٣": "۳", "٤": "۴",
    "٥": "۵", "٦": "۶", "٧": "۷", "٨": "۸", "٩": "۹",
}
DANGEROUS_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Technical identifiers/nouns may remain Latin where they are the clearest product term.
PROTECTED_EXACT = {
    "4SO", "API", "MCP", "Kubernetes", "RKE2", "OKD", "OpenSearch", "PostgreSQL",
    "Forgejo", "Argo CD", "zot", "Keycloak", "S3", "S3-compatible", "OIDC", "SAML", "SBOM", "SHA-256",
    "SHA256", "GitOps", "TLS", "HA", "DR", "HMAC-SHA256", "Ed25519", "JSON", "HTTP",
    "HTTPS", "OCI", "CAPI", "CRD", "QUERY", "TAIL", "INSTALL", "STRING", "INTEGER",
    "BOOLEAN", "STRING_LIST", "M00", "M13", "S1", "v1beta2", "oc-mirror", "v2",
    "FOUNDATION_V1", "OBSERVABILITY_V1", "TARGET_RUNTIME_V1", "COMPONENT_RUNTIME_V1",
}
TECHNICAL_TOKEN_RE = re.compile(
    r"^(?:[A-Z][A-Z0-9_.:/+-]*|[A-Za-z]+(?:-[A-Za-z0-9]+)+|v?\d+(?:\.\d+){1,3}|"
    r"\d{3,4}|[A-Z][A-Z0-9_]+_V\d+|sha256:[0-9a-f]+)$"
)

# English *grammar/adjectives/verbs* inside Persian product sentences are implementation-first copy.
# Established technical nouns are deliberately not listed here.
FORBIDDEN_MIXED = {
    "immutable": "تغییرناپذیر",
    "authoritative": "مرجع",
    "Plaintext": "متن ساده",
    "Expiring": "دارای تاریخ انقضا",
    "Scoped": "محدود به دامنهٔ مجاز",
    "Server-verified": "تأییدشده در سرور",
    "Redacted": "پاک‌شده از اطلاعات حساس",
    "Cross-project": "بین‌پروژه‌ای",
    "Same-tenant": "درون همان Tenant",
    "Cross-tenant": "بین Tenantها",
    "Default-deny": "مسدودسازی پیش‌فرض",
    "Source-level": "در سطح سورس",
    "Typed": "نوع‌دار",
    "Fail-closed": "در حالت ابهام یا خطا رد می‌شود",
    "fail-closed": "در حالت ابهام یا خطا رد می‌شود",
    "Digest-locked": "قفل‌شده به هش",
    "digest-locked": "قفل‌شده به هش",
    "digest-pinned": "قفل‌شده به هش",
    "Missing": "ناموجود",
    "Unavailable": "در دسترس نیست",
    "Overwrite": "بازنویسی",
    "overwritten": "بازنویسی",
    "Opt-in": "فقط با انتخاب صریح",
    "opt-in": "فقط با انتخاب صریح",
    "Sensitive": "حساس",
    "Remote": "راه‌دور",
    "canonical": "مرجع",
    "Synthetic": "ساختگی",
    "Sample": "نمونه",
    "planning-only": "فقط برای برنامه‌ریزی",
    "Server-side": "در سمت سرور",
    "server-side": "در سمت سرور",
    "Published": "منتشرشده",
    "Persisted": "ذخیره‌شده",
    "append-only": "فقط‌افزودنی",
    "Apply": "اعمال",
    "Adopt": "پذیرش",
    "Resolve": "حل",
    "Resolved": "حل‌شده",
    "Embedded": "درج‌شده",
    "Advisory": "مشورتی",
    "Closure": "بسته‌شدن",
    "Physical-runtime": "زمان اجرای فیزیکی",
}

BUREAUCRATIC = {
    "می‌باشد": "است",
    "می باشد": "است",
    "لازم به ذکر است": "مطلب را مستقیم بیان کنید",
    "شایان ذکر است": "مطلب را مستقیم بیان کنید",
    "در راستای": "برای",
    "در همین راستا": "برای/در ادامه",
    "از اهمیت ویژه‌ای برخوردار است": "ادعای مشخص و قابل سنجش بنویسید",
    "نقش بسزایی": "اثر مشخص را بنویسید",
    "در دنیای امروز": "مستقیم سر اصل مطلب بروید",
    "در نهایت می‌توان گفت": "با نتیجه یا گام بعدی مشخص تمام کنید",
    "به عمل آورد": "انجام داد",
    "گردیده است": "شده است",
}
COLLOQUIAL_FORMAL = ("میشه", "میخوام", "می‌خوام", "میریم", "بذار", "خودمونی")
FAKE_TANVIN = {"گاهاً": "گاهی", "دوماً": "دوم اینکه", "سوماً": "سوم اینکه", "ناچاراً": "به‌ناچار"}
MISSING_TANVIN = {"لطفا": "لطفاً", "حتما": "حتماً", "واقعا": "واقعاً", "اصلا": "اصلاً", "دقیقا": "دقیقاً"}

AUDITED = (
    "webconsole/static/app.js",
    "webconsole/static/index.html",
    "cmd/platform-installer/static/app.js",
    "cmd/platform-installer/static/index.html",
)


def js_strings(text: str):
    # Good enough for product literals: handles escaped quoted JS strings and template literals
    # without expressions. Template strings with ${...} are separately scanned line-wise below.
    pat = re.compile(r'(?P<q>["\'])(?P<s>(?:\\.|(?!\1)[^\n])*)(?P=q)')
    for m in pat.finditer(text):
        value = m.group("s")
        if PERSIAN_RE.search(value):
            yield value, text.count("\n", 0, m.start()) + 1


def product_strings(path: Path):
    text = path.read_text(encoding="utf-8")
    seen = set()
    for value, line in js_strings(text):
        key = (value, line)
        if key not in seen:
            seen.add(key)
            yield value, line
    if path.suffix == ".html":
        # Text nodes/attributes are already caught by quoted values; scan remaining Persian text chunks.
        stripped = re.sub(r"<script\b.*?</script>|<style\b.*?</style>", " ", text, flags=re.S | re.I)
        stripped = re.sub(r"<[^>]+>", "\n", stripped)
        for i, line in enumerate(stripped.splitlines(), 1):
            value = " ".join(line.split())
            if value and PERSIAN_RE.search(value) and (value, i) not in seen:
                yield value, i


def token_is_technical(token: str) -> bool:
    clean = token.strip("()[]{}<>«»\"'،؛؟!.,:=%٪")
    if not clean:
        return True
    return clean in PROTECTED_EXACT or bool(TECHNICAL_TOKEN_RE.fullmatch(clean))


def latin_digit_problem(value: str) -> str | None:
    if not PERSIAN_RE.search(value):
        return None
    for token in value.split():
        if re.search(r"[0-9]", token) and not token_is_technical(token):
            # URLs, paths, email, code-ish tokens retain Latin digits.
            if re.search(r"https?://|@|[/\\]|`|\.[a-z]{2,}$", token, re.I):
                continue
            return token
    return None


def scan_value(value: str, source: str, line: int) -> list[dict]:
    issues: list[dict] = []
    def add(kind: str, token: str, suggestion: str):
        issues.append({"source": source, "line": line, "kind": kind, "token": token,
                       "suggestion": suggestion, "sample": value[:220]})

    if value != unicodedata.normalize("NFC", value):
        add("unicode-nfc", "NFC", "متن را NFC کنید")
    for bad, good in ARABIC_VARIANTS.items():
        if bad in value:
            add("arabic-codepoint", bad, f"از {good} استفاده کنید")
    for ch in DANGEROUS_BIDI:
        if ch in value:
            add("hidden-bidi", f"U+{ord(ch):04X}", "از dir/lang صریح در HTML استفاده کنید")
    if "—" in value or "–" in value:
        add("dash", "—/–", "در نثر فارسی جمله را بازنویسی کنید یا از «،»/«؛» استفاده کنید")
    if re.search(r'(?<=[\u0600-\u06ff])\s*[,;?]|[,;?]\s*(?=[\u0600-\u06ff])', value):
        add("latin-punctuation", ", ; ?", "از «،»، «؛»، «؟» استفاده کنید")
    if re.search(r'"[^"\n]*[\u0600-\u06ff]', value):
        add("quotes", '"..."', "برای نقل‌قول فارسی از «گیومه» استفاده کنید")
    if re.search(r"\b(ن?می)\s+" + PERSIAN_LETTER, value):
        add("zwnj-mi", "می + فاصله", "از نیم‌فاصله استفاده کنید؛ مانند «می‌شود»")
    if re.search(r"(" + PERSIAN_LETTER + r")\s+ها\b", value):
        add("zwnj-ha", " ها", "جمع را با نیم‌فاصله بنویسید؛ مانند «کلاسترها»")
    if re.search(r"(" + PERSIAN_LETTER + r"{2,})\s+(تر|ترین)\b", value):
        add("zwnj-comparative", " تر/ترین", "از نیم‌فاصله استفاده کنید")
    if re.search(r"(?<=\S) {2,}(?=\S)", value):
        add("double-space", "  ", "فقط یک فاصله بگذارید")
    digit = latin_digit_problem(value)
    if digit:
        add("latin-digits", digit, "در نثر فارسی عدد را فارسی بنویسید؛ شناسه/نسخه/کد فنی مستثناست")
    for bad, suggestion in BUREAUCRATIC.items():
        if bad in value:
            add("bureaucratic-ai-tell", bad, suggestion)
    for bad, suggestion in FAKE_TANVIN.items():
        if bad in value:
            add("fake-tanvin", bad, suggestion)
    for bad, suggestion in MISSING_TANVIN.items():
        if re.search(rf"(?<![\u0600-\u06ff]){re.escape(bad)}(?![\u0600-\u06ffًٌٍَُِّ‌])", value):
            add("missing-tanvin", bad, suggestion)
    for form in COLLOQUIAL_FORMAL:
        if re.search(rf'(?<![\u0600-\u06ff]){re.escape(form)}(?![\u0600-\u06ff])', value):
            add("register", form, "رابط سازمانی 4SO باید formal-but-human باشد")
    # Reject specific English grammar/adjectives even when attached to Persian plural suffix.
    for bad, suggestion in FORBIDDEN_MIXED.items():
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(bad)}(?=$|[^A-Za-z0-9_])", value, re.I if bad[0].islower() else 0):
            add("mixed-language-grammar", bad, suggestion)
    if re.search(r"!{2,}", value):
        add("multi-bang", "!!", "یک علامت تعجب کافی است")
    return issues


def mask_technical_for_upstream(value: str) -> str:
    """Mask Latin/code identifiers so upstream fa_lint judges Persian prose only."""
    # URLs/emails/code-ish runs and mixed identifiers such as 4SO/v1beta2 are valid
    # product tokens. The orthography linter should judge the Persian around them.
    value = re.sub(r"https?://\\S+|(?<![\\u0600-\\u06FF])[A-Za-z0-9][A-Za-z0-9_.:/+@-]*(?![\\u0600-\\u06FF])", "فنی", value)
    return value


def run_upstream_lint(root: Path, values: list[str]) -> list[dict]:
    """Execute the vendored upstream fa_lint engine on normalized product prose."""
    lint_path = root / "third_party/persian-writing/scripts/fa_lint.py"
    if not lint_path.is_file():
        return [{"source": "third_party/persian-writing/scripts/fa_lint.py", "line": 0,
                 "kind": "upstream-lint-missing", "token": "fa_lint.py",
                 "suggestion": "vendored upstream linter must be present", "sample": ""}]
    spec = importlib.util.spec_from_file_location("_4so_persian_writing_fa_lint", lint_path)
    if spec is None or spec.loader is None:
        return [{"source": str(lint_path), "line": 0, "kind": "upstream-lint-load",
                 "token": "fa_lint.py", "suggestion": "could not load upstream linter", "sample": ""}]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ISSUES.clear()
    text = "\\n".join(mask_technical_for_upstream(v) for v in values)
    module.check_remaining(text)
    out = []
    for kind, line, snippet, suggestion in module.ISSUES:
        out.append({"source": "persian-writing/fa_lint.py", "line": int(line),
                    "kind": f"upstream-{kind}", "token": kind,
                    "suggestion": suggestion, "sample": snippet})
    return out


def verify_vendor(root: Path) -> list[str]:
    errors = []
    base = root / "third_party/persian-writing"
    upstream = base / "UPSTREAM.json"
    if not upstream.is_file():
        return ["third_party/persian-writing/UPSTREAM.json missing"]
    data = json.loads(upstream.read_text(encoding="utf-8"))
    expected = {
        "version": UPSTREAM_VERSION,
        "commit": UPSTREAM_COMMIT,
        "tree": UPSTREAM_TREE,
        "runtimeNetworkDependency": False,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            errors.append(f"persian-writing vendor {key} mismatch: {data.get(key)!r} != {value!r}")
    for rel in ("LICENSE", "SKILL.md", "references/orthography.md", "references/writing-style.md", "scripts/fa_lint.py"):
        if not (base / rel).is_file():
            errors.append(f"persian-writing curated core missing: {rel}")
    if (base / "assets/fonts").exists():
        errors.append("persian-writing binary fonts must not be redistributed by this integration")
    if (base / "assets/persian_words.txt").exists():
        errors.append("persian-writing optional large lexicon must not be redistributed by this integration")
    return errors


def build_report(root: Path) -> dict:
    vendor_errors = verify_vendor(root)
    issues = []
    scanned = 0
    unique_values = set()
    for rel in AUDITED:
        path = root / rel
        if not path.is_file():
            issues.append({"source": rel, "line": 0, "kind": "missing-surface", "token": rel,
                           "suggestion": "audited product surface is missing", "sample": ""})
            continue
        for value, line in product_strings(path):
            scanned += 1
            unique_values.add(value)
            issues.extend(scan_value(value, rel, line))
    upstream_issues = run_upstream_lint(root, sorted(unique_values))
    issues.extend(upstream_issues)
    canonical = json.dumps(issues, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schemaVersion": 1,
        "authority": AUTHORITY,
        "upstream": {"name": "ali2000hos/persian-writing", "version": UPSTREAM_VERSION,
                     "commit": UPSTREAM_COMMIT, "tree": UPSTREAM_TREE},
        "register": REGISTER,
        "auditedSurfaces": list(AUDITED),
        "scannedStringOccurrences": scanned,
        "uniquePersianStrings": len(unique_values),
        "upstreamLint": {"engine": "third_party/persian-writing/scripts/fa_lint.py",
                         "maskedTechnicalIdentifiers": True, "issueCount": len(upstream_issues)},
        "issueCount": len(issues) + len(vendor_errors),
        "vendorErrors": vendor_errors,
        "issues": issues,
        "issueDigest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "complete": not vendor_errors and not issues,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--write-report", action="store_true")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    report = build_report(root)
    if args.write_report:
        path = root / "webconsole/persian_writing_report.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not report["complete"]:
        for err in report["vendorErrors"]:
            print("PERSIAN_WRITING_GATE_ERROR vendor", err, file=sys.stderr)
        for issue in report["issues"][:120]:
            print(
                f"PERSIAN_WRITING_GATE_ERROR {issue['source']}:{issue['line']} "
                f"[{issue['kind']}] {issue['token']} -> {issue['suggestion']} :: {issue['sample']}",
                file=sys.stderr,
            )
        if len(report["issues"]) > 120:
            print(f"PERSIAN_WRITING_GATE_ERROR ... {len(report['issues'])-120} more", file=sys.stderr)
        return 1
    print(
        f"PERSIAN_WRITING_GATE_PASS authority={AUTHORITY} upstream={UPSTREAM_VERSION}@{UPSTREAM_COMMIT[:12]} "
        f"register={REGISTER} strings={report['uniquePersianStrings']} issues=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
