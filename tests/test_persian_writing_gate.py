import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("persian_writing_gate", ROOT / "scripts" / "persian_writing_gate.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class PersianWritingGateTest(unittest.TestCase):
    def scan(self, value):
        return MOD.scan_value(value, "test", 1)

    def kinds(self, value):
        return {item["kind"] for item in self.scan(value)}

    def test_formal_human_product_copy_passes(self):
        self.assertEqual([], self.scan("اگر اجراکننده آماده نباشد، درخواست ثبت نمی‌شود. وضعیت را بررسی کنید و دوباره تلاش کنید."))

    def test_mechanical_errors_fail(self):
        self.assertIn("arabic-codepoint", self.kinds("اين متن با كاف و ي عربی است."))
        self.assertIn("zwnj-mi", self.kinds("این درخواست اجرا می شود."))
        self.assertIn("dash", self.kinds("این درخواست — تا تأیید اپراتور — اجرا نمی‌شود."))

    def test_bureaucratic_and_mixed_grammar_fail(self):
        self.assertIn("bureaucratic-ai-tell", self.kinds("این سرویس آماده می‌باشد."))
        self.assertIn("mixed-language-grammar", self.kinds("این Revision immutable است."))
        self.assertIn("mixed-language-grammar", self.kinds("Providerهای Missing در وضعیت BLOCKED می‌مانند."))

    def test_technical_identifiers_are_preserved(self):
        for value in (
            "نسخه RKE2 برای این کلاستر آماده است.",
            "امضای Ed25519 و HMAC-SHA256 بررسی شد.",
            "وضعیت FOUNDATION_V1 و M00 ثبت شد.",
            "فایل با مجوز 0600 ذخیره می‌شود.",
            "مقصد S3-compatible در دسترس است.",
        ):
            self.assertNotIn("latin-digits", self.kinds(value), value)

    def test_vendored_upstream_linter_is_executed(self):
        self.assertEqual([], MOD.run_upstream_lint(ROOT, ["این متن فارسی درست نوشته شده است."]))
        issues = MOD.run_upstream_lint(ROOT, ["این درخواست اجرا می شود."])
        self.assertTrue(any(item["kind"] == "upstream-zwnj-mi" for item in issues), issues)

    def test_report_records_zero_upstream_lint_findings(self):
        report = MOD.build_report(ROOT)
        self.assertEqual("third_party/persian-writing/scripts/fa_lint.py", report["upstreamLint"]["engine"])
        self.assertTrue(report["upstreamLint"]["maskedTechnicalIdentifiers"])
        self.assertEqual(0, report["upstreamLint"]["issueCount"])

    def test_vendor_pin_is_exact_and_network_free(self):
        errors = MOD.verify_vendor(ROOT)
        self.assertEqual([], errors)
        data = json.loads((ROOT / "third_party/persian-writing/UPSTREAM.json").read_text(encoding="utf-8"))
        self.assertEqual(MOD.UPSTREAM_COMMIT, data["commit"])
        self.assertEqual("1.3.5", data["version"])
        self.assertFalse(data["runtimeNetworkDependency"])

    def test_product_tree_is_clean(self):
        report = MOD.build_report(ROOT)
        self.assertTrue(report["complete"], report["issues"][:10])
        self.assertEqual(0, report["issueCount"])


if __name__ == "__main__":
    unittest.main()
