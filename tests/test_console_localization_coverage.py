from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/console_localization_coverage.py'


class ConsoleLocalizationCoverageTests(unittest.TestCase):
    def test_canonical_baseline_passes(self) -> None:
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(ROOT)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('CONSOLE_LOCALIZATION_COVERAGE_PASS', result.stdout)

    def test_new_operator_copy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'webconsole/static').mkdir(parents=True)
            shutil.copy2(ROOT / 'webconsole/static/index.html', target / 'webconsole/static/index.html')
            shutil.copy2(ROOT / 'webconsole/static/app.js', target / 'webconsole/static/app.js')
            shutil.copy2(ROOT / 'webconsole/localization_coverage_baseline.json', target / 'webconsole/localization_coverage_baseline.json')
            shutil.copy2(ROOT / 'webconsole/persian_glossary.json', target / 'webconsole/persian_glossary.json')
            html = target / 'webconsole/static/index.html'
            html.write_text(html.read_text(encoding='utf-8').replace('</body>', '<p>Brand new operator instruction</p></body>'), encoding='utf-8')
            result = subprocess.run(['python3', str(SCRIPT), '--root', str(target)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('NEW_GAP Brand new operator instruction', result.stderr)

    def test_english_only_pseudo_translation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'webconsole/static').mkdir(parents=True)
            for rel in ('static/index.html', 'static/app.js', 'localization_coverage_baseline.json', 'persian_glossary.json'):
                src = ROOT / 'webconsole' / rel
                dst = target / 'webconsole' / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            app = target / 'webconsole/static/app.js'
            text = app.read_text(encoding='utf-8')
            self.assertIn('"Assurance": "تضمین"', text)
            app.write_text(text.replace('"Assurance": "تضمین"', '"Assurance": "Assurance"', 1), encoding='utf-8')
            result = subprocess.run(['python3', str(SCRIPT), '--root', str(target)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('NEW_GAP Assurance', result.stderr)

    def test_duplicate_dynamic_dictionary_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'webconsole/static').mkdir(parents=True)
            for rel in ('static/index.html', 'static/app.js', 'localization_coverage_baseline.json', 'persian_glossary.json'):
                src = ROOT / 'webconsole' / rel
                dst = target / 'webconsole' / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            app = target / 'webconsole/static/app.js'
            text = app.read_text(encoding='utf-8')
            self.assertIn('  "Assurance": "تضمین",\n', text)
            # Repeating a reviewed key makes the later entry replace the first one in
            # the browser dictionary while the coverage report still looks complete.
            text = text.replace('  "Assurance": "تضمین",\n', '  "Assurance": "تضمین",\n  "Assurance": "تضمین‌نشده",\n', 1)
            app.write_text(text, encoding='utf-8')
            result = subprocess.run(['python3', str(SCRIPT), '--root', str(target)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('LOCALIZATION_DYNAMIC_DUPLICATE_KEY Assurance', result.stderr)

    def test_write_baseline_refuses_nonzero_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'webconsole/static').mkdir(parents=True)
            for rel in ('static/index.html', 'static/app.js', 'localization_coverage_baseline.json', 'persian_glossary.json'):
                src = ROOT / 'webconsole' / rel
                dst = target / 'webconsole' / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            baseline = target / 'webconsole/localization_coverage_baseline.json'
            before = baseline.read_bytes()
            html = target / 'webconsole/static/index.html'
            html.write_text(html.read_text(encoding='utf-8').replace('</body>', '<p>Unreviewed future operator text</p></body>'), encoding='utf-8')
            result = subprocess.run(['python3', str(SCRIPT), '--root', str(target), '--write-baseline'], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refusing incomplete baseline', result.stderr)
            self.assertEqual(baseline.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
