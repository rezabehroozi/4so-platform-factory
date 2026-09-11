from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import hashlib
import io
import os
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BROWSER = load("browser_triage_profile", ROOT / "scripts" / "browser_triage_profile.py")
BROWSER_BOOTSTRAP = load("browser_triage_bootstrap", ROOT / "scripts" / "browser_triage_bootstrap.py")
PERSIAN = load("persian_ui_lint", ROOT / "scripts" / "persian_ui_lint.py")


class DeveloperEvidenceTests(unittest.TestCase):
    def test_browser_profile_is_exact_pinned_isolated_and_non_authoritative(self):
        value = BROWSER.profile()
        BROWSER.verify(value)
        self.assertEqual(value["authority"], "BROWSER_TRIAGE_PROFILE_V2")
        self.assertFalse(value["productMutationAuthority"])
        args = value["server"]["args"]
        self.assertIn("chrome-devtools-mcp@1.8.0", args)
        self.assertNotIn("chrome-devtools-mcp@latest", args)
        for flag in ("--headless", "--isolated", "--no-usage-statistics", "--no-performance-crux"):
            self.assertIn(flag, args)
        self.assertEqual(value["server"]["env"]["CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS"], "1")

        prereq = value["prerequisites"]
        self.assertEqual(prereq["authority"], "BROWSER_TRIAGE_PREREQUISITE_AUTHORITY_V1")
        self.assertEqual(set(prereq["supportedOperatingSystems"]), {"linux", "windows"})
        self.assertFalse(prereq["administratorRequired"])
        self.assertIn("--ensure", prereq["bootstrap"])
        self.assertIn("--run-mcp", prereq["launcher"])

    def test_browser_prerequisite_policy_covers_windows_linux_and_version_floors(self):
        BROWSER_BOOTSTRAP.self_test()
        self.assertTrue(BROWSER_BOOTSTRAP._node_compatible("v20.19.0"))
        self.assertFalse(BROWSER_BOOTSTRAP._node_compatible("v20.18.9"))
        self.assertTrue(BROWSER_BOOTSTRAP._node_compatible("v22.12.0"))
        self.assertFalse(BROWSER_BOOTSTRAP._node_compatible("v22.11.0"))
        self.assertEqual(BROWSER_BOOTSTRAP._normalized_platform("Windows", "AMD64"), ("windows", "amd64"))
        self.assertEqual(BROWSER_BOOTSTRAP._normalized_platform("Linux", "x86_64"), ("linux", "x86_64"))
        self.assertIn(("windows", "amd64"), BROWSER_BOOTSTRAP.NODE_ASSETS)
        self.assertIn(("linux", "x86_64"), BROWSER_BOOTSTRAP.NODE_ASSETS)
        self.assertIn(("windows", "amd64"), BROWSER_BOOTSTRAP.CHROME_ASSETS)
        self.assertIn(("linux", "x86_64"), BROWSER_BOOTSTRAP.CHROME_ASSETS)


    def test_linux_user_local_bootstrap_installs_node_and_chrome_from_pinned_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            fixtures.mkdir()

            node_archive = fixtures / "node-v22.12.0-linux-x64.tar.xz"
            with tarfile.open(node_archive, "w:xz") as tf:
                for name, body in {
                    "node-v22.12.0-linux-x64/bin/node": b"#!/bin/sh\necho v22.12.0\n",
                    "node-v22.12.0-linux-x64/bin/npm": b"#!/bin/sh\necho 10.9.0\n",
                    "node-v22.12.0-linux-x64/bin/npx": b"#!/bin/sh\necho 10.9.0\n",
                }.items():
                    info = tarfile.TarInfo(name)
                    info.mode = 0o755
                    info.size = len(body)
                    tf.addfile(info, io.BytesIO(body))
            node_sha = hashlib.sha256(node_archive.read_bytes()).hexdigest()

            chrome_archive = fixtures / "chrome-linux64.zip"
            with zipfile.ZipFile(chrome_archive, "w") as zf:
                zf.writestr("chrome-linux64/chrome", "#!/bin/sh\necho 'Google Chrome 152.0.7977.75'\n")

            def fake_download(url, target):
                source = node_archive if "nodejs.org" in url else chrome_archive
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())

            assets = {("linux", "x86_64"): (node_archive.name, node_sha)}
            with mock.patch.object(BROWSER_BOOTSTRAP, "NODE_ASSETS", assets), mock.patch.object(BROWSER_BOOTSTRAP, "_download", side_effect=fake_download):
                BROWSER_BOOTSTRAP._ensure_node(root, "linux", "x86_64")
                BROWSER_BOOTSTRAP._ensure_chrome(root, "linux", "x86_64")

            node, npm, npx = BROWSER_BOOTSTRAP._node_local_paths(root, "linux", "x86_64")
            chrome = BROWSER_BOOTSTRAP._chrome_local_path(root, "linux", "x86_64")
            self.assertTrue(node.is_file() and npm.is_file() and npx.is_file())
            self.assertTrue(chrome and chrome.is_file())
            self.assertTrue(BROWSER_BOOTSTRAP._node_compatible(BROWSER_BOOTSTRAP._run_version([str(node), "--version"])))
            self.assertTrue(BROWSER_BOOTSTRAP._chrome_compatible(BROWSER_BOOTSTRAP._run_version([str(chrome), "--version"])))

    def test_safe_zip_extract_preserves_unix_executable_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "chrome.zip"
            info = zipfile.ZipInfo("chrome-linux64/chrome_crashpad_handler")
            info.create_system = 3
            info.external_attr = (0o100755 << 16)
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, b"helper")
            with mock.patch.object(Path, "chmod", autospec=True) as chmod:
                BROWSER_BOOTSTRAP._safe_zip_extract(archive, root / "out")
            self.assertTrue(any((call.args[1] & 0o111) == 0o111 for call in chmod.call_args_list), chmod.call_args_list)

    def test_safe_zip_extract_rejects_unix_symlink_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "symlink.zip"
            info = zipfile.ZipInfo("chrome-linux64/link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, "target")
            with self.assertRaisesRegex(RuntimeError, "SPECIAL_MEMBER_FORBIDDEN"):
                BROWSER_BOOTSTRAP._safe_zip_extract(archive, root / "out")

    def test_safe_tar_extract_allows_internal_relative_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "node.tar.xz"
            with tarfile.open(archive, "w:xz") as tf:
                body = b"#!/bin/sh\necho corepack\n"
                target = tarfile.TarInfo("node/lib/node_modules/corepack/dist/corepack.js")
                target.mode = 0o755
                target.size = len(body)
                tf.addfile(target, io.BytesIO(body))
                link = tarfile.TarInfo("node/bin/corepack")
                link.type = tarfile.SYMTYPE
                link.linkname = "../lib/node_modules/corepack/dist/corepack.js"
                tf.addfile(link)
            out = root / "out"
            BROWSER_BOOTSTRAP._safe_tar_extract(archive, out)
            installed = out / "node/bin/corepack"
            self.assertTrue(installed.is_symlink())
            self.assertEqual(os.readlink(installed).replace("\\", "/"), "../lib/node_modules/corepack/dist/corepack.js")

    def test_safe_tar_extract_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "escape.tar.xz"
            with tarfile.open(archive, "w:xz") as tf:
                link = tarfile.TarInfo("node/bin/corepack")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../../outside"
                tf.addfile(link)
            with self.assertRaisesRegex(RuntimeError, "SYMLINK_TARGET_ESCAPE"):
                BROWSER_BOOTSTRAP._safe_tar_extract(archive, root / "out")

    def test_persian_gate_rejects_arabic_codepoint_and_bidi_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "webconsole" / "static").mkdir(parents=True)
            glossary = {
                "authority": "PERSIAN_PRODUCT_GLOSSARY_V1",
                "externalLexiconShipped": False,
                "automaticLevel": "safe-only",
                "preferredTerms": [{"concept": "cluster", "value": "کلاستر", "avoid": ["خوشه"]}],
            }
            (root / "webconsole" / "persian_glossary.json").write_text(json.dumps(glossary, ensure_ascii=False), encoding="utf-8")
            copy_policy = {
                "authority": "PERSIAN_PRODUCT_COPY_QA_V1",
                "auditedSurfaces": ["webconsole/static/index.html", "webconsole/static/app.js"],
                "forbiddenRoboticPhrases": [],
            }
            (root / "webconsole" / "persian_copy_quality.json").write_text(json.dumps(copy_policy, ensure_ascii=False), encoding="utf-8")
            (root / "webconsole" / "static" / "index.html").write_text('<option value="fa">فارسی</option>', encoding="utf-8")
            (root / "webconsole" / "static" / "app.js").write_text("کلاستر ي\u202e", encoding="utf-8")
            errors = PERSIAN.scan(root)
            self.assertTrue(any("Arabic codepoint" in item for item in errors), errors)
            self.assertTrue(any("bidi control" in item for item in errors), errors)

    def test_current_console_passes_persian_gate(self):
        self.assertEqual(PERSIAN.scan(ROOT), [])


if __name__ == "__main__":
    unittest.main()
