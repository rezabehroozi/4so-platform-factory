from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"


class GuidedInstallEntrypointTests(unittest.TestCase):
    def test_help_is_safe_without_host_mutation(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("INSTALLER_MANUAL_ENTRYPOINT_V1", source)
        self.assertIn("INSTALLER_MANUAL_CONTINUATION_ENTRYPOINT_V1", source)
        self.assertIn("installer-manual", result.stdout)
        self.assertIn("--confirmation DEPLOY", result.stdout)
        self.assertIn("install.sh status", result.stdout)
        self.assertIn("--confirmation RECOVER", result.stdout)
        self.assertIn("--confirmation ROLLBACK", result.stdout)

    def test_continuation_modes_bypass_install_inputs_but_keep_canonical_owner(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("preflight|plan|install|status|verify|recover|rollback", source)
        continuation = source.index('status|verify|recover|rollback)')
        bundle_requirement = source.index('if [[ -z "${bundle_dir}" ]]')
        self.assertLess(continuation, bundle_requirement)
        self.assertIn('exec "${PLATFORMCTL}" installer-manual "${mode}" "$@"', source)
        self.assertIn("They do not require the original bundle or release ZIP again.", source)

    def test_entrypoint_is_thin_and_never_downloads_or_drives_systemd(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('exec "${PLATFORMCTL}" installer-manual', source)
        self.assertIn('bin/linux-amd64/platform-installer', source)
        self.assertIn('PLATFORM_FACTORY_RELEASE_ARTIFACT', source)
        self.assertIn('PLATFORM_INSTALLER_BUNDLE_DIR', source)
        for forbidden in ("curl ", "wget ", "systemctl ", "apt-get ", "dnf ", "yum "):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("PLATFORM_INSTALLER_ALLOW_EXECUTION=", source)


if __name__ == "__main__":
    unittest.main()
