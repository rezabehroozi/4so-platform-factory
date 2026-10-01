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
        self.assertIn("INSTALLER_MANUAL_ENTRYPOINT_V1", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("installer-manual", result.stdout)
        self.assertIn("--confirmation DEPLOY", result.stdout)

    def test_entrypoint_is_thin_and_never_downloads_or_drives_systemd(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('exec "${PLATFORMCTL}" installer-manual', source)
        self.assertIn('bin/linux-amd64/platform-installer', source)
        self.assertIn('PLATFORM_FACTORY_RELEASE_ARTIFACT', source)
        for forbidden in ("curl ", "wget ", "systemctl ", "apt-get ", "dnf ", "yum "):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("PLATFORM_INSTALLER_ALLOW_EXECUTION=", source)


if __name__ == "__main__":
    unittest.main()
