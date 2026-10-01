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
        self.assertIn("install.sh bootstrap-status", result.stdout)
        self.assertIn("install.sh resume", result.stdout)
        self.assertIn("install.sh reset", result.stdout)
        self.assertIn("install.sh reset-resume", result.stdout)
        self.assertIn("--confirmation RESUME", result.stdout)
        self.assertIn("--confirmation RESET", result.stdout)
        self.assertIn("--confirmation RESUME-RESET", result.stdout)
        self.assertIn("--confirmation RECOVER", result.stdout)
        self.assertIn("--confirmation ROLLBACK", result.stdout)

    def test_continuation_modes_bypass_install_inputs_but_keep_canonical_owner(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("preflight|plan|install|status|verify|bootstrap-status|resume|reset|reset-resume|recover|rollback", source)
        continuation = source.index('status|verify|recover|rollback)')
        bundle_requirement = source.index('if [[ -z "${bundle_dir}" ]]')
        self.assertLess(continuation, bundle_requirement)
        self.assertIn('exec "${PLATFORMCTL}" installer-manual "${mode}" "$@"', source)
        self.assertIn("They do not require the original bundle or release ZIP again.", source)

    def test_bootstrap_continuations_are_status_first_owner_paths_without_bundle_replay(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('installer-access "${access_command}"', source)
        self.assertIn('bootstrap-status|resume|reset|reset-resume)', source)
        self.assertIn('access_command="run-status"', source)
        self.assertIn('PLATFORM_INSTALLER_URL:-http://127.0.0.1:9080', source)
        self.assertIn('PLATFORM_INSTALLER_TOKEN_FILE:-/var/lib/4so-platform-installer/bootstrap-token', source)
        continuation = source.index('bootstrap-status|resume|reset|reset-resume)')
        bundle_requirement = source.index('if [[ -z "${bundle_dir}" ]]')
        self.assertLess(continuation, bundle_requirement)
        self.assertNotIn('curl ', source)
        self.assertNotIn('systemctl ', source)

    def test_remote_bootstrap_continuation_only_requires_root_for_effective_private_token(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('DEFAULT_BOOTSTRAP_TOKEN_FILE="/var/lib/4so-platform-installer/bootstrap-token"', source)
        self.assertIn('access_token_file="${access_args[i+1]}"', source)
        self.assertIn('access_token_file="${PLATFORM_INSTALLER_TOKEN_FILE:-${DEFAULT_BOOTSTRAP_TOKEN_FILE}}"', source)
        self.assertIn('[[ "${EUID}" -ne 0 && -z "${PLATFORM_INSTALLER_TOKEN:-}" && "${access_token_file}" == "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]', source)
        self.assertIn("Remote/custom authenticated continuation does not require local root", source)
        self.assertIn("[sudo] bash install.sh bootstrap-status", source)
        root_guard = source.index('[[ "${EUID}" -ne 0 && -z "${PLATFORM_INSTALLER_TOKEN:-}" && "${access_token_file}" == "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]')
        token_parse = source.index('access_token_file=""')
        token_injection = source.index('access_args=(--token-file "${access_token_file}"')
        self.assertGreater(root_guard, token_parse)
        self.assertLess(root_guard, token_injection)

    def test_entrypoint_is_thin_and_never_downloads_or_drives_systemd(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('exec "${PLATFORMCTL}" installer-manual', source)
        self.assertIn('bin/linux-amd64/platform-installer', source)
        self.assertIn('PLATFORM_FACTORY_RELEASE_ARTIFACT', source)
        self.assertIn('PLATFORM_INSTALLER_BUNDLE_DIR', source)
        for forbidden in ("curl ", "wget ", "systemctl ", "apt-get ", "dnf ", "yum "):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("PLATFORM_INSTALLER_ALLOW_EXECUTION=", source)


class GuidedInstallDoctorContractTests(unittest.TestCase):
    def test_doctor_is_read_only_non_root_and_input_discovery_is_bounded(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("INSTALLER_MANUAL_DOCTOR_V1", source)
        self.assertIn("discover_bundle_dir", source)
        self.assertIn('"${ROOT_DIR}/bundle"', source)
        self.assertIn('"${ROOT_DIR}/appliance-bundle"', source)
        self.assertIn('"/opt/4so-platform-factory/bundle"', source)
        self.assertIn("bundle.lock.json", source)
        self.assertIn("discover_release_artifact", source)
        doctor = source.index('if [[ "${mode}" == "doctor" ]]')
        root_guard = source.index('if [[ "${EUID}" -ne 0 ]]', doctor)
        self.assertLess(doctor, root_guard)
        for forbidden in ("curl ", "wget ", "systemctl ", "apt-get ", "dnf ", "yum "):
            self.assertNotIn(forbidden, source)

    def test_help_exposes_doctor_and_optional_discovered_inputs(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"], cwd=ROOT, text=True, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install.sh doctor", result.stdout)
        self.assertIn("When omitted, the entrypoint safely checks", result.stdout)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"readyForPreflight=${ready}"', source)
        self.assertIn('"bundleAdmissionVerified=false"', source)
        self.assertIn("bundleAdmissionVerified=false", source)
        self.assertNotIn("json_escape", source)

    def test_doctor_emits_shell_escaped_exact_preflight_command_with_resolved_inputs(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('DOCTOR_HANDOFF_AUTHORITY="INSTALLER_MANUAL_EXACT_NEXT_COMMAND_V1"', source)
        self.assertIn('"handoffAuthority=${DOCTOR_HANDOFF_AUTHORITY}"', source)
        self.assertIn("nextAction=copy nextCommand exactly", source)
        self.assertIn("printf 'nextCommand=sudo bash %q preflight --bundle-dir %q --release-artifact %q", source)
        doctor = source.index('if [[ "${mode}" == "doctor" ]]')
        next_command = source.index("nextCommand=sudo bash %q preflight", doctor)
        self.assertGreater(next_command, doctor)

    def test_normal_install_fails_early_without_actionable_browser_flags(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("INSTALLER_MANUAL_ACTIONABLE_ENTRYPOINT_V1", source)
        self.assertIn('normal install requires --enable-execution', source)
        self.assertIn('install requires explicit --confirmation DEPLOY', source)
        validation = source.index('if [[ "${mode}" == "install" ]]')
        discovery = source.index('if [[ -z "${bundle_dir}" ]]')
        self.assertLess(validation, discovery)


if __name__ == "__main__":
    unittest.main()
