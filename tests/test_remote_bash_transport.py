from __future__ import annotations

from pathlib import Path
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "remote_bash_transport", ROOT / "scripts" / "run_remote_bash.py"
)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class RemoteBashTransportTests(unittest.TestCase):
    def test_normalizes_bom_crlf_and_bare_cr(self) -> None:
        self.assertEqual(
            module.canonical_bash_payload(
                b"\xef\xbb\xbfset -eu\r\necho one\recho two"
            ),
            b"set -eu\necho one\necho two\n",
        )

    def test_rejects_nul_and_invalid_utf8(self) -> None:
        with self.assertRaisesRegex(ValueError, "REMOTE_BASH_PAYLOAD_NUL"):
            module.canonical_bash_payload(b"echo ok\x00oops")
        with self.assertRaisesRegex(ValueError, "REMOTE_BASH_PAYLOAD_UTF8_INVALID"):
            module.canonical_bash_payload(b"\xff")

    def test_builds_strict_argument_safe_ssh_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "id_ed25519"
            ssh = root / "ssh"
            identity.write_text("key", encoding="utf-8")
            ssh.write_text("#!/bin/sh\n", encoding="utf-8")
            command = module.ssh_command(
                ssh=str(ssh),
                identity=identity,
                user="root",
                host="213.176.28.136",
                connect_timeout=8,
                connection_attempts=3,
                alive_interval=5,
                alive_count=3,
            )
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(command[-3:], ["root@213.176.28.136", "bash", "-s"])

    def test_rejects_host_metacharacters_before_identity_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / "ssh"
            ssh.write_text("#!/bin/sh\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "REMOTE_BASH_HOST_INVALID"):
                module.ssh_command(
                    ssh=str(ssh),
                    identity=root / "missing",
                    user="root",
                    host="host;touch-pwned",
                    connect_timeout=8,
                    connection_attempts=3,
                    alive_interval=5,
                    alive_count=3,
                )


if __name__ == "__main__":
    unittest.main()
