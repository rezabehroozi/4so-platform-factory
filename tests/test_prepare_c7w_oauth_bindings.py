import importlib.util, json, os, stat, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("prepare_c7w_oauth_bindings",ROOT/"scripts"/"prepare_c7w_oauth_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class PrepareC7WOAuthBindingsTests(unittest.TestCase):
    def test_materialize_writes_private_validated_binding_document_without_echoing_ids(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            out=root/".state"/"private"/"c7w-oauth-client-bindings.json"
            clients={name:f"oauth-{name}-unit" for name in mod.CLIENTS}
            result=mod.materialize(out,clients)
            self.assertEqual(mod.AUTHORITY,result["authority"])
            self.assertEqual(str(out),result["path"])
            self.assertEqual(4,result["clientCount"])
            self.assertRegex(result["sha256"],r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("oauth-chatgpt-unit",json.dumps(result))
            document=json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual({"authority":mod.AUTHORITY,"clients":clients},document)
            if os.name!="nt":
                self.assertEqual(0o600,stat.S_IMODE(out.stat().st_mode))

    def test_materialize_rejects_duplicate_or_invalid_client_ids(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/".state"/"private"/"oauth.json"
            clients={name:"same" for name in mod.CLIENTS}
            with self.assertRaisesRegex(RuntimeError,"CLIENT_ID_REUSE"):
                mod.materialize(out,clients)
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}; clients["grok"]="bad\nvalue"
            with self.assertRaisesRegex(RuntimeError,"CLIENT_ID_INVALID"):
                mod.materialize(out,clients)

    def test_materialize_is_no_replace_but_idempotent_for_identical_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/".state"/"private"/"oauth.json"
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}
            first=mod.materialize(out,clients)
            second=mod.materialize(out,clients)
            self.assertEqual(first,second)
            changed=dict(clients); changed["grok"]="oauth-grok-changed"
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_CONFLICT"):
                mod.materialize(out,changed)

    def test_existing_bytes_does_not_reopen_replaced_path(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            out=root/"binding.json"
            replacement=root/"replacement.json"
            original=b"original-private-oauth-binding"
            replacement_bytes=b"replacement-private-oauth-binding"
            out.write_bytes(original)
            replacement.write_bytes(replacement_bytes)
            if os.name!="nt":
                out.chmod(0o600); replacement.chmod(0o600)
            real_read_bytes=Path.read_bytes

            def replace_before_reopen(path):
                if path==out:
                    os.replace(replacement,out)
                return real_read_bytes(path)

            with mock.patch.object(Path,"read_bytes",autospec=True,side_effect=replace_before_reopen):
                observed=mod._existing_bytes(out)
            self.assertEqual(original,observed)

    def test_output_must_live_under_state_private_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PATH_INVALID"):
                mod.materialize(root/"oauth.json",clients,root=root)

    def test_explicit_symlinked_repository_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            out=root/".state"/"private"/"oauth.json"
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}
            original=Path.is_symlink
            def fake(path):
                candidate=Path(path)
                return candidate==root or original(candidate)
            with mock.patch.object(Path,"is_symlink",fake):
                with self.assertRaisesRegex(RuntimeError,"OUTPUT_PATH_INVALID"):
                    mod.materialize(out,clients,root=root)

    def test_symlinked_state_parent_is_rejected_before_private_directory_creation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            attacker=root/"attacker"; attacker.mkdir()
            try:
                (root/".state").symlink_to(attacker,target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PATH_INVALID"):
                mod.materialize(root/".state"/"private"/"oauth.json",clients,root=root)
            self.assertFalse((attacker/"private").exists())

    def test_followup_preflight_preserves_repository_endpoint_and_token_env_name_without_token_value(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            out=root/".state/private/c7w-oauth-client-bindings.json"
            command=mod.followup_preflight_command(root,out,"https://mcp.example.test/mcp","C7W_PLATFORM_ADMIN_TOKEN")
        self.assertIn("scripts/c7w_preflight.py",command)
        self.assertIn("--endpoint",command)
        self.assertIn("https://mcp.example.test/mcp",command)
        self.assertIn("--token-env",command)
        self.assertIn("C7W_PLATFORM_ADMIN_TOKEN",command)
        self.assertIn("--oauth-client-map",command)
        self.assertIn(str(out),command)
        self.assertEqual(str(root),command[command.index("--root")+1])
        self.assertNotIn("secret-token-value",command)


if __name__=="__main__":
    unittest.main()
