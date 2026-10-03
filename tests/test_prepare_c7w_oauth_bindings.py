import importlib.util, json, os, stat, tempfile, unittest
from pathlib import Path

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

    def test_output_must_live_under_state_private_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            clients={name:f"oauth-{name}" for name in mod.CLIENTS}
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PATH_INVALID"):
                mod.materialize(root/"oauth.json",clients,root=root)

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


if __name__=="__main__":
    unittest.main()
