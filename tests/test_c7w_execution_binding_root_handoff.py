import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_binding_root_handoff",ROOT/"scripts"/"c7w_execution_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingRootHandoffTests(unittest.TestCase):
    def test_followup_preflight_canonicalizes_repository_alias_output_and_script(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); root=base/"repo"; root.mkdir(); alias=base/"repo-alias"
            try:
                alias.symlink_to(root,target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            output=alias/".state/private/c7w-execution-bindings.json"
            command=mod.followup_preflight_command(alias,output,"https://mcp.example.test/mcp",None,"TOKEN")
        root_index=command.index("--root")+1
        output_index=command.index("--execution-bindings")+1
        self.assertEqual(str((root/"scripts/c7w_preflight.py").resolve()),command[1])
        self.assertEqual(str(root.resolve()),command[root_index])
        self.assertEqual(str((root/".state/private/c7w-execution-bindings.json").resolve()),command[output_index])


if __name__=="__main__":
    unittest.main()
