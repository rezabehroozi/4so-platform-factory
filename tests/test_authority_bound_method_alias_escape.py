import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


c7w=load("scripts/c7w_execution_authority_gate.py","c7w_bound_method_alias")
c9=load("scripts/release_tool_authority_gate.py","c9_bound_method_alias")


class AuthorityBoundMethodAliasEscapeTests(unittest.TestCase):
    def test_c7w_detects_result_bound_reader_method_alias(self):
        function=ast.parse('''\ndef main():\n    result={}\n    reader=result.items\n    reader.__self__.update({"workingDirectory":"."})\n''').body[0]
        self.assertTrue(c7w.direct_authority_alias_present(function,"result"))

    def test_c7w_rejects_result_bound_reader_escape_after_projection(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    reader=result.items\n    reader.__self__.update({"workingDirectory":"."})\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",c7w.runner_working_directory_contract_errors(source))

    def test_c9_detects_evidence_bound_reader_method_alias(self):
        function=ast.parse('''\ndef main():\n    evidence={}\n    reader=evidence.items\n    reader.__self__.clear()\n''').body[0]
        self.assertTrue(c9.direct_authority_alias_present(function,"evidence"))

    def test_c9_rejects_evidence_bound_reader_escape_after_projection(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    reader=evidence.items\n    reader.__self__.clear()\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))

    def test_c9_rejects_container_bound_reader_method_escape(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    reader={"e":evidence}.values\n    reader.__self__["e"].clear()\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))


if __name__=="__main__":
    unittest.main()
