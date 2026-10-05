import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_namedexpr_authority",ROOT/"scripts"/"c7w_execution_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WNamedExpressionAuthorityTests(unittest.TestCase):
    def test_assignment_extractor_treats_named_expression_as_mutation(self):
        named=ast.parse("if (alias := args):\n    pass\n").body[0].test
        targets,value=mod.assignment_targets_and_value(named)
        self.assertEqual(1,len(targets))
        self.assertIsInstance(targets[0],ast.Name)
        self.assertEqual("alias",targets[0].id)
        self.assertIsInstance(value,ast.Name)
        self.assertEqual("args",value.id)

    def test_assignment_extractor_treats_delete_as_mutation(self):
        deleted=ast.parse("del args.progress_out\n").body[0]
        targets,value=mod.assignment_targets_and_value(deleted)
        self.assertEqual(1,len(targets))
        self.assertIsInstance(targets[0],ast.Attribute)
        self.assertEqual("progress_out",targets[0].attr)
        self.assertIsNone(value)

    def test_canonical_runner_root_rejects_walrus_rebind(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    if (root := Path(".")):\n        pass\n    return {}\n'''
        function=ast.parse(source).body[0]
        self.assertFalse(mod.canonical_runner_root_bound(function))

    def test_args_authority_alias_rejects_walrus_capture(self):
        source='''\ndef main():\n    if (alias := args):\n        pass\n    return None\n'''
        function=ast.parse(source).body[0]
        self.assertTrue(mod.direct_authority_alias_present(function,"args"))

    def test_canonical_output_rejects_delete_after_guard(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    root=Path.cwd().resolve()\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    del args.progress_out\n    return None\n'''
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(source))

    def test_working_directory_rejects_delete_after_projection(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    del result["workingDirectory"]\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(source))


if __name__=="__main__":
    unittest.main()