import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c9_namedexpr_authority",ROOT/"scripts"/"release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9NamedExpressionAuthorityTests(unittest.TestCase):
    def test_assignment_extractor_treats_named_expression_as_mutation(self):
        named=ast.parse("if (alias := evidence):\n    pass\n").body[0].test
        targets,value=mod.assignment_targets_and_value(named)
        self.assertEqual(1,len(targets))
        self.assertIsInstance(targets[0],ast.Name)
        self.assertEqual("alias",targets[0].id)
        self.assertIsInstance(value,ast.Name)
        self.assertEqual("evidence",value.id)

    def test_canonical_output_rejects_walrus_root_rebind(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    if (root := args.root):\n        pass\n    return evidence\n'''
        self.assertFalse(mod.c9_main_canonical_output_bound(source))

    def test_working_directory_rejects_walrus_root_rebind(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    if (root := args.root):\n        pass\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_evidence_alias_rejects_walrus_capture(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    if (alias := evidence):\n        alias.update({"drift":True})\n    return evidence\n'''
        self.assertFalse(mod.c9_main_canonical_output_bound(source))


if __name__=="__main__":
    unittest.main()
