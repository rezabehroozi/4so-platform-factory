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

    def test_canonical_runner_root_rejects_walrus_rebind(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    if (root := Path(".")):\n        pass\n    return {}\n'''
        function=ast.parse(source).body[0]
        self.assertFalse(mod.canonical_runner_root_bound(function))

    def test_args_authority_alias_rejects_walrus_capture(self):
        source='''\ndef main():\n    if (alias := args):\n        pass\n    return None\n'''
        function=ast.parse(source).body[0]
        self.assertTrue(mod.direct_authority_alias_present(function,"args"))


if __name__=="__main__":
    unittest.main()
