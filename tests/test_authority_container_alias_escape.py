import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


c7w=load("scripts/c7w_execution_authority_gate.py","c7w_container_alias")
c9=load("scripts/release_tool_authority_gate.py","c9_container_alias")


class AuthorityContainerAliasEscapeTests(unittest.TestCase):
    def test_c7w_detects_attribute_and_subscript_args_escape(self):
        attribute=ast.parse('''\ndef main():\n    holder.value=args\n    return None\n''').body[0]
        nested=ast.parse('''\ndef main():\n    holder["args"]={"value":args}\n    return None\n''').body[0]
        self.assertTrue(c7w.direct_authority_alias_present(attribute,"args"))
        self.assertTrue(c7w.direct_authority_alias_present(nested,"args"))

    def test_c7w_detects_conditional_container_args_escape(self):
        expressions=(
            "args if runtime_condition else None",
            "args or None",
            "[args for _ in range(1)]",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                source=f'''\ndef main():\n    holder.value={expression}\n    return None\n'''
                self.assertTrue(c7w.direct_authority_alias_present(ast.parse(source).body[0],"args"))

    def test_c7w_working_directory_rejects_result_escape(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    holder.value=result\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",c7w.runner_working_directory_contract_errors(source))

    def test_c9_detects_attribute_and_nested_evidence_escape(self):
        attribute='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    holder.value=evidence\n    return evidence\n'''
        nested='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    holder["e"]={"value":evidence}\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(attribute))
        self.assertFalse(c9.c9_main_canonical_output_bound(nested))

    def test_c9_rejects_conditional_container_evidence_escape(self):
        expressions=(
            "evidence if runtime_condition else None",
            "evidence or None",
            "[evidence for _ in range(1)]",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                source=f'''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    holder.value={expression}\n    return evidence\n'''
                self.assertFalse(c9.c9_main_canonical_output_bound(source))

    def test_c9_working_directory_rejects_result_escape(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    holder.value=result\n    return result\n'''
        self.assertFalse(c9.c9_main_working_directory_bound(source))

    def test_c9_rejects_args_escape_into_container(self):
        source='''\ndef main():\n    parser=argparse.ArgumentParser()\n    args=parser.parse_args()\n    holder.value={"args":args}\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))


if __name__=="__main__":
    unittest.main()
