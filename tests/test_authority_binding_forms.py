import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


c7w=load("scripts/c7w_execution_authority_gate.py","c7w_binding_forms")
c9=load("scripts/release_tool_authority_gate.py","c9_binding_forms")


class AuthorityBindingFormsTests(unittest.TestCase):
    def assert_bound(self,mod,node,name):
        targets,_=mod.assignment_targets_and_value(node)
        names=[target.id for target in targets if isinstance(target,ast.Name)]
        self.assertIn(name,names)

    def test_extractors_cover_outer_scope_binding_forms(self):
        nodes=[
            (ast.parse("for root in rows:\n    pass\n").body[0],"root"),
            (ast.parse("with ctx() as root:\n    pass\n").body[0],"root"),
            (ast.parse("try:\n    pass\nexcept Error as root:\n    pass\n").body[0].handlers[0],"root"),
            (ast.parse("def root():\n    pass\n").body[0],"root"),
            (ast.parse("class root:\n    pass\n").body[0],"root"),
            (ast.parse("import package as root\n").body[0],"root"),
            (ast.parse("from package import member as root\n").body[0],"root"),
            (ast.parse("match value:\n    case root:\n        pass\n").body[0].cases[0].pattern,"root"),
        ]
        for mod in (c7w,c9):
            for node,name in nodes:
                with self.subTest(module=mod.__name__,node=type(node).__name__):
                    self.assert_bound(mod,node,name)

    def test_c7w_root_rejects_for_rebind(self):
        source='''\ndef main():\n    root=Path.cwd().resolve()\n    for root in [Path(".")]:\n        pass\n    return {}\n'''
        function=ast.parse(source).body[0]
        self.assertFalse(c7w.canonical_runner_root_bound(function))

    def test_c7w_args_rejects_with_rebind(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    root=Path.cwd().resolve()\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    with context() as args:\n        pass\n    return None\n'''
        errors=c7w.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_c7w_rejects_match_subject_alias_escape(self):
        source='''\ndef main():\n    match args:\n        case alias:\n            pass\n    return None\n'''
        function=ast.parse(source).body[0]
        self.assertTrue(c7w.direct_authority_alias_present(function,"args"))

    def test_c9_output_rejects_for_rebind(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    for out in [args.out]:\n        pass\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))

    def test_c9_working_directory_rejects_definition_rebind(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    def root():\n        pass\n    return result\n'''
        self.assertFalse(c9.c9_main_working_directory_bound(source))

    def test_c9_rejects_match_subject_alias_escape(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    match evidence:\n        case alias:\n            pass\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))

    def test_c9_working_directory_rejects_match_result_alias_escape(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    match result:\n        case alias:\n            pass\n    return result\n'''
        self.assertFalse(c9.c9_main_working_directory_bound(source))


if __name__=="__main__":
    unittest.main()
