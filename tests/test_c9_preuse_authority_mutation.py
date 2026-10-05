import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c9_preuse_authority",ROOT/"scripts"/"release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9PreUseAuthorityMutationTests(unittest.TestCase):
    def test_canonical_output_rejects_conditional_root_drift_before_execute(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    if runtime_condition:\n        root=args.root\n    evidence=execute(root,out)\n    return evidence\n'''
        self.assertFalse(mod.c9_main_canonical_output_bound(source))

    def test_canonical_output_rejects_conditional_out_drift_before_execute(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    if runtime_condition:\n        out=args.out\n    evidence=execute(root,out)\n    return evidence\n'''
        self.assertFalse(mod.c9_main_canonical_output_bound(source))

    def test_working_directory_rejects_conditional_root_drift_before_projection(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    if runtime_condition:\n        root=args.root\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_literal_false_preuse_drift_remains_ignored(self):
        output='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    if False:\n        root=args.root\n        out=args.out\n    evidence=execute(root,out)\n    return evidence\n'''
        workdir='''\ndef main():\n    root=args.root.resolve()\n    if False:\n        root=args.root\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertTrue(mod.c9_main_canonical_output_bound(output))
        self.assertTrue(mod.c9_main_working_directory_bound(workdir))


if __name__=="__main__":
    unittest.main()
