import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("release_tool_authority_gate_c9_workdir",ROOT/"scripts/release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9SealerWorkingDirectoryGateTests(unittest.TestCase):
    def test_rejects_missing_post_seal_working_directory_projection(self):
        source='''\ndef main():\n    result={}\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_accepts_reachable_args_root_projection(self):
        source='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(args.root.resolve())\n    return result\n'''
        self.assertTrue(mod.c9_main_working_directory_bound(source))

    def test_rejects_dead_or_nested_projection(self):
        source='''\ndef main():\n    result={}\n    if False:\n        result["workingDirectory"]=str(args.root.resolve())\n    def dead():\n        result["workingDirectory"]=str(args.root.resolve())\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_requires_canonical_output_before_execute(self):
        good='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        bypass='''\ndef main():\n    root=args.root.resolve()\n    evidence=execute(root,args.out)\n    return evidence\n'''
        dead='''\ndef main():\n    root=args.root.resolve()\n    if False:\n        out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,args.out)\n    return evidence\n'''
        self.assertTrue(mod.c9_main_canonical_output_bound(good))
        self.assertFalse(mod.c9_main_canonical_output_bound(bypass))
        self.assertFalse(mod.c9_main_canonical_output_bound(dead))


if __name__=="__main__":
    unittest.main()
