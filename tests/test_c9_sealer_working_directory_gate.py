import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("release_tool_authority_gate_c9_workdir",ROOT/"scripts"/"release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9SealerWorkingDirectoryGateTests(unittest.TestCase):
    def test_rejects_missing_post_seal_working_directory_projection(self):
        source='''\ndef main():\n    result={}\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_accepts_reachable_canonical_root_projection(self):
        source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertTrue(mod.c9_main_working_directory_bound(source))

    def test_rejects_unbound_dead_branch_split_or_overwritten_projection(self):
        unbound='''\ndef main():\n    root=args.root\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        dead='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    if False:\n        result["workingDirectory"]=str(root)\n    def ignored():\n        result["workingDirectory"]=str(root)\n    return result\n'''
        split='''\ndef main():\n    result={}\n    if runtime_condition:\n        root=args.root.resolve()\n    else:\n        result["workingDirectory"]=str(root)\n    return result\n'''
        overwritten='''\ndef main():\n    root=args.root.resolve()\n    root=args.root\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        late_overwrite='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"]=str(args.root)\n    return result\n'''
        result_rebound='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result={}\n    return result\n'''
        self.assertFalse(mod.c9_main_working_directory_bound(unbound))
        self.assertFalse(mod.c9_main_working_directory_bound(dead))
        self.assertFalse(mod.c9_main_working_directory_bound(split))
        self.assertFalse(mod.c9_main_working_directory_bound(overwritten))
        self.assertFalse(mod.c9_main_working_directory_bound(late_overwrite))
        self.assertFalse(mod.c9_main_working_directory_bound(result_rebound))

    def test_rejects_nonstandard_working_directory_mutations(self):
        annotated='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"]: str="."\n    return result\n'''
        augmented='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"] += "/tmp"\n    return result\n'''
        updated='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result.update({"workingDirectory":"."})\n    return result\n'''
        removed='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    result.pop("workingDirectory")\n    return result\n'''
        for source in (annotated,augmented,updated,removed):
            self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_requires_canonical_output_before_execute_on_same_path(self):
        good='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        bypass='''\ndef main():\n    root=args.root.resolve()\n    evidence=execute(root,args.out)\n    return evidence\n'''
        dead='''\ndef main():\n    root=args.root.resolve()\n    if False:\n        out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,args.out)\n    return evidence\n'''
        split='''\ndef main():\n    root=args.root.resolve()\n    if runtime_condition:\n        out=canonical_cli_output_path(root,args.out)\n    else:\n        evidence=execute(root,out)\n    return evidence\n'''
        overwritten='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    out=args.out\n    evidence=execute(root,out)\n    return evidence\n'''
        root_drift='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    root=args.root\n    evidence=execute(root,out)\n    return evidence\n'''
        late_execute='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    evidence=execute(root,args.out)\n    return evidence\n'''
        late_out_drift='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    out=args.out\n    return evidence\n'''
        late_root_drift='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    root=args.root\n    return evidence\n'''
        self.assertTrue(mod.c9_main_canonical_output_bound(good))
        self.assertFalse(mod.c9_main_canonical_output_bound(bypass))
        self.assertFalse(mod.c9_main_canonical_output_bound(dead))
        self.assertFalse(mod.c9_main_canonical_output_bound(split))
        self.assertFalse(mod.c9_main_canonical_output_bound(overwritten))
        self.assertFalse(mod.c9_main_canonical_output_bound(root_drift))
        self.assertFalse(mod.c9_main_canonical_output_bound(late_execute))
        self.assertFalse(mod.c9_main_canonical_output_bound(late_out_drift))
        self.assertFalse(mod.c9_main_canonical_output_bound(late_root_drift))

    def test_rejects_nonstandard_canonical_output_mutations(self):
        annotated='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    out: Path=args.out\n    return evidence\n'''
        augmented='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    out /= "alternate"\n    return evidence\n'''
        root_setattr='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    setattr(args,"root",Path("."))\n    return evidence\n'''
        evidence_rebind='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    evidence += {"drift":True}\n    return evidence\n'''
        for source in (annotated,augmented,root_setattr,evidence_rebind):
            self.assertFalse(mod.c9_main_canonical_output_bound(source))


if __name__=="__main__":
    unittest.main()