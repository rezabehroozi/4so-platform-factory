import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("release_tool_authority_gate_c9_cli_input",ROOT/"scripts"/"release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9CLIInputAuthorityTests(unittest.TestCase):
    def test_working_directory_rejects_precanonical_args_root_mutation(self):
        direct='''\ndef main():\n    setattr(args,"root",Path("other"))\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        aliased='''\ndef main():\n    alias=args\n    setattr(alias,"root",Path("other"))\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        rebound='''\ndef main():\n    args=other\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        for source in (direct,aliased,rebound):
            self.assertFalse(mod.c9_main_working_directory_bound(source))

    def test_canonical_output_rejects_precanonical_args_mutation(self):
        root_mutation='''\ndef main():\n    args.root=Path("other")\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        out_mutation='''\ndef main():\n    root=args.root.resolve()\n    args.__dict__.update({"out":Path("other.json")})\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        aliased='''\ndef main():\n    alias=args\n    setattr(alias,"out",Path("other.json"))\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        for source in (root_mutation,out_mutation,aliased):
            self.assertFalse(mod.c9_main_canonical_output_bound(source))

    def test_rejects_derived_mutable_args_mapping_aliases(self):
        dict_alias='''\ndef main():\n    namespace=args.__dict__\n    namespace["root"]=Path("other")\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        vars_alias='''\ndef main():\n    namespace=vars(args)\n    namespace["out"]=Path("other.json")\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        self.assertFalse(mod.c9_main_canonical_output_bound(dict_alias))
        self.assertFalse(mod.c9_main_canonical_output_bound(vars_alias))


if __name__=="__main__":
    unittest.main()
