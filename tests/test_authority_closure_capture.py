import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


c7w=load("scripts/c7w_execution_authority_gate.py","c7w_execution_authority_gate_closure_capture")
c9=load("scripts/release_tool_authority_gate.py","release_tool_authority_gate_closure_capture")


class AuthorityClosureCaptureTests(unittest.TestCase):
    def test_c7w_rejects_args_closure_capture_after_canonical_guards(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    def mutate():\n        setattr(args,"progress_out",Path("alternate-progress.json"))\n    mutate()\n    return None\n'''
        errors=c7w.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_c7w_rejects_result_closure_capture_after_working_directory_projection(self):
        source='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    def mutate():\n        result.pop("workingDirectory")\n    mutate()\n    return result\n'''
        self.assertIn(
            "RUNNER_WORKING_DIRECTORY_WIRING_INVALID",
            c7w.runner_working_directory_contract_errors(source),
        )

    def test_c9_rejects_args_closure_capture_before_canonicalization(self):
        source='''\ndef main():\n    def mutate():\n        setattr(args,"root",Path("other"))\n    mutate()\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    return evidence\n'''
        self.assertFalse(c9.c9_main_canonical_output_bound(source))

    def test_c9_rejects_result_and_evidence_closure_capture(self):
        workdir='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    def mutate():\n        result.pop("workingDirectory")\n    mutate()\n    return result\n'''
        evidence='''\ndef main():\n    root=args.root.resolve()\n    out=canonical_cli_output_path(root,args.out)\n    evidence=execute(root,out)\n    def mutate():\n        evidence.update({"drift":True})\n    mutate()\n    return evidence\n'''
        self.assertFalse(c9.c9_main_working_directory_bound(workdir))
        self.assertFalse(c9.c9_main_canonical_output_bound(evidence))

    def test_parameter_shadow_does_not_count_as_closure_capture(self):
        c7w_source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    def helper(args):\n        return args\n    return None\n'''
        c9_source='''\ndef main():\n    root=args.root.resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    def helper(result):\n        return result\n    return result\n'''
        self.assertEqual([],c7w.canonical_output_contract_errors(c7w_source))
        self.assertTrue(c9.c9_main_working_directory_bound(c9_source))


if __name__=="__main__":
    unittest.main()
