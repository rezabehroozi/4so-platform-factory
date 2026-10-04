import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_authority_gate_scope",ROOT/"scripts"/"c7w_execution_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionAuthorityScopeTests(unittest.TestCase):
    def test_external_action_wiring_ignores_nested_and_false_branch_calls(self):
        source='''\ndef external_client_action():\n    return {"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":[],"nextClientHandoff":{},"postExternalExecutionCommand":[]}\ndef prepare():\n    def dead():\n        return external_client_action()\n    if False:\n        return external_client_action()\n    return {}\ndef admit(): return external_client_action()\ndef status(): return external_client_action()\n'''
        errors=mod.external_client_action_contract_errors(source)
        self.assertIn("PREPARE_EXTERNAL_ACTION_WIRING_INVALID",errors)

    def test_canonical_output_wiring_ignores_nested_and_false_branch_assignments(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(): pass\ndef main():\n    def dead():\n        args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    if False:\n        args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    return None\n'''
        errors=mod.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_canonical_output_wiring_rejects_runtime_branch_split(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    if runtime_condition:\n        args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    else:\n        args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    return None\n'''
        errors=mod.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_canonical_output_wiring_rejects_late_reassignment(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    args.progress_out=Path("alternate-progress.json")\n    return None\n'''
        errors=mod.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertNotIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_working_directory_wiring_rejects_conditional_projection(self):
        source='''\ndef main():\n    result={}\n    if runtime_condition:\n        result["workingDirectory"]=str(root)\n    return result\n'''
        errors=mod.runner_working_directory_contract_errors(source)
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",errors)

    def test_working_directory_wiring_rejects_late_overwrite_or_result_rebind(self):
        overwritten='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"]="."\n    return result\n'''
        rebound='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result={}\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(overwritten))
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(rebound))


if __name__=="__main__":
    unittest.main()
