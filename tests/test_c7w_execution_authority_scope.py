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

    def test_external_action_owner_rejects_mixed_safe_and_unsafe_returns(self):
        source='''\ndef external_client_action():\n    if runtime_condition:\n        return {"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":[],"nextClientHandoff":{},"postExternalExecutionCommand":[]}\n    return {"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":["python","admit.py"],"nextClientHandoff":{},"postExternalExecutionCommand":[]}\ndef prepare(): return external_client_action()\ndef admit(): return external_client_action()\ndef status(): return external_client_action()\n'''
        errors=mod.external_client_action_contract_errors(source)
        self.assertIn("EXTERNAL_ACTION_SHAPE_INVALID",errors)

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

    def test_canonical_output_wiring_rejects_annotated_and_augmented_reassignment(self):
        annotated='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    args.progress_out: Path=Path("alternate-progress.json")\n    return None\n'''
        augmented='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    args.progress_out /= "alternate"\n    return None\n'''
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(annotated))
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(augmented))

    def test_canonical_output_wiring_rejects_direct_call_mutation(self):
        overwritten='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    setattr(args,"progress_out",Path("alternate-progress.json"))\n    return None\n'''
        deleted='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    delattr(args,"evidence_out")\n    return None\n'''
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(overwritten))
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(deleted))

    def test_canonical_output_wiring_rejects_args_alias_mutation(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    alias=args\n    setattr(alias,"progress_out",Path("alternate-progress.json"))\n    return None\n'''
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(source))

    def test_canonical_output_wiring_rejects_unknown_args_helper_exposure(self):
        source='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef taint(value): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    taint(args)\n    return None\n'''
        errors=mod.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_canonical_output_wiring_rejects_derived_args_mapping_aliases(self):
        vars_alias='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    mapping=vars(args)\n    mapping["progress_out"]=Path("alternate-progress.json")\n    return None\n'''
        dict_alias='''\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    mapping=args.__dict__\n    mapping["evidence_out"]=Path("alternate-evidence.json")\n    return None\n'''
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(vars_alias))
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",mod.canonical_output_contract_errors(dict_alias))

    def test_working_directory_wiring_rejects_conditional_projection(self):
        source='''\ndef main():\n    result={}\n    if runtime_condition:\n        result["workingDirectory"]=str(root)\n    return result\n'''
        errors=mod.runner_working_directory_contract_errors(source)
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",errors)

    def test_working_directory_wiring_rejects_late_overwrite_or_result_rebind(self):
        overwritten='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"]="."\n    return result\n'''
        rebound='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result={}\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(overwritten))
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(rebound))

    def test_working_directory_wiring_rejects_annotated_and_augmented_overwrite(self):
        annotated='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"]: str="."\n    return result\n'''
        augmented='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result["workingDirectory"] += "/tmp"\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(annotated))
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(augmented))

    def test_working_directory_wiring_rejects_direct_call_mutation(self):
        updated='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result.update({"workingDirectory":"."})\n    return result\n'''
        removed='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    result.pop("workingDirectory")\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(updated))
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(removed))

    def test_working_directory_wiring_rejects_result_alias_mutation(self):
        source='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    alias=result\n    alias.pop("workingDirectory")\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(source))

    def test_working_directory_wiring_rejects_unknown_result_helper_exposure(self):
        tainted='''\ndef taint(value): pass\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    taint(result)\n    return result\n'''
        safe='''\ndef main():\n    result={}\n    result["workingDirectory"]=str(root)\n    print(json.dumps(result,sort_keys=True))\n    return 0\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(tainted))
        self.assertEqual([],mod.runner_working_directory_contract_errors(safe))


if __name__=="__main__":
    unittest.main()
