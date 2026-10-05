import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_authority_gate_root",ROOT/"scripts"/"c7w_execution_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WRunnerRootAuthorityTests(unittest.TestCase):
    def test_working_directory_rejects_noncanonical_root_binding(self):
        source='''\nfrom pathlib import Path\ndef main():\n    root=Path("/tmp")\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(source))

    def test_canonical_outputs_reject_noncanonical_root_binding(self):
        source='''\nfrom pathlib import Path\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    root=Path("/tmp")\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    return None\n'''
        errors=mod.canonical_output_contract_errors(source)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_rejects_root_drift_after_valid_binding(self):
        workdir='''\nfrom pathlib import Path\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    root=Path("/tmp")\n    return result\n'''
        outputs='''\nfrom pathlib import Path\nCANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")\nCANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")\ndef require_canonical_artifact_path(*args): pass\ndef main():\n    root=Path.cwd().resolve()\n    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")\n    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")\n    root=Path("/tmp")\n    return None\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(workdir))
        errors=mod.canonical_output_contract_errors(outputs)
        self.assertIn("PROGRESS_OUTPUT_WIRING_INVALID",errors)
        self.assertIn("EVIDENCE_OUTPUT_WIRING_INVALID",errors)

    def test_accepts_canonical_root_binding(self):
        source='''\nfrom pathlib import Path\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertEqual([],mod.runner_working_directory_contract_errors(source))


if __name__=="__main__":
    unittest.main()
