import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_execution_bindings",ROOT/"scripts"/"c7w_execution_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingsTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root:Path)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"seed.txt").write_text("seed\n")
        self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed")
        return self.git(root,"rev-parse","HEAD")

    def resources(self):
        return {
            "foreignProjectId":"project-foreign-001",
            "sameProjectOperationId":"operation-cancellable-001",
            "selfApprovalRequestId":"approval-request-001",
        }

    def test_materialize_is_private_source_bound_non_secret_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source_sha=self.repo(root)
            out=root/".state/private/c7w-execution-bindings.json"
            result=mod.materialize(out,self.resources(),source_sha,root=root)
            value=json.loads(out.read_text())
            self.assertEqual(mod.AUTHORITY,value["authority"])
            self.assertEqual(source_sha,value["sourceCommitSHA"])
            self.assertEqual(self.resources(),value["resources"])
            self.assertEqual(mod.credential_contract()["authority"],value["credentialProfileContractAuthority"])
            self.assertRegex(value["credentialProfileContractSha256"],r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(str(out),result["path"])
            self.assertEqual(value["credentialProfileContractSha256"],result["credentialProfileContractSha256"])
            self.assertFalse(result["physicalCertified"])
            raw=out.read_text().lower()
            for forbidden in ("access_token","refresh_token","clientsecret","bearer "):
                self.assertNotIn(forbidden,raw)
            before=out.read_bytes()
            again=mod.materialize(out,self.resources(),source_sha,root=root)
            self.assertEqual(before,out.read_bytes())
            self.assertEqual(result["sha256"],again["sha256"])

    def test_load_rejects_source_drift_and_placeholder_resources(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source_sha=self.repo(root)
            out=root/".state/private/c7w-execution-bindings.json"
            mod.materialize(out,self.resources(),source_sha,root=root)
            with self.assertRaisesRegex(RuntimeError,"SOURCE_MISMATCH"):
                mod.load(out,"f"*40)

            bad=dict(self.resources()); bad["foreignProjectId"]="<foreign-project-id>"
            other=root/".state/private/c7w-bad-bindings.json"
            with self.assertRaisesRegex(RuntimeError,"RESOURCE_INVALID"):
                mod.materialize(other,bad,source_sha,root=root)

    def test_materialize_refuses_conflicting_existing_private_file(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source_sha=self.repo(root)
            out=root/".state/private/c7w-execution-bindings.json"
            mod.materialize(out,self.resources(),source_sha,root=root)
            changed=dict(self.resources()); changed["foreignProjectId"]="project-foreign-002"
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_CONFLICT"):
                mod.materialize(out,changed,source_sha,root=root)

    def test_credential_contract_digest_is_canonical_and_complete(self):
        contract=mod.credential_contract()
        raw=json.dumps(contract,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
        expected="sha256:"+hashlib.sha256(raw).hexdigest()
        self.assertEqual(expected,mod.credential_contract_digest())
        self.assertEqual({
            "none","valid-user-token-wrong-resource-audience","campaign-delegated-user",
            "project-scoped-delegation","revoked-campaign-delegation","view-delegation",
            "administration-delegation-requester",
        },set(contract["profiles"]))


if __name__=="__main__": unittest.main()
