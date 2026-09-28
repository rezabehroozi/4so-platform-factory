import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SEAL_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
seal=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(seal)
import sys; sys.modules["seal_mcp_external_interop"]=seal
SPEC=importlib.util.spec_from_file_location("progress",ROOT/"scripts"/"admit_mcp_external_receipt.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class IncrementalMCPInteropTests(unittest.TestCase):
    def campaign(self,matrix):
        rows=[]
        for c in seal.CLIENTS:
            challenge=("incremental-"+c+"-")*4
            rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest()})
        return {"authority":seal.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-incremental","matrixAuthority":seal.MATRIX_AUTHORITY,"matrixSha256":seal.sha256(matrix),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","clients":rows,"externalExecutionRequired":True}
    def receipt(self,client,checks,campaign,execution=None):
        challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
        return {"authority":seal.RECEIPT_AUTHORITY,"clientId":client,"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"protocol":"2026-07-28","transport":"streamable-http","endpoint":campaign["endpoint"],"executionId":execution or "run-"+client,"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def test_receipts_merge_incrementally_and_fourth_seals(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            for idx,client in enumerate(seal.CLIENTS,1):
                rp=root/(client+".json"); rp.write_text(json.dumps(self.receipt(client,checks,campaign)))
                out=mod.merge(matrix,cp,rp,client,progress if progress.exists() else None)
                progress.write_text(json.dumps(out))
                self.assertEqual(idx,out["certifiedClientCount"]); self.assertEqual(idx==4,out["complete"])
            evidence=mod.final_evidence(out,progress)
            self.assertEqual(4,evidence["certifiedClientCount"]); self.assertTrue(evidence["externalCertificationPass"]); self.assertFalse(evidence["runtimeCertified"]); self.assertFalse(evidence["physicalCertified"])
    def test_divergent_replacement_and_campaign_drift_reject(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            rp=root/"chatgpt.json"; rp.write_text(json.dumps(self.receipt("chatgpt",checks,campaign)))
            out=mod.merge(matrix,cp,rp,"chatgpt",None); progress.write_text(json.dumps(out))
            rp.write_text(json.dumps(self.receipt("chatgpt",checks,campaign,"different-run")))
            with self.assertRaisesRegex(RuntimeError,"REPLACEMENT_FORBIDDEN"): mod.merge(matrix,cp,rp,"chatgpt",progress)
            campaign["campaignId"]="mcp-interop-other"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_DRIFT|CAMPAIGN_BINDING"): mod.merge(matrix,cp,rp,"chatgpt",progress)

if __name__=="__main__": unittest.main()
