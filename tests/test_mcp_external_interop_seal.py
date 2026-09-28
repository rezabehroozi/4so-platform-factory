import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mcpseal",ROOT/"scripts"/"seal_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class MCPExternalSealTests(unittest.TestCase):
    def campaign(self,matrix_path,endpoint="https://mcp.example.test/mcp"):
        rows=[]
        for c in mod.CLIENTS:
            challenge=("challenge-"+c+"-")*4
            rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest()})
        return {"authority":mod.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","matrixAuthority":mod.MATRIX_AUTHORITY,"matrixSha256":mod.sha256(matrix_path),"protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"clients":rows,"externalExecutionRequired":True}
    def receipt(self,client,checks,campaign,endpoint="https://mcp.example.test/mcp"):
        challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
        return {"authority":mod.RECEIPT_AUTHORITY,"clientId":client,"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"executionId":"run-"+client,"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def fixture(self,root):
        matrix_path=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
        matrix=json.loads(matrix_path.read_text()); checks=matrix["spec"]["sharedRequiredChecks"]
        campaign=self.campaign(matrix_path); campaign_path=root/"campaign.json"; campaign_path.write_text(json.dumps(campaign))
        receipts=root/"receipts"; receipts.mkdir()
        for c in mod.CLIENTS:(receipts/(c+".json")).write_text(json.dumps(self.receipt(c,checks,campaign)))
        return matrix_path,campaign_path,receipts,campaign,checks
    def test_four_named_clients_are_campaign_bound_and_sealed(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,campaign,_=self.fixture(Path(td))
            out=mod.seal(matrix,campaign_path,receipts)
            self.assertEqual(4,out["certifiedClientCount"]); self.assertEqual(campaign["campaignId"],out["campaignId"]); self.assertTrue(out["externalCertificationPass"]); self.assertFalse(out["runtimeCertified"]); self.assertFalse(out["physicalCertified"])
    def test_replay_negative_control_and_endpoint_drift_reject(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,campaign,checks=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["challengeSha256"]="sha256:"+"0"*64; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_BINDING"):mod.seal(matrix,campaign_path,receipts)
            (receipts/"chatgpt.json").write_text(json.dumps(self.receipt("chatgpt",checks,campaign,"https://other.example.test/mcp")))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_ENDPOINT"):mod.seal(matrix,campaign_path,receipts)
    def test_missing_negative_control_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,_,_=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["revokedGrantAccepted"]=True; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"NEGATIVE_CONTROL"):mod.seal(matrix,campaign_path,receipts)

if __name__=="__main__": unittest.main()
