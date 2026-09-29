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
    def request_ids(self,client):
        return {name:f"{client}-{idx:02d}-request" for idx,name in enumerate(mod.AUDITED_CHECKS,1)}
    def receipt(self,client,checks,campaign,endpoint="https://mcp.example.test/mcp"):
        challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
        return {"authority":mod.RECEIPT_AUTHORITY,"clientId":client,"clientSurface":mod.CLIENT_SURFACES[client],"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"executionId":"run-"+client,"providerExecutionRef":"provider-execution-"+client,"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"requestIds":self.request_ids(client),"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def audit(self,receipt):
        rows=[]; prev=""; seq=1
        for check in mod.AUDITED_CHECKS:
            category,decision,reason=mod.AUDIT_REQUIREMENTS[check]
            digest="sha256:"+hashlib.sha256(f"{receipt['clientId']}:{seq}".encode()).hexdigest()
            rows.append({"id":f"sau-{seq}","sequence":seq,"occurredAt":"2026-09-28T00:00:00Z","methodVersion":"SECURITY_AUDIT_CHAIN_V1","category":category,"decision":decision,"actorId":"external-user","authentication":"oidc","method":"POST","path":"/mcp","statusCode":200 if decision=="ALLOW" else 403,"reasonCode":reason,"requestId":receipt["requestIds"][check],"previousDigest":prev,"digest":digest})
            prev=digest; seq+=1
        return rows
    def fixture(self,root):
        matrix_path=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; matrix=json.loads(matrix_path.read_text()); checks=matrix["spec"]["sharedRequiredChecks"]
        campaign=self.campaign(matrix_path); campaign_path=root/"campaign.json"; campaign_path.write_text(json.dumps(campaign))
        receipts=root/"receipts"; receipts.mkdir(); audits=root/"audits"; audits.mkdir()
        for c in mod.CLIENTS:
            row=self.receipt(c,checks,campaign); (receipts/(c+".json")).write_text(json.dumps(row)); (audits/(c+".json")).write_text(json.dumps(self.audit(row)))
        return matrix_path,campaign_path,receipts,audits,campaign,checks
    def test_four_named_clients_are_campaign_and_server_audit_bound(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,campaign,_=self.fixture(Path(td)); out=mod.seal(matrix,campaign_path,receipts,audits)
            self.assertEqual(4,out["certifiedClientCount"]); self.assertEqual(campaign["campaignId"],out["campaignId"]); self.assertTrue(out["serverAuditWitnessPass"]); self.assertEqual(24,out["serverAuditWitnessedCheckCount"]); self.assertFalse(out["physicalCertified"])
    def test_replay_endpoint_and_audit_semantics_reject(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,campaign,checks=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["challengeSha256"]="sha256:"+"0"*64; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_BINDING"): mod.seal(matrix,campaign_path,receipts,audits)
            row=self.receipt("chatgpt",checks,campaign); (receipts/"chatgpt.json").write_text(json.dumps(row))
            audit=json.loads((audits/"chatgpt.json").read_text()); audit[0]["reasonCode"]="WRONG"; (audits/"chatgpt.json").write_text(json.dumps(audit))
            with self.assertRaisesRegex(RuntimeError,"SEMANTIC_WITNESS"): mod.seal(matrix,campaign_path,receipts,audits)
    def test_cross_client_execution_or_evidence_reuse_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            chat=json.loads((receipts/"chatgpt.json").read_text()); claude=json.loads((receipts/"claude.json").read_text())
            claude["executionId"]=chat["executionId"]; (receipts/"claude.json").write_text(json.dumps(claude))
            with self.assertRaisesRegex(RuntimeError,"EXECUTION_REUSE"): mod.seal(matrix,campaign_path,receipts,audits)
            claude["executionId"]="run-claude"; claude["evidenceDigest"]=chat["evidenceDigest"]; (receipts/"claude.json").write_text(json.dumps(claude))
            with self.assertRaisesRegex(RuntimeError,"EVIDENCE_REUSE"): mod.seal(matrix,campaign_path,receipts,audits)
            claude["evidenceDigest"]="sha256:"+hashlib.sha256(b"claude-unique").hexdigest(); claude["providerExecutionRef"]=chat["providerExecutionRef"]; (receipts/"claude.json").write_text(json.dumps(claude))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REUSE"): mod.seal(matrix,campaign_path,receipts,audits)

    def test_cross_client_request_id_reuse_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            chat=json.loads((receipts/"chatgpt.json").read_text()); claude=json.loads((receipts/"claude.json").read_text())
            first=next(iter(chat["requestIds"].values())); key=next(iter(claude["requestIds"]))
            claude["requestIds"][key]=first; (receipts/"claude.json").write_text(json.dumps(claude))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.seal(matrix,campaign_path,receipts,audits)

    def test_missing_negative_control_or_duplicate_request_id_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["revokedGrantAccepted"]=True; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"NEGATIVE_CONTROL"): mod.seal(matrix,campaign_path,receipts,audits)
            bad["revokedGrantAccepted"]=False; vals=list(bad["requestIds"].values()); bad["requestIds"][mod.AUDITED_CHECKS[1]]=vals[0]; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_IDS"): mod.seal(matrix,campaign_path,receipts,audits)

if __name__=="__main__": unittest.main()
