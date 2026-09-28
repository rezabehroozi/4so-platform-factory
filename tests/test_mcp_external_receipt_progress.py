import hashlib,importlib.util,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SEAL_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
seal=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(seal); sys.modules["seal_mcp_external_interop"]=seal
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
        ids={name:f"{client}-{idx:02d}-request" for idx,name in enumerate(seal.AUDITED_CHECKS,1)}
        return {"authority":seal.RECEIPT_AUTHORITY,"clientId":client,"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"protocol":"2026-07-28","transport":"streamable-http","endpoint":campaign["endpoint"],"executionId":execution or "run-"+client,"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"requestIds":ids,"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def audit(self,row):
        out=[]; prev=""
        for seq,check in enumerate(seal.AUDITED_CHECKS,1):
            cat,decision,reason=seal.AUDIT_REQUIREMENTS[check]; digest="sha256:"+hashlib.sha256(f"{row['clientId']}:{seq}".encode()).hexdigest()
            out.append({"sequence":seq,"category":cat,"decision":decision,"method":"POST","path":"/mcp","reasonCode":reason,"requestId":row["requestIds"][check],"previousDigest":prev,"digest":digest}); prev=digest
        return out
    def test_receipts_merge_incrementally_and_fourth_seals(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            for idx,client in enumerate(seal.CLIENTS,1):
                row=self.receipt(client,checks,campaign); rp=root/(client+".json"); ap=root/(client+"-audit.json"); rp.write_text(json.dumps(row)); ap.write_text(json.dumps(self.audit(row)))
                out=mod.merge(matrix,cp,rp,ap,client,progress if progress.exists() else None); progress.write_text(json.dumps(out))
                self.assertEqual(idx,out["certifiedClientCount"]); self.assertEqual(idx==4,out["complete"])
            evidence=mod.final_evidence(out,progress); self.assertEqual(4,evidence["certifiedClientCount"]); self.assertTrue(evidence["serverAuditWitnessPass"]); self.assertEqual(24,evidence["serverAuditWitnessedCheckCount"]); self.assertFalse(evidence["physicalCertified"])
    def test_cross_client_request_id_reuse_rejects_incrementally(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            first=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"chatgpt-audit.json"; rp.write_text(json.dumps(first)); ap.write_text(json.dumps(self.audit(first)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None); progress.write_text(json.dumps(out))
            second=self.receipt("claude",checks,campaign); key=next(iter(second["requestIds"])); second["requestIds"][key]=next(iter(first["requestIds"].values()))
            rp2=root/"claude.json"; ap2=root/"claude-audit.json"; rp2.write_text(json.dumps(second)); ap2.write_text(json.dumps(self.audit(second)))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.merge(matrix,cp,rp2,ap2,"claude",progress)

    def test_explicit_supersede_replaces_only_incomplete_campaign(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); old_campaign=self.campaign(matrix); old_path=root/"old.json"; old_path.write_text(json.dumps(old_campaign)); progress=root/"progress.json"
            first=self.receipt("chatgpt",checks,old_campaign); rp=root/"first.json"; ap=root/"first-audit.json"; rp.write_text(json.dumps(first)); ap.write_text(json.dumps(self.audit(first)))
            partial=mod.merge(matrix,old_path,rp,ap,"chatgpt",None); progress.write_text(json.dumps(partial))
            new_campaign=self.campaign(matrix); new_campaign["campaignId"]="mcp-interop-fresh"; new_path=root/"new.json"; new_path.write_text(json.dumps(new_campaign))
            second=self.receipt("claude",checks,new_campaign); rp2=root/"second.json"; ap2=root/"second-audit.json"; rp2.write_text(json.dumps(second)); ap2.write_text(json.dumps(self.audit(second)))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_DRIFT"): mod.merge(matrix,new_path,rp2,ap2,"claude",progress)
            reset=mod.merge(matrix,new_path,rp2,ap2,"claude",progress,allow_campaign_supersede=True)
            self.assertEqual(1,reset["certifiedClientCount"]); self.assertEqual("mcp-interop-fresh",reset["campaignId"])

    def test_divergent_replacement_and_campaign_drift_reject(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            row=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"audit.json"; rp.write_text(json.dumps(row)); ap.write_text(json.dumps(self.audit(row)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None); progress.write_text(json.dumps(out))
            row=self.receipt("chatgpt",checks,campaign,"different-run"); rp.write_text(json.dumps(row))
            with self.assertRaisesRegex(RuntimeError,"REPLACEMENT_FORBIDDEN"): mod.merge(matrix,cp,rp,ap,"chatgpt",progress)
            campaign["campaignId"]="mcp-interop-other"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_DRIFT|CAMPAIGN_BINDING"): mod.merge(matrix,cp,rp,ap,"chatgpt",progress)

if __name__=="__main__": unittest.main()
