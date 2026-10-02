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
            rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),
                         "oauthClientId":c+"-oauth-client","trustedClientId":"mcpcli-"+c,
                         "trustedClientRevision":1,"trustedClientProvider":c})
        endpoint="https://mcp.example.test/mcp"; metadata="https://mcp.example.test/.well-known/oauth-protected-resource"
        preflight={"authority":seal.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":endpoint,"protectedResourceMetadata":metadata,"resource":endpoint,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        spec=json.loads(matrix.read_text())["spec"]
        created=seal.datetime.now(seal.timezone.utc)-seal.timedelta(minutes=1)
        expires=created+seal.timedelta(seconds=spec["campaignMaxAgeSeconds"])
        return {"authority":seal.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-incremental","createdAt":seal.utc_timestamp(created),"expiresAt":seal.utc_timestamp(expires),"matrixAuthority":seal.MATRIX_AUTHORITY,"matrixSha256":seal.sha256(matrix),
                "oauthClientBindingAuthority":seal.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"incremental-oauth-bindings").hexdigest(),
                "sourceCommitSHA":"1"*40,"runtimeVersion":"0.0.test",
                "protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
    def receipt(self,client,checks,campaign,execution=None):
        challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
        binding=seal.interop_binding_digest(campaign["campaignId"],client,challenge["challengeSha256"])
        ids={name:f"{client}-{idx:02d}-request" for idx,name in enumerate(seal.AUDITED_CHECKS,1)}
        executed=seal.parse_utc_timestamp(campaign["createdAt"],"TEST_CREATED")+seal.timedelta(seconds=30)
        return {"authority":seal.RECEIPT_AUTHORITY,"clientId":client,"clientSurface":seal.CLIENT_SURFACES[client],"sourceCommitSHA":campaign["sourceCommitSHA"],"runtimeVersion":campaign["runtimeVersion"],"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"oauthClientId":challenge["oauthClientId"],"interopBindingAuthority":seal.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"protocol":"2026-07-28","transport":"streamable-http","endpoint":campaign["endpoint"],"executionId":execution or "run-"+client,"providerExecutionRef":"provider-execution-"+client,"executedAt":seal.utc_timestamp(executed),"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"responseObservations":seal.expected_response_observations(campaign["sourceCommitSHA"],campaign["runtimeVersion"],campaign["endpoint"]),"requestIds":ids,"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def audit(self,row):
        out=[]; prev=""
        for seq,check in enumerate(seal.AUDITED_CHECKS,1):
            cat,decision,reason=seal.AUDIT_REQUIREMENTS[check]
            event={"id":f"sau-{row['clientId']}-{seq}","sequence":seq,"occurredAt":row["executedAt"],"methodVersion":seal.AUDIT_METHOD_VERSION,"category":cat,"decision":decision,"actorId":"external-user","authentication":"oidc","method":"POST","path":"/mcp","statusCode":200 if decision=="ALLOW" else 403,"reasonCode":reason,"requestId":row["requestIds"][check],"mcpInteropBindingDigest":row["interopBindingDigest"],"previousDigest":prev}
            if check in seal.OAUTH_CLIENT_AUDITED_CHECKS:
                event["oauthClientId"]=row["oauthClientId"]
            event["digest"]=seal.audit_event_digest(event)
            out.append(event); prev=event["digest"]
        return out
    def test_receipts_merge_incrementally_and_fourth_seals(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            receipts=root/"receipts"; receipts.mkdir(); audits=root/"audits"; audits.mkdir()
            for idx,client in enumerate(seal.CLIENTS,1):
                row=self.receipt(client,checks,campaign); rp=receipts/(client+".json"); ap=audits/(client+".json"); rp.write_text(json.dumps(row)); ap.write_text(json.dumps(self.audit(row)))
                out=mod.merge(matrix,cp,rp,ap,client,progress if progress.exists() else None); progress.write_text(json.dumps(out))
                self.assertEqual(idx,out["certifiedClientCount"]); self.assertEqual(idx==4,out["complete"])
            evidence=mod.final_evidence(out,progress); self.assertEqual(4,evidence["certifiedClientCount"]); self.assertTrue(evidence["serverAuditWitnessPass"]); self.assertEqual(24,evidence["serverAuditWitnessedCheckCount"]); self.assertFalse(evidence["physicalCertified"])
            self.assertEqual(campaign["sourceCommitSHA"],evidence["sourceCommitSHA"]); self.assertEqual(campaign["runtimeVersion"],evidence["runtimeVersion"])
            self.assertEqual(seal.seal(matrix,cp,receipts,audits),evidence)
    def test_existing_progress_rejects_interop_binding_or_witness_binding_drift(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            row=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"chatgpt-audit.json"; rp.write_text(json.dumps(row)); ap.write_text(json.dumps(self.audit(row)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None)
            bad=json.loads(json.dumps(out)); bad["clients"][0]["interopBindingDigest"]="sha256:"+"0"*64
            with self.assertRaisesRegex(RuntimeError,"INTEROP_BINDING_INVALID"): mod.validate_existing(bad,out)
            bad=json.loads(json.dumps(out)); bad["clients"][0]["serverAuditWitness"]["interopBindingDigest"]="sha256:"+"1"*64
            with self.assertRaisesRegex(RuntimeError,"INTEROP_BINDING_INVALID"): mod.validate_existing(bad,out)
            bad=json.loads(json.dumps(out)); bad["clients"][0]["trustedClientRevision"]=2
            with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_DRIFT"): mod.validate_existing(bad,out)
            bad=json.loads(json.dumps(out)); bad["clients"][0]["sourceCommitSHA"]="2"*40
            with self.assertRaisesRegex(RuntimeError,"RUNTIME_IDENTITY_DRIFT"): mod.validate_existing(bad,out)
            bad=json.loads(json.dumps(out)); bad["clients"][0]["responseObservations"]["project-resource-scope-negative-control"]["foreignProjectDataReturned"]=True
            with self.assertRaisesRegex(RuntimeError,"RESPONSE_OBSERVATION_MISMATCH"): mod.validate_existing(bad,out)

    def test_resumed_progress_rebinds_rows_to_current_campaign_window_and_endpoint(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            first=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"chatgpt-audit.json"; rp.write_text(json.dumps(first)); ap.write_text(json.dumps(self.audit(first)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None)

            second=self.receipt("claude",checks,campaign); rp2=root/"claude.json"; ap2=root/"claude-audit.json"; rp2.write_text(json.dumps(second)); ap2.write_text(json.dumps(self.audit(second)))

            bad=json.loads(json.dumps(out)); bad["clients"][0]["endpoint"]="https://other.example.test/mcp"; progress.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"ENDPOINT_DRIFT"):
                mod.merge(matrix,cp,rp2,ap2,"claude",progress)

            bad=json.loads(json.dumps(out)); bad["clients"][0]["campaignCreatedAt"]="2026-09-28T00:00:00Z"; progress.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_WINDOW_DRIFT"):
                mod.merge(matrix,cp,rp2,ap2,"claude",progress)

    def test_cross_client_execution_or_evidence_reuse_rejects_incrementally(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            first=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"chatgpt-audit.json"; rp.write_text(json.dumps(first)); ap.write_text(json.dumps(self.audit(first)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None); progress.write_text(json.dumps(out))
            second=self.receipt("claude",checks,campaign); second["executionId"]=first["executionId"]
            rp2=root/"claude.json"; ap2=root/"claude-audit.json"; rp2.write_text(json.dumps(second)); ap2.write_text(json.dumps(self.audit(second)))
            with self.assertRaisesRegex(RuntimeError,"EXECUTION_REUSE"): mod.merge(matrix,cp,rp2,ap2,"claude",progress)
            second["executionId"]="run-claude"; second["evidenceDigest"]=first["evidenceDigest"]; rp2.write_text(json.dumps(second))
            with self.assertRaisesRegex(RuntimeError,"EVIDENCE_REUSE"): mod.merge(matrix,cp,rp2,ap2,"claude",progress)
            second["evidenceDigest"]="sha256:"+hashlib.sha256(b"claude-unique").hexdigest(); second["providerExecutionRef"]=first["providerExecutionRef"]; rp2.write_text(json.dumps(second))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REUSE"): mod.merge(matrix,cp,rp2,ap2,"claude",progress)

    def test_cross_client_request_id_reuse_rejects_incrementally(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            first=self.receipt("chatgpt",checks,campaign); rp=root/"chatgpt.json"; ap=root/"chatgpt-audit.json"; rp.write_text(json.dumps(first)); ap.write_text(json.dumps(self.audit(first)))
            out=mod.merge(matrix,cp,rp,ap,"chatgpt",None); progress.write_text(json.dumps(out))
            second=self.receipt("claude",checks,campaign); key=next(iter(second["requestIds"])); second["requestIds"][key]=next(iter(first["requestIds"].values()))
            rp2=root/"claude.json"; ap2=root/"claude-audit.json"; rp2.write_text(json.dumps(second)); ap2.write_text(json.dumps(self.audit(second)))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.merge(matrix,cp,rp2,ap2,"claude",progress)

    def test_existing_progress_revalidates_witness_and_replay_authorities(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            rows=[]
            for client in ("chatgpt","claude"):
                receipt=self.receipt(client,checks,campaign); rp=root/(client+".json"); ap=root/(client+"-audit.json")
                rp.write_text(json.dumps(receipt)); ap.write_text(json.dumps(self.audit(receipt)))
                current=mod.merge(matrix,cp,rp,ap,client,progress if progress.exists() else None); progress.write_text(json.dumps(current)); rows.append(current)
            expected=rows[-1]
            bad=json.loads(json.dumps(expected)); bad["clients"][0]["serverAuditWitness"]["auditChainDigestVerified"]=False
            with self.assertRaisesRegex(RuntimeError,"SERVER_WITNESS"): mod.validate_existing(bad,expected)
            bad=json.loads(json.dumps(expected)); bad["clients"][1]["executionId"]=bad["clients"][0]["executionId"]
            with self.assertRaisesRegex(RuntimeError,"EXECUTION_ID"): mod.validate_existing(bad,expected)
            bad=json.loads(json.dumps(expected)); key=next(iter(bad["clients"][1]["requestIds"])); bad["clients"][1]["requestIds"][key]=next(iter(bad["clients"][0]["requestIds"].values()))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.validate_existing(bad,expected)

    def test_final_evidence_requires_exact_persisted_progress_bytes(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign)); progress=root/"progress.json"
            out=None
            for client in seal.CLIENTS:
                receipt=self.receipt(client,checks,campaign); rp=root/(client+".json"); ap=root/(client+"-audit.json")
                rp.write_text(json.dumps(receipt)); ap.write_text(json.dumps(self.audit(receipt)))
                out=mod.merge(matrix,cp,rp,ap,client,progress if progress.exists() else None); progress.write_text(json.dumps(out))
            persisted=json.loads(progress.read_text()); persisted["clients"][0]["executionId"]="tampered-after-memory"; progress.write_text(json.dumps(persisted))
            with self.assertRaisesRegex(RuntimeError,"FILE_BINDING"): mod.final_evidence(out,progress)

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
