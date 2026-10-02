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
            rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),
                         "oauthClientId":c+"-oauth-client","trustedClientId":"mcpcli-"+c,
                         "trustedClientRevision":1,"trustedClientProvider":c})
        metadata=endpoint.rsplit("/mcp",1)[0]+"/.well-known/oauth-protected-resource"
        preflight={"authority":mod.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":endpoint,"protectedResourceMetadata":metadata,"resource":endpoint,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        spec=json.loads(matrix_path.read_text())["spec"]
        created=mod.datetime.now(mod.timezone.utc)-mod.timedelta(minutes=1)
        expires=created+mod.timedelta(seconds=spec["campaignMaxAgeSeconds"])
        return {"authority":mod.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","createdAt":mod.utc_timestamp(created),"expiresAt":mod.utc_timestamp(expires),"matrixAuthority":mod.MATRIX_AUTHORITY,"matrixSha256":mod.sha256(matrix_path),
                "oauthClientBindingAuthority":mod.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"seal-oauth-bindings").hexdigest(),
                "protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
    def request_ids(self,client):
        return {name:f"{client}-{idx:02d}-request" for idx,name in enumerate(mod.AUDITED_CHECKS,1)}
    def receipt(self,client,checks,campaign,endpoint="https://mcp.example.test/mcp"):
        challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
        binding=mod.interop_binding_digest(campaign["campaignId"],client,challenge["challengeSha256"])
        executed=mod.parse_utc_timestamp(campaign["createdAt"],"TEST_CREATED")+mod.timedelta(seconds=30)
        return {"authority":mod.RECEIPT_AUTHORITY,"clientId":client,"clientSurface":mod.CLIENT_SURFACES[client],"campaignId":campaign["campaignId"],"challengeSha256":challenge["challengeSha256"],"oauthClientId":challenge["oauthClientId"],"interopBindingAuthority":mod.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"executionId":"run-"+client,"providerExecutionRef":"provider-execution-"+client,"executedAt":mod.utc_timestamp(executed),"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"requestIds":self.request_ids(client),"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def audit_digest(self,row):
        canonical={}
        required=("id","sequence","occurredAt","methodVersion","category","decision","actorId")
        ordered=required+("authentication","method","path","statusCode","reasonCode","requestId","scopeType","scopeId","effectiveRole","mappingDigest","oauthClientId","mcpInteropBindingDigest","previousDigest")
        for key in ordered:
            value=row.get(key)
            if key in required or value not in ("",0,None):
                canonical[key]=value
        canonical["digest"]=""
        raw=json.dumps(canonical,separators=(",",":"),ensure_ascii=False).encode()
        return "sha256:"+hashlib.sha256(raw).hexdigest()
    def audit(self,receipt):
        rows=[]; prev=""; seq=1
        for check in mod.AUDITED_CHECKS:
            category,decision,reason=mod.AUDIT_REQUIREMENTS[check]
            row={"id":f"sau-{seq}","sequence":seq,"occurredAt":receipt["executedAt"],"methodVersion":"IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1","category":category,"decision":decision,"actorId":"external-user","authentication":"oidc","method":"POST","path":"/mcp","statusCode":200 if decision=="ALLOW" else 403,"reasonCode":reason,"requestId":receipt["requestIds"][check],"mcpInteropBindingDigest":receipt["interopBindingDigest"],"previousDigest":prev}
            if check in mod.OAUTH_CLIENT_AUDITED_CHECKS:
                row["oauthClientId"]=receipt["oauthClientId"]
            row["digest"]=self.audit_digest(row)
            rows.append(row); prev=row["digest"]; seq+=1
        return rows
    def fixture(self,root):
        matrix_path=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; matrix=json.loads(matrix_path.read_text()); checks=matrix["spec"]["sharedRequiredChecks"]
        campaign=self.campaign(matrix_path); campaign_path=root/"campaign.json"; campaign_path.write_text(json.dumps(campaign))
        receipts=root/"receipts"; receipts.mkdir(); audits=root/"audits"; audits.mkdir()
        for c in mod.CLIENTS:
            row=self.receipt(c,checks,campaign); (receipts/(c+".json")).write_text(json.dumps(row)); (audits/(c+".json")).write_text(json.dumps(self.audit(row)))
        return matrix_path,campaign_path,receipts,audits,campaign,checks
    def test_json_persistence_is_atomic_and_immutable_by_authority_type(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            sealed=root/"sealed.json"
            mod.write_json_once_or_identical(sealed,{"value":1},"TEST_SEALED")
            first=sealed.read_bytes()
            mod.write_json_once_or_identical(sealed,{"value":1},"TEST_SEALED")
            self.assertEqual(first,sealed.read_bytes())
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_REPLACEMENT_FORBIDDEN"):
                mod.write_json_once_or_identical(sealed,{"value":2},"TEST_SEALED")
            progress=root/"progress.json"
            mod.write_json_atomic_replace(progress,{"value":1},"TEST_PROGRESS")
            mod.write_json_atomic_replace(progress,{"value":2},"TEST_PROGRESS")
            self.assertEqual({"value":2},json.loads(progress.read_text()))

    def test_go_security_audit_digest_vector_parity(self):
        row={
            "id":"sau-parity","sequence":7,"occurredAt":"2026-09-29T01:02:03Z",
            "methodVersion":mod.AUDIT_METHOD_VERSION,
            "category":"CAPABILITY_AUTHORIZATION","decision":"DENY",
            "actorId":"actor&<>\u2028\u2029","authentication":"oidc","method":"POST","path":"/mcp",
            "statusCode":403,"reasonCode":"CAPABILITY_PERMISSION_REQUIRED","requestId":"request-12345",
            "effectiveRole":"operator","mappingDigest":"sha256:"+"a"*64,
            "oauthClientId":"chatgpt-c7w-client",
            "mcpInteropBindingDigest":"sha256:"+"b"*64,"previousDigest":"sha256:"+"c"*64,
        }
        self.assertEqual("sha256:3a1000439b4083afeccfae99c17e4e44843949c94e3d27158d9d2ad932d16b56",mod.audit_event_digest(row))

    def test_four_named_clients_are_campaign_and_server_audit_bound(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,campaign,_=self.fixture(Path(td)); out=mod.seal(matrix,campaign_path,receipts,audits)
            self.assertEqual(4,out["certifiedClientCount"]); self.assertEqual(campaign["campaignId"],out["campaignId"]); self.assertTrue(out["serverAuditWitnessPass"]); self.assertEqual(24,out["serverAuditWitnessedCheckCount"]); self.assertFalse(out["physicalCertified"])
            self.assertTrue(all(row["serverAuditWitness"]["auditChainDigestVerified"] for row in out["clients"]))
            self.assertTrue(all(row["serverAuditWitness"]["auditMethodVersion"]==mod.AUDIT_METHOD_VERSION for row in out["clients"]))
    def test_secondary_witness_validator_rechecks_event_semantics_and_request_binding(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            out=mod.seal(matrix,campaign_path,receipts,audits)
            row=out["clients"][0]
            witness=row["serverAuditWitness"]
            mod.validate_server_audit_witness(
                witness,row["interopBindingDigest"],row["clientId"],"SECONDARY_WITNESS",
                row["oauthClientId"],row["requestIds"],
            )

            tampered=json.loads(json.dumps(witness))
            tampered["matchedEvents"]["authorization-filtered-tools-list"]["category"]="WRONG"
            with self.assertRaisesRegex(RuntimeError,"MATCHED_EVENT_SEMANTICS_INVALID"):
                mod.validate_server_audit_witness(
                    tampered,row["interopBindingDigest"],row["clientId"],"SECONDARY_WITNESS",
                    row["oauthClientId"],row["requestIds"],
                )

            tampered=json.loads(json.dumps(witness))
            tampered["matchedEvents"]["project-resource-scope-negative-control"]["requestId"]="different-request-id"
            with self.assertRaisesRegex(RuntimeError,"MATCHED_EVENT_REQUEST_ID_MISMATCH"):
                mod.validate_server_audit_witness(
                    tampered,row["interopBindingDigest"],row["clientId"],"SECONDARY_WITNESS",
                    row["oauthClientId"],row["requestIds"],
                )

    def test_receipt_or_server_audit_binding_tamper_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,campaign,checks=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["interopBindingDigest"]="sha256:"+"0"*64; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"INTEROP_BINDING_INVALID"): mod.seal(matrix,campaign_path,receipts,audits)
            good=self.receipt("chatgpt",checks,campaign); (receipts/"chatgpt.json").write_text(json.dumps(good))
            audit=json.loads((audits/"chatgpt.json").read_text()); audit[-1]["mcpInteropBindingDigest"]="sha256:"+"1"*64; audit[-1]["digest"]=self.audit_digest(audit[-1]); (audits/"chatgpt.json").write_text(json.dumps(audit))
            with self.assertRaisesRegex(RuntimeError,"AUDIT_INTEROP_BINDING_MISSING"): mod.seal(matrix,campaign_path,receipts,audits)

    def test_bounded_non_genesis_audit_window_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            audit_path=audits/"chatgpt.json"; audit=json.loads(audit_path.read_text())
            prev="sha256:"+hashlib.sha256(b"prior-audit-head").hexdigest()
            for seq,row in enumerate(audit,101):
                row["sequence"]=seq; row["previousDigest"]=prev; row["digest"]=self.audit_digest(row); prev=row["digest"]
            audit_path.write_text(json.dumps(audit))
            out=mod.seal(matrix,campaign_path,receipts,audits)
            witness=out["clients"][0]["serverAuditWitness"]
            self.assertEqual(101,witness["auditWindowStartSequence"])
            self.assertEqual("sha256:"+hashlib.sha256(b"prior-audit-head").hexdigest(),witness["auditWindowPreviousDigest"])
            self.assertEqual(106,witness["auditHeadSequence"])

    def test_replay_endpoint_and_audit_semantics_reject(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,campaign,checks=self.fixture(Path(td))
            bad=json.loads((receipts/"chatgpt.json").read_text()); bad["challengeSha256"]="sha256:"+"0"*64; (receipts/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_BINDING"): mod.seal(matrix,campaign_path,receipts,audits)
            row=self.receipt("chatgpt",checks,campaign); (receipts/"chatgpt.json").write_text(json.dumps(row))
            audit=json.loads((audits/"chatgpt.json").read_text()); audit[-1]["reasonCode"]="WRONG"; audit[-1]["digest"]=self.audit_digest(audit[-1]); (audits/"chatgpt.json").write_text(json.dumps(audit))
            with self.assertRaisesRegex(RuntimeError,"SEMANTIC_WITNESS"): mod.seal(matrix,campaign_path,receipts,audits)
    def test_forged_audit_event_payload_rejects_before_semantic_witness(self):
        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            audit_path=audits/"chatgpt.json"
            audit=json.loads(audit_path.read_text()); audit[0]["actorId"]="forged-external-user"; audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(RuntimeError,"AUDIT_DIGEST_INVALID"): mod.seal(matrix,campaign_path,receipts,audits)

    def test_expired_campaign_and_stale_audit_window_reject(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
            matrix_spec=json.loads(matrix.read_text())["spec"]
            campaign=self.campaign(matrix)
            expired=mod.datetime.now(mod.timezone.utc)-mod.timedelta(seconds=1)
            campaign["expiresAt"]=mod.utc_timestamp(expired)
            campaign["createdAt"]=mod.utc_timestamp(expired-mod.timedelta(seconds=matrix_spec["campaignMaxAgeSeconds"]))
            cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_EXPIRED"):
                mod.verify_campaign(cp,matrix,matrix_spec)

        with tempfile.TemporaryDirectory() as td:
            root=Path(td); matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; checks=json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]
            campaign=self.campaign(matrix); cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            receipts=root/"receipts"; receipts.mkdir(); audits=root/"audits"; audits.mkdir()
            for client in mod.CLIENTS:
                receipt=self.receipt(client,checks,campaign); (receipts/(client+".json")).write_text(json.dumps(receipt))
                events=self.audit(receipt)
                if client=="chatgpt":
                    stale=mod.parse_utc_timestamp(receipt["executedAt"],"TEST_EXECUTED")-mod.timedelta(seconds=json.loads(matrix.read_text())["spec"]["executionAuditWindowSeconds"]+1)
                    events[0]["occurredAt"]=mod.utc_timestamp(stale)
                    previous=""
                    for event in events:
                        event["previousDigest"]=previous; event["digest"]=self.audit_digest(event); previous=event["digest"]
                (audits/(client+".json")).write_text(json.dumps(events))
            with self.assertRaisesRegex(RuntimeError,"AUDIT_TIME_WINDOW_INVALID"):
                mod.seal(matrix,cp,receipts,audits)

    def test_campaign_live_preflight_is_mandatory_and_endpoint_bound(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"; spec=json.loads(matrix.read_text())["spec"]
            campaign=self.campaign(matrix)
            campaign.pop("livePreflight")
            cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"PREFLIGHT_INVALID"): mod.verify_campaign(cp,matrix,spec)
            campaign=self.campaign(matrix); campaign["livePreflight"]["resource"]="https://other.example.test/mcp"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"PREFLIGHT_INVALID"): mod.verify_campaign(cp,matrix,spec)
            campaign=self.campaign(matrix); campaign["livePreflight"]["challenge"]="Bearer wrong"; cp.write_text(json.dumps(campaign))
            with self.assertRaisesRegex(RuntimeError,"PREFLIGHT_INVALID"): mod.verify_campaign(cp,matrix,spec)

    def test_campaign_challenge_reuse_and_audit_request_ambiguity_reject(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
            campaign=self.campaign(matrix)
            campaign["clients"][1]["challenge"]=campaign["clients"][0]["challenge"]
            campaign["clients"][1]["challengeSha256"]=campaign["clients"][0]["challengeSha256"]
            cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            spec=json.loads(matrix.read_text())["spec"]
            with self.assertRaisesRegex(RuntimeError,"CHALLENGE_REUSE"): mod.verify_campaign(cp,matrix,spec)

        with tempfile.TemporaryDirectory() as td:
            root=Path(td); matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
            campaign=self.campaign(matrix)
            campaign["clients"][1]["trustedClientId"]=campaign["clients"][0]["trustedClientId"]
            cp=root/"campaign.json"; cp.write_text(json.dumps(campaign))
            spec=json.loads(matrix.read_text())["spec"]
            with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_ID_REUSE"):
                mod.verify_campaign(cp,matrix,spec)

        with tempfile.TemporaryDirectory() as td:
            matrix,campaign_path,receipts,audits,_,_=self.fixture(Path(td))
            audit_path=audits/"chatgpt.json"; audit=json.loads(audit_path.read_text())
            duplicate=dict(audit[-1]); duplicate["id"]="sau-duplicate"; duplicate["sequence"]=len(audit)+1; duplicate["previousDigest"]=audit[-1]["digest"]; duplicate["digest"]=self.audit_digest(duplicate)
            audit.append(duplicate); audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_AMBIGUOUS"): mod.seal(matrix,campaign_path,receipts,audits)

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
