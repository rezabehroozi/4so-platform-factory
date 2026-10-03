import copy,hashlib,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
S=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py"); core=importlib.util.module_from_spec(S); S.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
B=importlib.util.spec_from_file_location("c7w_execution_bindings",ROOT/"scripts"/"c7w_execution_bindings.py"); bindings=importlib.util.module_from_spec(B); B.loader.exec_module(bindings); sys.modules["c7w_execution_bindings"]=bindings
P=importlib.util.spec_from_file_location("packet",ROOT/"scripts"/"prepare_mcp_external_client_execution.py"); packetmod=importlib.util.module_from_spec(P); P.loader.exec_module(packetmod)
F=importlib.util.spec_from_file_location("finalizer",ROOT/"scripts"/"finalize_mcp_external_client_receipt.py"); mod=importlib.util.module_from_spec(F); F.loader.exec_module(mod)

class ReceiptFinalizerTests(unittest.TestCase):
    def fixture(self,td:Path):
        matrix=ROOT/"lab/mcp-external-client-interop-matrix.json"; rows=[]
        for c in core.CLIENTS:
            challenge=("capture-"+c+"-")*4; rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),"oauthClientId":c+"-oauth-client","trustedClientId":"mcpcli-"+c,"trustedClientRevision":1,"trustedClientProvider":c})
        ep="https://mcp.example.test/mcp"; metadata="https://mcp.example.test/.well-known/oauth-protected-resource"; preflight={"authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":ep,"protectedResourceMetadata":metadata,"resource":ep,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        spec=json.loads(matrix.read_text())["spec"]; created=core.datetime.now(core.timezone.utc)-core.timedelta(minutes=1); expires=created+core.timedelta(seconds=spec["campaignMaxAgeSeconds"])
        resources={"foreignProjectId":"project-foreign-001","sameProjectOperationId":"operation-cancellable-001","selfApprovalRequestId":"approval-request-001"}
        document={"authority":bindings.AUTHORITY,"sourceCommitSHA":"1"*40,"resources":resources,"credentialProfileContractAuthority":bindings.credential_contract()["authority"],"credentialProfileContractSha256":bindings.credential_contract_digest()}; raw=(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
        campaign={"authority":core.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-capturetest","createdAt":core.utc_timestamp(created),"expiresAt":core.utc_timestamp(expires),"matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix),"oauthClientBindingAuthority":core.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"capture-oauth-bindings").hexdigest(),"executionBindingAuthority":bindings.AUTHORITY,"executionBindingsSha256":"sha256:"+hashlib.sha256(raw).hexdigest(),"executionBindings":resources,"credentialProfileContractAuthority":document["credentialProfileContractAuthority"],"credentialProfileContractSha256":document["credentialProfileContractSha256"],"sourceCommitSHA":"1"*40,"runtimeVersion":"0.0.test","protocol":"2026-07-28","transport":"streamable-http","endpoint":ep,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
        cp=td/"campaign.json"; cp.write_text(json.dumps(campaign)); packet=packetmod.packet(matrix,cp,"chatgpt"); pp=td/"packet.json"; pp.write_text(json.dumps(packet))
        checks={}; n=0
        for row in packet["checks"]:
            cid=row["id"]; observed={"scopes":list(value) if key=="scopesContain" else value for key,value in row["expect"].items() for _ in [0]}
            if "scopesContain" in row["expect"]:
                observed={}
                for key,value in row["expect"].items(): observed["scopes" if key=="scopesContain" else key]=list(value) if key=="scopesContain" else value
            if cid in core.AUDITED_CHECKS: n+=1; checks[cid]={"observed":observed,"requestId":f"req-chatgpt-{n:02d}"}
            else: checks[cid]={"observed":observed}
        executed=core.parse_utc_timestamp(packet["campaignCreatedAt"],"TEST_CREATED")+core.timedelta(minutes=1)
        capture={"authority":mod.AUTHORITY,"clientId":"chatgpt","clientSurface":packet["clientSurface"],"campaignId":packet["campaignId"],"challengeSha256":packet["challengeSha256"],"endpoint":packet["endpoint"],"sourceCommitSHA":packet["sourceCommitSHA"],"runtimeVersion":packet["runtimeVersion"],"executionId":"provider-run-chatgpt-001","executedAt":core.utc_timestamp(executed),"externalExecution":True,"credentialedExecution":True,"checks":checks,"providerExecutionRef":"opaque-provider-execution-001"}
        cap=td/"capture.json"; cap.write_text(json.dumps(capture)); return pp,cap,capture

    def test_capture_finalizes_to_digest_bound_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); out=mod.finalize(pp,cap)
            self.assertEqual(core.RECEIPT_AUTHORITY,out["authority"]); self.assertEqual("chatgpt",out["clientId"]); self.assertEqual(core.sha256(cap),out["evidenceDigest"]); self.assertEqual(set(core.AUDITED_CHECKS),set(out["requestIds"])); self.assertTrue(all(out["checks"].values())); self.assertEqual(set(core.REQUIRED_CHECKS),set(out["responseObservations"])); self.assertFalse(out["scopeLeakObserved"]); self.assertFalse(out["revokedGrantAccepted"]); self.assertFalse(out["selfApprovalAccepted"])

    def test_receipt_digest_comes_from_same_validated_capture_snapshot(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); wanted="sha256:"+hashlib.sha256(cap.read_bytes()).hexdigest(); original=core.sha256
            try: core.sha256=lambda path:"sha256:"+"f"*64; out=mod.finalize(pp,cap)
            finally: core.sha256=original
            self.assertEqual(wanted,out["evidenceDigest"])

    def test_materialized_binding_and_credential_contract_tamper_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); original=json.loads(pp.read_text())
            bad=copy.deepcopy(original); bad["executionBindings"]["foreignProjectId"]="project-other"; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"EXECUTION_BINDINGS_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(original); bad["credentialProfileContractSha256"]="sha256:"+"f"*64; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CREDENTIAL_CONTRACT_INVALID"): mod.finalize(pp,cap)

    def test_false_check_missing_request_id_and_binding_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw)); bad=copy.deepcopy(capture); bad["checks"]["authorization-filtered-tools-list"]["observed"]["httpStatus"]=500; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"OBSERVATION_MISMATCH"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["authorization-filtered-tools-list"]["requestId"]=""; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["campaignId"]="mcp-interop-other"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"BINDING_INVALID"): mod.finalize(pp,cap)

    def test_capture_rejects_extra_fields_missing_provider_ref_and_check_shape_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw)); bad=copy.deepcopy(capture); bad["authorization"]="secret"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"FIELDS_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["providerExecutionRef"]=""; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REF_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["oauth-protected-resource-discovery"]["requestId"]="req-public-01"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CHECK_FIELDS_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["oauth-protected-resource-discovery"]["observed"]["scopes"]=["mcp.read"]; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"OBSERVATION_MISMATCH"): mod.finalize(pp,cap)

    def test_packet_authority_protocol_endpoint_and_scope_drift_fail_before_capture(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); original=json.loads(pp.read_text())
            for mutate,error in ((lambda r:r.__setitem__("matrixAuthority","wrong"),"SOURCE_AUTHORITY_INVALID"),(lambda r:r.__setitem__("protocol","legacy-http"),"PROTOCOL_INVALID"),(lambda r:r.__setitem__("endpoint","http://mcp.example.test/mcp"),"ENDPOINT_INVALID"),(lambda r:r.__setitem__("runtimeCertified",True),"SCOPE_INFLATED")):
                bad=copy.deepcopy(original); mutate(bad); pp.write_text(json.dumps(bad))
                with self.assertRaisesRegex(RuntimeError,error): mod.finalize(pp,cap)

    def test_packet_wire_and_semantic_weakening_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); original=json.loads(pp.read_text())
            bad=copy.deepcopy(original); row=next(x for x in bad["checks"] if x["id"]=="authorization-filtered-tools-list"); row["request"]["headers"]["MCP-Protocol-Version"]="legacy"; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PACKET_WIRE_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(original); row=next(x for x in bad["checks"] if x["id"]=="project-resource-scope-negative-control"); row["expect"]["accepted"]=True; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PACKET_SEMANTICS_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(original); row=next(x for x in bad["checks"] if x["id"]=="read-only-client-mutation-negative-control"); row["request"]["credentialProfile"]="campaign-delegated-user"; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PACKET_SEMANTICS_INVALID|CREDENTIAL_PROFILE_SET_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(original); row=next(x for x in bad["checks"] if x["id"]=="administration-approval-self-approval-negative-control"); row["request"]["jsonRpc"]["params"]["arguments"]["expectedRevision"]=2; pp.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PACKET_WIRE_INVALID"): mod.finalize(pp,cap)

    def test_capture_runtime_identity_and_response_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw)); bad=copy.deepcopy(capture); bad["sourceCommitSHA"]="2"*40; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"BINDING_INVALID sourceCommitSHA"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["authorization-filtered-tools-list"]["observed"]["runtimeVersion"]="0.0.other"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"OBSERVATION_MISMATCH"): mod.finalize(pp,cap)

    def test_capture_execution_time_outside_campaign_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw)); packet=json.loads(pp.read_text()); expired=core.parse_utc_timestamp(packet["campaignExpiresAt"],"TEST_EXPIRES")+core.timedelta(seconds=1); capture["executedAt"]=core.utc_timestamp(expired); cap.write_text(json.dumps(capture))
            with self.assertRaisesRegex(RuntimeError,"EXECUTION_TIME_INVALID"): mod.finalize(pp,cap)

    def test_capture_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td=Path(raw); pp,cap,_=self.fixture(td); link=td/"capture-link.json"
            try: link.symlink_to(cap.name)
            except OSError as exc: self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"FILE_INVALID"): mod.finalize(pp,link)

if __name__=="__main__": unittest.main()
