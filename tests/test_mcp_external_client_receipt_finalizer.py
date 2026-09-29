import copy,hashlib,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py"); core=importlib.util.module_from_spec(S); S.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
P=importlib.util.spec_from_file_location("packet",ROOT/"scripts"/"prepare_mcp_external_client_execution.py"); packetmod=importlib.util.module_from_spec(P); P.loader.exec_module(packetmod)
F=importlib.util.spec_from_file_location("finalizer",ROOT/"scripts"/"finalize_mcp_external_client_receipt.py"); mod=importlib.util.module_from_spec(F); F.loader.exec_module(mod)

class ReceiptFinalizerTests(unittest.TestCase):
    def fixture(self,td:Path):
        matrix=ROOT/"lab/mcp-external-client-interop-matrix.json"
        rows=[]
        for c in core.CLIENTS:
            challenge=("capture-"+c+"-")*4
            rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest()})
        ep="https://mcp.example.test/mcp"; metadata="https://mcp.example.test/.well-known/oauth-protected-resource"
        preflight={"authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":ep,"protectedResourceMetadata":metadata,"resource":ep,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        campaign={"authority":core.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-capturetest","matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix),"protocol":"2026-07-28","transport":"streamable-http","endpoint":ep,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
        cp=td/"campaign.json"; cp.write_text(json.dumps(campaign))
        packet=packetmod.packet(matrix,cp,"chatgpt"); pp=td/"packet.json"; pp.write_text(json.dumps(packet))
        checks={}
        n=0
        for row in packet["checks"]:
            cid=row["id"]
            if cid in core.AUDITED_CHECKS:
                n+=1; checks[cid]={"passed":True,"requestId":f"req-chatgpt-{n:02d}"}
            else:
                checks[cid]={"passed":True}
        capture={"authority":mod.AUTHORITY,"clientId":"chatgpt","clientSurface":packet["clientSurface"],"campaignId":packet["campaignId"],"challengeSha256":packet["challengeSha256"],"endpoint":packet["endpoint"],"executionId":"provider-run-chatgpt-001","externalExecution":True,"credentialedExecution":True,"checks":checks,"providerExecutionRef":"opaque-provider-execution-001"}
        cap=td/"capture.json"; cap.write_text(json.dumps(capture))
        return pp,cap,capture
    def test_capture_finalizes_to_digest_bound_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,_=self.fixture(Path(raw)); out=mod.finalize(pp,cap)
            self.assertEqual(core.RECEIPT_AUTHORITY,out["authority"]); self.assertEqual("chatgpt",out["clientId"]); self.assertEqual(core.CLIENT_SURFACES["chatgpt"],out["clientSurface"])
            self.assertEqual(core.sha256(cap),out["evidenceDigest"]); self.assertEqual("opaque-provider-execution-001",out["providerExecutionRef"]); self.assertEqual(set(core.AUDITED_CHECKS),set(out["requestIds"]))
            self.assertTrue(all(out["checks"].values())); self.assertFalse(out["scopeLeakObserved"]); self.assertFalse(out["revokedGrantAccepted"]); self.assertFalse(out["selfApprovalAccepted"])
    def test_false_check_missing_request_id_and_binding_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw))
            bad=copy.deepcopy(capture); bad["checks"]["authorization-filtered-tools-list"]["passed"]=False; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CHECK_NOT_PASS"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["authorization-filtered-tools-list"]["requestId"]=""; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["campaignId"]="mcp-interop-other"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"BINDING_INVALID"): mod.finalize(pp,cap)
    def test_capture_rejects_extra_fields_missing_provider_ref_and_check_shape_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            pp,cap,capture=self.fixture(Path(raw))
            bad=copy.deepcopy(capture); bad["authorization"]="secret"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"FIELDS_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["providerExecutionRef"]=""; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REF_INVALID"): mod.finalize(pp,cap)
            bad=copy.deepcopy(capture); bad["checks"]["oauth-protected-resource-discovery"]["requestId"]="req-public-01"; cap.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CHECK_FIELDS_INVALID"): mod.finalize(pp,cap)

    def test_capture_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td=Path(raw); pp,cap,_=self.fixture(td); link=td/"capture-link.json"; link.symlink_to(cap.name)
            with self.assertRaisesRegex(RuntimeError,"FILE_INVALID"): mod.finalize(pp,link)
if __name__=="__main__": unittest.main()
