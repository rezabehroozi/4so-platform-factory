import hashlib,importlib.util,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
S=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py"); core=importlib.util.module_from_spec(S); S.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
B=importlib.util.spec_from_file_location("c7w_execution_bindings",ROOT/"scripts"/"c7w_execution_bindings.py"); bindings=importlib.util.module_from_spec(B); B.loader.exec_module(bindings); sys.modules["c7w_execution_bindings"]=bindings
I=importlib.util.spec_from_file_location("c7w_request_identity",ROOT/"scripts"/"c7w_request_identity.py"); request_identity=importlib.util.module_from_spec(I); I.loader.exec_module(request_identity); sys.modules["c7w_request_identity"]=request_identity
P=importlib.util.spec_from_file_location("packet",ROOT/"scripts"/"prepare_mcp_external_client_execution.py"); mod=importlib.util.module_from_spec(P); P.loader.exec_module(mod)
class PacketTests(unittest.TestCase):
    def test_packet_covers_all_checks_without_secrets_or_false_runtime_claims(self):
        matrix=ROOT/"lab/mcp-external-client-interop-matrix.json"; rows=[]
        for c in core.CLIENTS:
            challenge=("packet-"+c+"-")*4; rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),"oauthClientId":c+"-oauth-client","trustedClientId":"mcpcli-"+c,"trustedClientRevision":1,"trustedClientProvider":c})
        ep="https://mcp.example.test/mcp"; metadata="https://mcp.example.test/.well-known/oauth-protected-resource"; spec=json.loads(matrix.read_text())["spec"]
        preflight={"authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":ep,"protectedResourceMetadata":metadata,"resource":ep,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        created=core.datetime.now(core.timezone.utc)-core.timedelta(minutes=1); expires=created+core.timedelta(seconds=spec["campaignMaxAgeSeconds"])
        resources={"foreignProjectId":"project-foreign-001","sameProjectOperationId":"operation-cancellable-001","selfApprovalRequestId":"approval-request-001"}
        document={"authority":bindings.AUTHORITY,"sourceCommitSHA":"1"*40,"resources":resources,"credentialProfileContractAuthority":bindings.credential_contract()["authority"],"credentialProfileContractSha256":bindings.credential_contract_digest()}
        raw=(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
        campaign={"authority":core.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-packettest","createdAt":core.utc_timestamp(created),"expiresAt":core.utc_timestamp(expires),"matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix),"oauthClientBindingAuthority":core.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"packet-oauth-bindings").hexdigest(),"executionBindingAuthority":bindings.AUTHORITY,"executionBindingsSha256":"sha256:"+hashlib.sha256(raw).hexdigest(),"executionBindings":resources,"credentialProfileContractAuthority":document["credentialProfileContractAuthority"],"credentialProfileContractSha256":document["credentialProfileContractSha256"],"sourceCommitSHA":"1"*40,"runtimeVersion":"0.0.test","protocol":"2026-07-28","transport":"streamable-http","endpoint":ep,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
        with tempfile.TemporaryDirectory() as td:
            cp=Path(td)/"campaign.json"; cp.write_text(json.dumps(campaign)); out=mod.packet(matrix,cp,"chatgpt")
        self.assertEqual(core.CLIENTS[0],out["clientId"]); self.assertEqual(core.CLIENT_SURFACES["chatgpt"],out["clientSurface"]); self.assertEqual(set(spec["sharedRequiredChecks"]),{x["id"] for x in out["checks"]})
        self.assertFalse(out["secretsIncluded"]); self.assertFalse(out["runtimeCertified"]); self.assertFalse(out["physicalCertified"])
        self.assertEqual("chatgpt-oauth-client",out["oauthClientId"]); self.assertEqual("chatgpt-oauth-client",out["receiptRequirements"]["oauthClientId"])
        self.assertEqual(bindings.AUTHORITY,out["executionBindingAuthority"]); self.assertEqual(resources,out["executionBindings"]); self.assertEqual(bindings.credential_contract(),out["credentialProfileContract"])
        self.assertEqual(request_identity.AUTHORITY,out["requestIdentityAuthority"]); self.assertEqual(request_identity.AUTHORITY,out["receiptRequirements"]["requestIdentityAuthority"])
        self.assertEqual(campaign["sourceCommitSHA"],out["sourceCommitSHA"]); self.assertEqual(campaign["runtimeVersion"],out["runtimeVersion"]); self.assertEqual(campaign["sourceCommitSHA"],out["requestMeta"]["io.4so/sourceCommitSHA"])
        runtime_check=next(x for x in out["checks"] if x["id"]=="authorization-filtered-tools-list"); self.assertEqual(campaign["sourceCommitSHA"],runtime_check["expect"]["sourceCommitSHA"]); self.assertIn("serverInfo.sourceCommitSHA",runtime_check["captureRuntimeIdentityFrom"]["sourceCommitSHA"])
        audited=[x for x in out["checks"] if x.get("serverAudit")]; self.assertEqual(set(core.AUDITED_CHECKS),{x["id"] for x in audited}); self.assertTrue(all("X-Request-ID" in x["request"]["captureRequestIdFrom"][0] for x in audited)); self.assertTrue(all(x["request"]["headers"]["MCP-Protocol-Version"]=="2026-07-28" for x in audited)); self.assertTrue(all(x["request"]["headers"]["Mcp-Interop-Binding"]==out["interopBindingDigest"] for x in audited))
        by_id={x["id"]:x for x in out["checks"]}; self.assertEqual("project-foreign-001",by_id["project-resource-scope-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["projectId"]); self.assertEqual("operation-cancellable-001",by_id["read-only-client-mutation-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["id"]); self.assertEqual("approval-request-001",by_id["administration-approval-self-approval-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["id"])
        rpc_rows=[row for row in out["checks"] if "jsonRpc" in row.get("request",{})]
        rpc_ids=[row["request"]["jsonRpc"]["id"] for row in rpc_rows]
        self.assertEqual(len(rpc_ids),len(set(rpc_ids)))
        self.assertTrue(all(isinstance(value,str) and value.startswith("c7w-") and len(value)==36 for value in rpc_ids))
        self.assertNotIn("<unique-jsonrpc-id>",json.dumps(out))
        challenge_sha=next(x for x in campaign["clients"] if x["clientId"]=="chatgpt")["challengeSha256"]
        for row in rpc_rows:
            self.assertEqual(request_identity.jsonrpc_id(campaign["campaignId"],"chatgpt",challenge_sha,row["id"]),row["request"]["jsonRpc"]["id"])
        self.assertEqual({row["id"]:row["request"]["jsonRpc"]["id"] for row in rpc_rows},request_identity.validate_packet_ids(out))
        text=json.dumps(out); self.assertNotIn("<foreign-project-id>",text); self.assertNotIn("<same-project-operation-id>",text); self.assertNotIn("<request-created-by-same-subject>",text)
if __name__=="__main__": unittest.main()
