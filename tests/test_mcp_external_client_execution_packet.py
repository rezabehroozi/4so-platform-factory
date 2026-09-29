import hashlib,importlib.util,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py"); core=importlib.util.module_from_spec(S); S.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
P=importlib.util.spec_from_file_location("packet",ROOT/"scripts"/"prepare_mcp_external_client_execution.py"); mod=importlib.util.module_from_spec(P); P.loader.exec_module(mod)
class PacketTests(unittest.TestCase):
    def test_packet_covers_all_checks_without_secrets_or_false_runtime_claims(self):
        matrix=ROOT/"lab/mcp-external-client-interop-matrix.json"
        rows=[]
        for c in core.CLIENTS:
            challenge=("packet-"+c+"-")*4; rows.append({"clientId":c,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest()})
        ep="https://mcp.example.test/mcp"; metadata="https://mcp.example.test/.well-known/oauth-protected-resource"
        preflight={"authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":ep,"protectedResourceMetadata":metadata,"resource":ep,"authorizationServers":["https://identity.example.test/realms/4so"],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"}
        campaign={"authority":core.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-packettest","matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix),"protocol":"2026-07-28","transport":"streamable-http","endpoint":ep,"livePreflight":preflight,"clients":rows,"externalExecutionRequired":True}
        with tempfile.TemporaryDirectory() as td:
            cp=Path(td)/"campaign.json"; cp.write_text(json.dumps(campaign))
            out=mod.packet(matrix,cp,"chatgpt")
            self.assertEqual(core.CLIENTS[0],out["clientId"]); self.assertEqual(core.CLIENT_SURFACES["chatgpt"],out["clientSurface"]); self.assertEqual(set(json.loads(matrix.read_text())["spec"]["sharedRequiredChecks"]),{x["id"] for x in out["checks"]})
            self.assertFalse(out["secretsIncluded"]); self.assertFalse(out["runtimeCertified"]); self.assertFalse(out["physicalCertified"])
            self.assertEqual("MCP_EXTERNAL_CLIENT_CAPTURE_V1",out["receiptRequirements"]["captureAuthority"])
            self.assertIn("finalize_mcp_external_client_receipt.py",out["receiptRequirements"]["finalizer"])
            audited=[x for x in out["checks"] if x.get("serverAudit")]
            self.assertEqual(set(core.AUDITED_CHECKS),{x["id"] for x in audited})
            self.assertTrue(all("X-Request-ID" in x["request"]["captureRequestIdFrom"][0] for x in audited))
            audit_by_id={x["id"]:x["serverAudit"] for x in audited}
            self.assertEqual({"category":"DELEGATION_AUTHORIZATION","decision":"DENY","reasonCode":"MCP_DELEGATION_INACTIVE"},audit_by_id["revoked-delegation-negative-control"])
            self.assertEqual({"category":"CAPABILITY_AUTHORIZATION","decision":"DENY","reasonCode":"CAPABILITY_PERMISSION_REQUIRED"},audit_by_id["read-only-client-mutation-negative-control"])
            self.assertEqual({"category":"APPROVAL_AUTHORIZATION","decision":"DENY","reasonCode":"SEPARATION_OF_DUTIES_REQUIRED"},audit_by_id["administration-approval-self-approval-negative-control"])
if __name__=="__main__": unittest.main()
