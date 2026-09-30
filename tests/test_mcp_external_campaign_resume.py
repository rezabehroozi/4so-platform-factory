import contextlib, hashlib, importlib.util, io, json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SEAL_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
SPEC=importlib.util.spec_from_file_location("prepare_mcp_external_interop_campaign",ROOT/"scripts"/"prepare_mcp_external_interop_campaign.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class CampaignResumeTests(unittest.TestCase):
    def campaign(self,matrix:Path):
        endpoint="https://mcp.example.test/mcp"
        metadata="https://mcp.example.test/.well-known/oauth-protected-resource"
        rows=[]
        for client in core.CLIENTS:
            challenge=("resume-"+client+"-")*4
            rows.append({"clientId":client,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),
                         "oauthClientId":client+"-oauth-client","trustedClientId":"mcpcli-"+client,
                         "trustedClientRevision":1,"trustedClientProvider":client})
        return {
            "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropCampaign",
            "authority":core.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-resume-test",
            "createdAt":"2026-09-30T00:00:00+00:00",
            "matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix),
            "oauthClientBindingAuthority":core.OAUTH_BINDING_AUTHORITY,
            "oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"resume-oauth-bindings").hexdigest(),
            "endpoint":endpoint,"protocol":"2026-07-28","transport":"streamable-http",
            "livePreflight":{"authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,"endpoint":endpoint,
                "protectedResourceMetadata":metadata,"resource":endpoint,
                "authorizationServers":["https://identity.example.test/realms/4so"],
                "scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,
                "challenge":f'Bearer resource_metadata="{metadata}"',"protocol":"2026-07-28"},
            "clients":rows,"externalExecutionRequired":True,
        }

    def test_live_preflight_http_opener_refuses_redirects(self):
        opener=mod.exact_https_opener(mod.ssl.create_default_context())
        self.assertTrue(any(isinstance(handler,mod.RejectRedirects) for handler in opener.handlers))
        req=mod.Request("https://mcp.example.test/mcp")
        handler=mod.RejectRedirects()
        self.assertIsNone(handler.redirect_request(req,None,302,"Found",{},"https://other.example.test/mcp"))

    def test_existing_campaign_resumes_without_network_or_challenge_regeneration(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"campaign.json"
            original=self.campaign(matrix)
            core.write_json_once_or_identical(out,original,"TEST_CAMPAIGN")
            argv=["prepare_mcp_external_interop_campaign.py","--matrix",str(matrix),"--endpoint",original["endpoint"],"--out",str(out)]
            with mock.patch.object(sys,"argv",argv), mock.patch.object(mod,"live_preflight",side_effect=AssertionError("network preflight must not run on resume")):
                buf=io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(0,mod.main())
            emitted=json.loads(buf.getvalue())
            self.assertTrue(emitted["resumed"])
            self.assertEqual(original,core.load(out,"CAMPAIGN"))

    def test_existing_campaign_endpoint_drift_fails_closed(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"campaign.json"
            original=self.campaign(matrix)
            core.write_json_once_or_identical(out,original,"TEST_CAMPAIGN")
            with self.assertRaisesRegex(RuntimeError,"RESUME_ENDPOINT_DRIFT"):
                mod.resume_existing(matrix,"https://other.example.test/mcp",out)

if __name__=="__main__":
    unittest.main()
