import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
S=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(S); S.loader.exec_module(core); sys.modules["seal_mcp_external_interop"]=core
B=importlib.util.spec_from_file_location("c7w_execution_bindings",ROOT/"scripts"/"c7w_execution_bindings.py")
bindings=importlib.util.module_from_spec(B); B.loader.exec_module(bindings); sys.modules["c7w_execution_bindings"]=bindings
P=importlib.util.spec_from_file_location("prepare_mcp_external_client_execution",ROOT/"scripts"/"prepare_mcp_external_client_execution.py")
packet_mod=importlib.util.module_from_spec(P); P.loader.exec_module(packet_mod)


class C7WExecutablePacketMaterializationTests(unittest.TestCase):
    def campaign(self,matrix:Path)->dict:
        rows=[]
        for client in core.CLIENTS:
            challenge=("materialize-"+client+"-")*4
            rows.append({
                "clientId":client,
                "challenge":challenge,
                "challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),
                "oauthClientId":client+"-oauth-client",
                "trustedClientId":"mcpcli-"+client,
                "trustedClientRevision":1,
                "trustedClientProvider":client,
            })
        ep="https://mcp.example.test/mcp"
        metadata="https://mcp.example.test/.well-known/oauth-protected-resource"
        spec=json.loads(matrix.read_text())["spec"]
        created=core.datetime.now(core.timezone.utc)-core.timedelta(minutes=1)
        expires=created+core.timedelta(seconds=spec["campaignMaxAgeSeconds"])
        resources={
            "foreignProjectId":"project-foreign-001",
            "sameProjectOperationId":"operation-cancellable-001",
            "selfApprovalRequestId":"approval-request-001",
        }
        binding_document={
            "authority":bindings.AUTHORITY,
            "sourceCommitSHA":"1"*40,
            "resources":resources,
            "credentialProfileContractAuthority":bindings.credential_contract()["authority"],
            "credentialProfileContractSha256":bindings.credential_contract_digest(),
        }
        raw=(json.dumps(binding_document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
        return {
            "authority":core.CAMPAIGN_AUTHORITY,
            "campaignId":"mcp-interop-materialized-packet",
            "createdAt":core.utc_timestamp(created),
            "expiresAt":core.utc_timestamp(expires),
            "matrixAuthority":core.MATRIX_AUTHORITY,
            "matrixSha256":core.sha256(matrix),
            "oauthClientBindingAuthority":core.OAUTH_BINDING_AUTHORITY,
            "oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"oauth").hexdigest(),
            "executionBindingAuthority":bindings.AUTHORITY,
            "executionBindingsSha256":"sha256:"+hashlib.sha256(raw).hexdigest(),
            "executionBindings":resources,
            "credentialProfileContractAuthority":bindings.credential_contract()["authority"],
            "credentialProfileContractSha256":bindings.credential_contract_digest(),
            "sourceCommitSHA":"1"*40,
            "runtimeVersion":"0.0.test",
            "protocol":"2026-07-28",
            "transport":"streamable-http",
            "endpoint":ep,
            "livePreflight":{
                "authority":core.CAMPAIGN_PREFLIGHT_AUTHORITY,
                "endpoint":ep,
                "protectedResourceMetadata":metadata,
                "resource":ep,
                "authorizationServers":["https://identity.example.test/realms/4so"],
                "scopes":["mcp.read","mcp.operate"],
                "unauthenticatedStatus":401,
                "challenge":f'Bearer resource_metadata="{metadata}"',
                "protocol":"2026-07-28",
            },
            "clients":rows,
            "externalExecutionRequired":True,
        }

    def test_packet_has_no_resource_placeholders_and_binds_credential_contract(self):
        matrix=ROOT/"lab/mcp-external-client-interop-matrix.json"
        campaign=self.campaign(matrix)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(bindings,"source_commit_sha",return_value=campaign["sourceCommitSHA"]):
            cp=Path(td)/"campaign.json"; cp.write_text(json.dumps(campaign))
            packet=packet_mod.packet(matrix,cp,"chatgpt")
        text=json.dumps(packet,sort_keys=True)
        for placeholder in ("<foreign-project-id>","<same-project-operation-id>","<request-created-by-same-subject>"):
            self.assertNotIn(placeholder,text)
        self.assertEqual(bindings.AUTHORITY,packet["executionBindingAuthority"])
        self.assertEqual(campaign["executionBindingsSha256"],packet["executionBindingsSha256"])
        self.assertEqual(campaign["executionBindings"],packet["executionBindings"])
        self.assertEqual(bindings.credential_contract()["authority"],packet["credentialProfileContractAuthority"])
        self.assertEqual(bindings.credential_contract_digest(),packet["credentialProfileContractSha256"])
        self.assertEqual(bindings.credential_contract(),packet["credentialProfileContract"])
        profiles={row["request"]["credentialProfile"] for row in packet["checks"]}
        self.assertEqual(set(bindings.credential_contract()["profiles"]),profiles)
        by_id={row["id"]:row for row in packet["checks"]}
        self.assertEqual("project-foreign-001",by_id["project-resource-scope-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["projectId"])
        self.assertEqual("operation-cancellable-001",by_id["read-only-client-mutation-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["id"])
        self.assertEqual("approval-request-001",by_id["administration-approval-self-approval-negative-control"]["request"]["jsonRpc"]["params"]["arguments"]["id"])
        self.assertFalse(packet["secretsIncluded"])


if __name__=="__main__": unittest.main()
