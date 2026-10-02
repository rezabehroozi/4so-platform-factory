import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("final_adm",ROOT/"scripts"/"final_exact_release_admission.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
from scripts import seal_final_exact_release as local_seal

class FinalExactReleaseAdmissionTests(unittest.TestCase):
    def progress_row(self,c):
        checks={name:True for name in ("oauth-protected-resource-discovery","dedicated-audience-validation","authorization-filtered-tools-list","project-resource-scope-negative-control","revoked-delegation-negative-control","read-only-client-mutation-negative-control","administration-approval-self-approval-negative-control")}
        request_ids={name:f"{c}-{idx:02d}-request" for idx,name in enumerate(mod.MCP_AUDITED_CHECKS,1)}
        challenge="sha256:"+hashlib.sha256((c+"-challenge").encode()).hexdigest()
        binding=mod.mcp_contract.interop_binding_digest("mcp-interop-testcampaign",c,challenge)
        oauth_client_id=c+"-oauth-client"
        trusted={"trustedClientId":"mcpcli-"+c,"trustedClientRevision":1,"trustedClientProvider":c}
        executed_at="2026-09-29T01:02:03Z"
        matched={}
        for sequence,check in enumerate(mod.MCP_AUDITED_CHECKS,1):
            category,decision,reason=mod.mcp_contract.AUDIT_REQUIREMENTS[check]
            matched[check]={
                "requestId":request_ids[check],
                "sequence":sequence,
                "digest":"sha256:"+hashlib.sha256(f"{c}-{check}-audit".encode()).hexdigest(),
                "occurredAt":executed_at,
                "category":category,
                "decision":decision,
                "reasonCode":reason,
                "oauthClientId":oauth_client_id if check in mod.mcp_contract.OAUTH_CLIENT_AUDITED_CHECKS else "",
                "interopBindingDigest":binding,
            }
        witness={"authority":"MCP_EXTERNAL_SERVER_AUDIT_WITNESS_V1","clientId":c,"oauthClientId":oauth_client_id,"interopBindingAuthority":mod.mcp_contract.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"auditMethodVersion":"IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1","auditChainDigestVerified":True,"oauthClientWitnessPass":True,"oauthClientWitnessedCheckCount":5,"auditWindowStartSequence":1,"auditWindowPreviousDigest":"","auditHeadSequence":6,"serverAuditWitnessPass":True,"witnessedCheckCount":6,"auditHeadDigest":"sha256:"+hashlib.sha256((c+"-audit-head").encode()).hexdigest(),"auditExportSha256":"sha256:"+hashlib.sha256((c+"-audit-export").encode()).hexdigest(),"executionObservedAt":executed_at,"executionAuditWindowSeconds":3600,"matchedEvents":matched}
        return {"clientId":c,"clientSurface":mod.CLIENT_SURFACES[c],"endpoint":"https://mcp.example.test/mcp","executionId":"run-"+c,"providerExecutionRef":"provider-execution-"+c,"executedAt":executed_at,"campaignId":"mcp-interop-testcampaign","challengeSha256":challenge,"oauthClientId":oauth_client_id,**trusted,"interopBindingAuthority":mod.mcp_contract.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"evidenceDigest":"sha256:"+hashlib.sha256((c+"-evidence").encode()).hexdigest(),"externalReceiptSha256":"sha256:"+hashlib.sha256((c+"-receipt").encode()).hexdigest(),"checks":checks,"requestIds":request_ids,"campaignCreatedAt":"2026-09-29T00:00:00Z","campaignExpiresAt":"2026-10-06T00:00:00Z","executionAuditWindowSeconds":3600,"serverAuditWitness":witness}

    def oauth_bindings(self):
        return {c:c+"-oauth-client" for c in mod.CLIENTS}

    def trusted_bindings(self):
        return {c:{"trustedClientId":"mcpcli-"+c,"trustedClientRevision":1,"trustedClientProvider":c} for c in mod.CLIENTS}

    def fixture(self,root:Path):
        (root/"lab").mkdir(exist_ok=True)
        pack="a"*64; archive="b"*64
        lock={"authority":mod.S1_AUTHORITY,"schemaVersion":8,"status":"ready","missingAuthorities":[],"partialAuthorities":[],"inputPack":{"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging","sha256":pack,"sizeBytes":123,"urls":[f"https://dist.example.test/sha256/{pack}/appliance.zip"]},"resolvedAuthorities":[{"id":"management-workload-oci-archive","artifacts":[{"sha256":archive,"sizeBytes":456,"urls":[f"https://dist.example.test/sha256/{archive}/archive.tar"]}]}]}
        (root/"lab/appliance-bundle-acquisition-lock.json").write_text(json.dumps(lock))
        clients=[self.progress_row(c) for c in mod.CLIENTS]
        oauth_bindings={row["clientId"]:row["oauthClientId"] for row in clients}
        trusted_bindings={row["clientId"]:{"trustedClientId":row["trustedClientId"],"trustedClientRevision":row["trustedClientRevision"],"trustedClientProvider":row["trustedClientProvider"]} for row in clients}
        mcp={"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence","authority":mod.MCP_AUTHORITY,"matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":"MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1","campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"oauth-bindings").hexdigest(),"oauthClientBindings":oauth_bindings,"trustedClientBindings":trusted_bindings,"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","clients":clients,"certifiedClientCount":4,"allRequiredChecksPass":True,"serverAuditWitnessPass":True,"serverAuditWitnessedCheckCount":24,"externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False}
        (root/"lab/mcp-external-client-interoperability-evidence.json").write_text(json.dumps(mcp))
        return lock,mcp
    def test_local_final_seal_evidence_is_exact_file_bound_and_never_physical(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); release_dir=root/"release"; release_dir.mkdir()
            version="0.0.test"; release_name="unit"
            release=release_dir/f"4so-platform-factory-{version}-{release_name}.zip"; release.write_bytes(b"exact-release")
            stage=release_dir/release.stem; stage.mkdir()
            for name,payload in (("ARTIFACT-MANIFEST.json",b"manifest"),("BUILD-PROVENANCE.json",b"provenance"),("SBOM.spdx.json",b"sbom")):
                (stage/name).write_bytes(payload)
            admitted={"authority":mod.AUTHORITY,"admitted":True,"applianceDistributionSha256":"sha256:"+"a"*64,"mcpExternalInteropSha256":"sha256:"+"b"*64,"physicalCertified":False}
            out=local_seal.build_evidence(root,release,stage,admitted,"c"*40,version,release_name)
            self.assertEqual(local_seal.AUTHORITY,out["authority"])
            self.assertEqual(local_seal.EXECUTION_AUTHORITY,out["sourceExecutionAuthority"])
            self.assertEqual(local_seal.SOURCE_WORKSPACE_AUTHORITY,out["sourceWorkspaceAuthority"])
            self.assertEqual(f"release/{release.name}",out["releaseArchivePath"])
            self.assertEqual("sha256:"+hashlib.sha256(b"exact-release").hexdigest(),out["releaseArchiveSha256"])
            self.assertTrue(out["fullVerifierPass"]); self.assertFalse(out["physicalCertified"])
            inflated=dict(admitted); inflated["physicalCertified"]=True
            with self.assertRaisesRegex(RuntimeError,"SCOPE_INFLATED"):
                local_seal.build_evidence(root,release,stage,inflated,"c"*40,version,release_name)

    def test_two_external_authorities_admit_final_release_without_physical_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); out=mod.verify(root)
            self.assertTrue(out["admitted"]); self.assertFalse(out["physicalCertified"])
            self.assertTrue(out["applianceDistributionSha256"].startswith("sha256:"))
    def test_multipart_distribution_is_admitted_with_same_full_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); lock,_=self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text())
            pack=d["inputPack"]; pd=pack.pop("urls")
            pack["parts"]=[{"index":0,"urls":[pd[0].replace("appliance.zip","part0")],"sha256":pack["sha256"],"sizeBytes":pack["sizeBytes"]}]
            ar=d["resolvedAuthorities"][0]["artifacts"][0]; au=ar.pop("urls")
            ar["parts"]=[{"index":0,"urls":[au[0].replace("archive.tar","part0")],"sha256":ar["sha256"],"sizeBytes":ar["sizeBytes"]}]
            p.write_text(json.dumps(d))
            out=mod.verify(root); self.assertTrue(out["admitted"])

    def test_multipart_distribution_rejects_part_sum_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text())
            pack=d["inputPack"]; url=pack.pop("urls")[0]
            pack["parts"]=[{"index":0,"urls":[url.replace("appliance.zip","part0")],"sha256":pack["sha256"],"sizeBytes":pack["sizeBytes"]-1}]
            p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"SIZE_SUM"): mod.verify(root)

    def test_missing_mcp_evidence_is_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            with self.assertRaisesRegex(mod.Pending,"MCP_EXTERNAL_INTEROP_PENDING"): mod.verify(root)
    def test_pending_status_is_structured_for_ci_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            try:
                mod.verify(root)
            except mod.Pending as exc:
                pending=str(exc)
                status={"authority":mod.AUTHORITY,"admitted":False,"pending":pending,"blockers":[{"code":pending,"detail":"required external closure evidence is not sealed on canonical main"}],"physicalCertified":False}
                self.assertEqual("MCP_EXTERNAL_INTEROP_PENDING",status["blockers"][0]["code"])
                self.assertFalse(status["admitted"])
            else:
                self.fail("pending evidence unexpectedly admitted")

    def test_external_progress_reports_missing_clients_without_inventing_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            p=root/"lab/mcp-external-client-interop-progress.json"
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[self.progress_row("chatgpt"),self.progress_row("gemini")],"certifiedClientCount":2,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            progress=mod.external_client_progress(root)
            self.assertEqual(["chatgpt","gemini"],progress["certifiedClients"])
            self.assertEqual(["claude","grok"],progress["missingClients"])
            self.assertEqual("claude",progress["nextClient"])
            self.assertFalse(progress["evidenceSealPending"])

    def test_external_progress_rejects_unwitnessed_or_reused_provider_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            rows=[self.progress_row("chatgpt"),self.progress_row("claude")]
            rows[1]["providerExecutionRef"]=rows[0]["providerExecutionRef"]
            p=root/"lab/mcp-external-client-interop-progress.json"
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":2,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REF"):
                mod.external_client_progress(root)
            rows=[self.progress_row("chatgpt")]; rows[0]["serverAuditWitness"]["serverAuditWitnessPass"]=False
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"SERVER_WITNESS"):
                mod.external_client_progress(root)

    def test_complete_progress_without_evidence_reports_seal_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            rows=[self.progress_row(c) for c in mod.CLIENTS]
            (root/"lab/mcp-external-client-interop-progress.json").write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":4,"complete":True,"externalCertificationPass":True,"serverAuditWitnessPass":True,"runtimeCertified":False,"physicalCertified":False}))
            progress=mod.external_client_progress(root)
            self.assertEqual([],progress["missingClients"])
            self.assertIsNone(progress["nextClient"])
            self.assertTrue(progress["evidenceSealPending"])

    def test_final_admission_revalidates_mcp_projection_identity_and_timing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"

            evidence=json.loads(evidence_path.read_text())
            evidence["protocol"]="future-protocol"
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"PROTOCOL_INVALID"):
                mod.verify(root)

            self.fixture(root)
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["endpoint"]="https://other.example.test/mcp"
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"ENDPOINT_DRIFT"):
                mod.verify(root)

            self.fixture(root)
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["serverAuditWitness"]["executionObservedAt"]="2026-09-29T01:02:04Z"
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"SERVER_WITNESS_TIME_DRIFT"):
                mod.verify(root)

            self.fixture(root)
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["campaignCreatedAt"]="2026-09-28T00:00:00Z"
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_WINDOW_DRIFT"):
                mod.verify(root)

    def test_progress_revalidates_projection_identity_and_timing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            row=self.progress_row("chatgpt")
            base={"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[row],"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}
            p=root/"lab/mcp-external-client-interop-progress.json"

            invalid=json.loads(json.dumps(base)); invalid["matrixSha256"]="not-a-digest"; p.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(RuntimeError,"MATRIX_BINDING_INVALID"):
                mod.external_client_progress(root)

            invalid=json.loads(json.dumps(base)); invalid["clients"][0]["executionAuditWindowSeconds"]=0; p.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(RuntimeError,"AUDIT_WINDOW_INVALID"):
                mod.external_client_progress(root)

    def test_unwitnessed_external_evidence_remains_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text()); evidence["serverAuditWitnessPass"]=False; evidence["serverAuditWitnessedCheckCount"]=0; p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(mod.Pending,"MCP_EXTERNAL_SERVER_AUDIT_WITNESS_PENDING"):
                mod.verify(root)

    def test_duplicate_provider_execution_reference_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text()); evidence["clients"][1]["providerExecutionRef"]=evidence["clients"][0]["providerExecutionRef"]; p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"PROVIDER_EXECUTION_REUSE"):
                mod.verify(root)

    def test_final_evidence_rejects_cross_client_replay_identifiers(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            for field,error in (("executionId","EXECUTION_REUSE"),("evidenceDigest","EVIDENCE_REUSE"),("externalReceiptSha256","EVIDENCE_REUSE"),("challengeSha256","EVIDENCE_REUSE")):
                evidence=json.loads(p.read_text())
                evidence["clients"][1][field]=evidence["clients"][0][field]
                p.write_text(json.dumps(evidence))
                with self.assertRaisesRegex(RuntimeError,error): mod.verify(root)
                self.fixture(root)

    def test_final_evidence_rejects_cross_client_request_id_reuse(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text())
            first_key=next(iter(evidence["clients"][0]["requestIds"]))
            second_key=next(iter(evidence["clients"][1]["requestIds"]))
            evidence["clients"][1]["requestIds"][second_key]=evidence["clients"][0]["requestIds"][first_key]
            p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.verify(root)

    def test_progress_rejects_cross_client_execution_evidence_and_request_reuse(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interop-progress.json"
            rows=[self.progress_row("chatgpt"),self.progress_row("claude")]
            for field,error in (("executionId","EXECUTION_ID"),("evidenceDigest","EVIDENCE_REUSE"),("externalReceiptSha256","EVIDENCE_REUSE")):
                mutated=json.loads(json.dumps(rows)); mutated[1][field]=mutated[0][field]
                p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":mutated,"certifiedClientCount":2,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
                with self.assertRaisesRegex(RuntimeError,error): mod.external_client_progress(root)
            mutated=json.loads(json.dumps(rows)); a=next(iter(mutated[0]["requestIds"])); b=next(iter(mutated[1]["requestIds"])); mutated[1]["requestIds"][b]=mutated[0]["requestIds"][a]
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":mutated,"certifiedClientCount":2,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_ID_REUSE"): mod.external_client_progress(root)

    def test_final_and_progress_reject_tampered_matched_audit_event_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(evidence_path.read_text())
            event=evidence["clients"][0]["serverAuditWitness"]["matchedEvents"]["authorization-filtered-tools-list"]
            event["category"]="WRONG"
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"MATCHED_EVENT_SEMANTICS_INVALID"):
                mod.verify(root)

            self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            row=self.progress_row("chatgpt")
            event=row["serverAuditWitness"]["matchedEvents"]["project-resource-scope-negative-control"]
            event["requestId"]="different-request-id"
            progress={"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[row],"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}
            (root/"lab/mcp-external-client-interop-progress.json").write_text(json.dumps(progress))
            with self.assertRaisesRegex(RuntimeError,"MATCHED_EVENT_REQUEST_ID_MISMATCH"):
                mod.external_client_progress(root)

    def test_progress_and_final_evidence_require_exact_check_names(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interop-progress.json"
            rows=[self.progress_row("chatgpt")]
            rows[0]["checks"]["invented-check"]=rows[0]["checks"].pop("oauth-protected-resource-discovery")
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"CHECKS_INVALID"): mod.external_client_progress(root)
            self.fixture(root)
            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["requestIds"]["invented-audit-check"]=evidence["clients"][0]["requestIds"].pop(next(iter(evidence["clients"][0]["requestIds"])))
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"REQUEST_IDS_INVALID"): mod.verify(root)

    def test_progress_rejects_reused_challenge_digest_and_inconsistent_completion_flags(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interop-progress.json"
            rows=[self.progress_row("chatgpt"),self.progress_row("claude")]
            rows[1]["challengeSha256"]=rows[0]["challengeSha256"]
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":2,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"EVIDENCE_REUSE"): mod.external_client_progress(root)
            rows=[self.progress_row("chatgpt")]
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":1,"complete":False,"externalCertificationPass":True,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"COUNT_INVALID"): mod.external_client_progress(root)

    def test_non_genesis_audit_window_metadata_is_accepted_but_malformed_anchor_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interop-progress.json"
            row=self.progress_row("chatgpt")
            row["serverAuditWitness"]["auditWindowStartSequence"]=101
            row["serverAuditWitness"]["auditWindowPreviousDigest"]="sha256:"+hashlib.sha256(b"prior-head").hexdigest()
            row["serverAuditWitness"]["auditHeadSequence"]=106
            for offset,event in enumerate(row["serverAuditWitness"]["matchedEvents"].values(),101):
                event["sequence"]=offset
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[row],"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            self.assertEqual(1,mod.external_client_progress(root)["certifiedClientCount"])
            row["serverAuditWitness"]["auditWindowPreviousDigest"]="not-a-digest"
            p.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[row],"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"SERVER_WITNESS"): mod.external_client_progress(root)

    def test_weak_audit_witness_is_rejected_in_progress_and_final_admission(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            progress_path=root/"lab/mcp-external-client-interop-progress.json"
            rows=[self.progress_row("chatgpt")]
            rows[0]["serverAuditWitness"]["auditChainDigestVerified"]=False
            progress_path.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":rows,"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"PROGRESS_SERVER_WITNESS"): mod.external_client_progress(root)
            self.fixture(root)
            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["serverAuditWitness"].pop("auditMethodVersion")
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"INTEROP_SERVER_WITNESS"): mod.verify(root)

    def test_progress_and_final_reject_interop_binding_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            progress_path=root/"lab/mcp-external-client-interop-progress.json"
            row=self.progress_row("chatgpt")
            row["interopBindingDigest"]="sha256:"+"0"*64
            progress_path.write_text(json.dumps({"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,"matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),"campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),"oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),"protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp","allAdmittedReceiptsPass":True,"clients":[row],"certifiedClientCount":1,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False,"runtimeCertified":False,"physicalCertified":False}))
            with self.assertRaisesRegex(RuntimeError,"INTEROP_BINDING_INVALID"): mod.external_client_progress(root)
            self.fixture(root)
            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(evidence_path.read_text())
            evidence["clients"][0]["serverAuditWitness"]["interopBindingDigest"]="sha256:"+"1"*64
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"INTEROP_BINDING_INVALID"): mod.verify(root)

    def test_final_evidence_rejects_trusted_client_provenance_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text())
            evidence["clients"][0]["trustedClientRevision"]=2
            p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_DRIFT"):
                mod.verify(root)
            _,evidence=self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text())
            evidence["trustedClientBindings"]["chatgpt"]["trustedClientRevision"]=2
            p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_DRIFT"):
                mod.verify(root)

    def test_progress_and_final_evidence_reject_extra_scope_claims(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            progress=root/"lab/mcp-external-client-interop-progress.json"
            rows=[self.progress_row("chatgpt")]
            doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress",
                 "authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","matrixAuthority":mod.mcp_contract.MATRIX_AUTHORITY,
                 "matrixSha256":"sha256:"+hashlib.sha256(b"matrix").hexdigest(),
                 "campaignAuthority":mod.mcp_contract.CAMPAIGN_AUTHORITY,"campaignId":"mcp-interop-testcampaign",
                 "campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),
                 "oauthClientBindingAuthority":mod.mcp_contract.OAUTH_BINDING_AUTHORITY,
                 "oauthClientBindingsSha256":"sha256:"+hashlib.sha256(b"progress-oauth-bindings").hexdigest(),
                 "oauthClientBindings":self.oauth_bindings(),"trustedClientBindings":self.trusted_bindings(),
                 "protocol":"2026-07-28","transport":"streamable-http","endpoint":"https://mcp.example.test/mcp",
                 "clients":rows,"certifiedClientCount":1,"complete":False,"allAdmittedReceiptsPass":True,
                 "serverAuditWitnessPass":False,"externalCertificationPass":False,"runtimeCertified":False,"physicalCertified":False,
                 "physicalPass":True}
            progress.write_text(json.dumps(doc))
            with self.assertRaisesRegex(RuntimeError,"FIELDS_INVALID"):
                mod.external_client_progress(root)

            evidence_path=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(evidence_path.read_text()); evidence["physicalPass"]=True
            evidence_path.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"FIELDS_INVALID"):
                mod.verify(root)

    def test_wrong_client_surface_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text()); evidence["clients"][0]["clientSurface"]="Generic MCP"; p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"CLIENT_SURFACE"):
                mod.verify(root)

    def test_mutable_distribution_url_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text()); d["inputPack"]["urls"]=["https://dist.example.test/latest/appliance.zip"]; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"CONTENT_ADDRESS"): mod.verify(root)
if __name__=="__main__": unittest.main()
