import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_mcp_external_interop as mod


class LocalC7WRunnerTests(unittest.TestCase):
    def test_campaign_inputs_use_same_validated_snapshot_for_semantics_and_digest(self):
        matrix=ROOT/"lab"/"mcp-external-client-interop-matrix.json"
        expected_matrix="sha256:"+hashlib.sha256(matrix.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            oauth=Path(td)/"oauth.json"
            oauth.write_text(json.dumps({
                "authority":mod.core.OAUTH_BINDING_AUTHORITY,
                "clients":{client:f"{client}-oauth" for client in mod.core.CLIENTS},
            }),encoding="utf-8")
            expected_oauth="sha256:"+hashlib.sha256(oauth.read_bytes()).hexdigest()
            with mock.patch.object(mod.campaign_builder,"file_sha",return_value="sha256:"+"f"*64):
                bindings,digest=mod.campaign_builder.load_oauth_bindings(oauth)
                self.assertEqual(expected_oauth,digest)
                trusted={
                    client:{
                        "oauthClientId":bindings[client],
                        "trustedClientId":"trusted-"+client,
                        "trustedClientRevision":1,
                        "trustedClientProvider":client,
                    }
                    for client in mod.core.CLIENTS
                }
                campaign=mod.campaign_builder.prepare(
                    matrix,
                    "https://mcp.example.test/mcp",
                    {"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY},
                    digest,
                    trusted,
                    {
                        "authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1",
                        "product":"4SO Platform Factory",
                        "version":"0.0.unit",
                        "sourceCommitSHA":"a"*40,
                    },
                )
            self.assertEqual(expected_matrix,campaign["matrixSha256"])
            self.assertEqual(expected_oauth,campaign["oauthClientBindingsSha256"])

    def test_secure_state_owns_portable_capture_directory(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            p=mod.paths(state)
            self.assertEqual(state/"captures",p["captures"])
            self.assertTrue(p["captures"].is_dir())
            handoff=mod.client_execution_handoff(state,"chatgpt")
            self.assertEqual(str(p["captures"]/"chatgpt.capture.json"),handoff["expectedCapturePath"])
            self.assertNotIn("/secure/",json.dumps(handoff))

    def test_capture_template_preserves_runtime_identity_and_exact_check_shape(self):
        packet={
            "clientId":"chatgpt",
            "clientSurface":"ChatGPT custom MCP",
            "campaignId":"mcp-interop-unit",
            "challengeSha256":"sha256:"+"a"*64,
            "endpoint":"https://mcp.example.test/mcp",
            "sourceCommitSHA":"b"*40,
            "runtimeVersion":"0.0.unit",
            "receiptRequirements":{"requestIds":list(mod.core.AUDITED_CHECKS),"structuredResponseObservationRequired":True},
            "checks":[{"id":name,"expect":{"accepted":False}} for name in mod.core.REQUIRED_CHECKS],
        }
        out=mod.capture_template(packet)
        self.assertEqual("MCP_EXTERNAL_CLIENT_CAPTURE_V1",out["authority"])
        self.assertEqual(packet["sourceCommitSHA"],out["sourceCommitSHA"])
        self.assertEqual(packet["runtimeVersion"],out["runtimeVersion"])
        self.assertEqual("",out["executedAt"])
        self.assertFalse(out["externalExecution"])
        self.assertFalse(out["credentialedExecution"])
        self.assertEqual(list(mod.core.REQUIRED_CHECKS),list(out["checks"]))
        for name,row in out["checks"].items():
            if name in mod.core.AUDITED_CHECKS:
                self.assertEqual({"observed":{"accepted":None},"requestId":""},row)
            else:
                self.assertEqual({"observed":{"accepted":None}},row)

    def test_prepare_resume_avoids_live_registry_and_identity_calls(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state"
            state.mkdir()
            campaign_path=state/"campaign.json"
            campaign_path.write_text("{}")
            source_sha="c"*40
            campaign={
                "campaignId":"mcp-interop-resume",
                "sourceCommitSHA":source_sha,
                "runtimeVersion":"0.0.unit",
            }
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                endpoint="https://mcp.example.test/mcp",
                oauth_client_map=None,
                token_env="C7W_PLATFORM_ADMIN_TOKEN",
                source_commit_sha=source_sha,
                progress_out=Path(td)/"progress.json",
                evidence_out=Path(td)/"evidence.json",
            )
            def packet(_,__,client):
                return {
                    "clientId":client,
                    "clientSurface":mod.core.CLIENT_SURFACES[client],
                    "campaignId":campaign["campaignId"],
                    "challengeSha256":"sha256:"+("a"*64),
                    "endpoint":args.endpoint,
                    "sourceCommitSHA":source_sha,
                    "runtimeVersion":"0.0.unit",
                    "receiptRequirements":{"requestIds":list(mod.core.AUDITED_CHECKS),"structuredResponseObservationRequired":True},
                    "checks":[{"id":name,"expect":{"accepted":False}} for name in mod.core.REQUIRED_CHECKS],
                }
            with (
                mock.patch.object(mod.campaign_builder,"source_commit_sha",return_value=source_sha),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign_builder,"resume_existing",return_value=campaign),
                mock.patch.object(mod.campaign_builder,"runtime_identity_readback",side_effect=AssertionError("runtime readback must not run on resume")),
                mock.patch.object(mod.campaign_builder,"trusted_client_readback",side_effect=AssertionError("registry readback must not run on resume")),
                mock.patch.object(mod.campaign_builder,"live_preflight",side_effect=AssertionError("preflight must not run on resume")),
                mock.patch.object(mod.packet_builder,"packet",side_effect=packet),
                mock.patch.object(mod,"progress_status",return_value={
                    "certified":["chatgpt","claude"],
                    "missing":["gemini","grok"],
                    "complete":False,
                    "nextClient":"gemini",
                    "campaignPrepared":True,
                }),
            ):
                out=mod.prepare(args)
            self.assertTrue(out["resumed"])
            self.assertEqual(source_sha,out["sourceCommitSHA"])
            self.assertEqual(["chatgpt","claude"],out["certified"])
            self.assertEqual(["gemini","grok"],out["missing"])
            self.assertEqual("RUN_EXTERNAL_CLIENT",out["nextActionCode"])
            self.assertEqual("gemini",out["nextClient"])
            self.assertEqual([],out["nextCommand"])
            self.assertEqual(out["clientHandoff"]["gemini"]["admitCommand"],out["postExternalExecutionCommand"])
            self.assertEqual(set(mod.core.CLIENTS),set(out["clientHandoff"]))
            for client in mod.core.CLIENTS:
                self.assertTrue((state/"packets"/f"{client}.json").is_file())
                capture=json.loads((state/"capture-templates"/f"{client}.json").read_text())
                self.assertEqual(source_sha,capture["sourceCommitSHA"])
                self.assertEqual("0.0.unit",capture["runtimeVersion"])
                handoff=out["clientHandoff"][client]
                self.assertEqual(str(state/"packets"/f"{client}.json"),handoff["packetPath"])
                self.assertEqual(str(state/"capture-templates"/f"{client}.json"),handoff["captureTemplatePath"])
                expected_capture=str(state/"captures"/f"{client}.capture.json")
                self.assertEqual(expected_capture,handoff["expectedCapturePath"])
                self.assertEqual([sys.executable,"scripts/run_mcp_external_interop.py","--state-dir",str(state),"admit","--client",client,"--capture",expected_capture],handoff["admitCommand"])

    def test_admit_revalidates_existing_audit_with_normalized_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            p=mod.paths(state)
            client="chatgpt"
            packet_path=p["packets"]/(client+".json"); packet_path.write_text("{}")
            capture=Path(td)/"capture.json"; capture.write_text("{}")
            audit_path=p["audits"]/(client+".json"); audit_path.write_text("[]")
            raw_receipt={"authority":mod.core.RECEIPT_AUTHORITY,"clientId":client}
            normalized={"clientId":client,"requestIds":{},"executedAt":"2026-10-01T00:00:00Z","campaignCreatedAt":"2026-10-01T00:00:00Z","campaignExpiresAt":"2026-10-02T00:00:00Z","executionAuditWindowSeconds":60}
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",client=client,capture=capture,token_env="TOKEN",attempts=1,interval_seconds=0.0,progress_out=Path(td)/"progress.json",evidence_out=Path(td)/"evidence.json",allow_campaign_supersede=False)
            with (
                mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(mod,"require_active_campaign_source",return_value="a"*40),
                mock.patch.object(mod.finalizer,"finalize",return_value=raw_receipt),
                mock.patch.object(mod.core,"write_json_once_or_identical"),
                mock.patch.object(mod.admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},list(mod.core.REQUIRED_CHECKS),{})),
                mock.patch.object(mod.core,"verify_receipt",return_value=normalized) as verify_receipt,
                mock.patch.object(mod.core,"verify_server_audit",return_value={}) as verify_audit,
                mock.patch.object(mod.admission,"progress_lock"),
                mock.patch.object(mod.admission,"merge",return_value={"clients":[],"certifiedClientCount":0,"complete":False}) as merge,
                mock.patch.object(mod.core,"write_json_atomic_replace"),
                mock.patch.object(mod,"progress_status",return_value={"certified":[],"complete":False,"nextClient":"chatgpt"}),
            ):
                out=mod.admit(args)
            verify_receipt.assert_called_once()
            verify_audit.assert_called_once_with(audit_path,normalized,client)
            self.assertFalse(merge.call_args.kwargs["allow_campaign_supersede"])
            self.assertEqual("RUN_EXTERNAL_CLIENT",out["nextActionCode"])
            self.assertEqual("chatgpt",out["nextClientHandoff"]["clientId"])
            self.assertEqual([],out["nextCommand"])
            self.assertEqual(out["nextClientHandoff"]["admitCommand"],out["postExternalExecutionCommand"])

    def test_admit_fourth_client_hands_directly_to_independent_seal(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            p=mod.paths(state); client="grok"
            (p["packets"]/(client+".json")).write_text("{}")
            capture=Path(td)/"capture.json"; capture.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",client=client,capture=capture,token_env="TOKEN",attempts=1,interval_seconds=0.0,progress_out=Path(td)/"progress.json",evidence_out=Path(td)/"evidence.json",allow_campaign_supersede=False)
            with (
                mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(mod,"require_active_campaign_source",return_value="a"*40),
                mock.patch.object(mod.finalizer,"finalize",return_value={"authority":mod.core.RECEIPT_AUTHORITY,"clientId":client}),
                mock.patch.object(mod.core,"write_json_once_or_identical"),
                mock.patch.object(mod.admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},list(mod.core.REQUIRED_CHECKS),{})),
                mock.patch.object(mod.core,"verify_receipt",return_value={"clientId":client,"requestIds":{},"executedAt":"2026-10-01T00:00:00Z","campaignCreatedAt":"2026-10-01T00:00:00Z","campaignExpiresAt":"2026-10-02T00:00:00Z","executionAuditWindowSeconds":60}),
                mock.patch.object(mod.audit_fetch,"fetch",return_value={}),
                mock.patch.object(mod.admission,"progress_lock"),
                mock.patch.object(mod.admission,"merge",return_value={"clients":[1,2,3,4],"certifiedClientCount":4,"complete":True}),
                mock.patch.object(mod.admission,"final_evidence",return_value={"authority":"final"}),
                mock.patch.object(mod.core,"write_json_atomic_replace"),
                mock.patch.object(mod,"progress_status",return_value={"certified":list(mod.core.CLIENTS),"complete":True,"nextClient":None}),
            ):
                out=mod.admit(args)
            self.assertEqual("RUN_C7W_SEAL",out["nextActionCode"])
            self.assertEqual([sys.executable,"scripts/run_mcp_external_interop.py","--state-dir",str(state),"seal"],out["nextCommand"])
            self.assertTrue(out["complete"])

    def test_admit_forwards_explicit_partial_campaign_supersede(self):
        parser=mod.parser()
        args=parser.parse_args(["--state-dir",".state/new-campaign","admit","--client","chatgpt","--capture",".state/new-campaign/captures/chatgpt.json","--allow-campaign-supersede"])
        self.assertTrue(args.allow_campaign_supersede)

    def test_status_fails_closed_when_canonical_progress_survives_lost_local_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/"missing-state"; progress=root/"progress.json"; progress.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=root/"evidence.json")
            with self.assertRaisesRegex(RuntimeError,"STATE_MISSING_WITH_CANONICAL_EVIDENCE"):
                mod.status(args)
            self.assertFalse(state.exists())

    def test_progress_status_fails_closed_when_campaign_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state"); progress=root/"progress.json"; progress.write_text("{}")
            with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_MISSING_WITH_CANONICAL_PROGRESS"):
                mod.progress_status(ROOT/"lab/mcp-external-client-interop-matrix.json",state,progress)

    def test_status_rejects_evidence_without_complete_progress(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            evidence=root/"evidence.json"; evidence.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=root/"progress.json",evidence_out=evidence)
            with self.assertRaisesRegex(RuntimeError,"EVIDENCE_WITHOUT_PROGRESS"):
                mod.status(args)

        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            (state/"campaign.json").write_text("{}")
            progress=root/"progress.json"; progress.write_text("{}")
            evidence=root/"evidence.json"; evidence.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=evidence)
            with mock.patch.object(mod,"progress_status",return_value={"complete":False,"certified":["chatgpt"],"missing":["claude","gemini","grok"],"nextClient":"claude","campaignPrepared":True}):
                with self.assertRaisesRegex(RuntimeError,"EVIDENCE_WITH_INCOMPLETE_PROGRESS"):
                    mod.status(args)

    def test_source_freeze_allows_only_canonical_c7w_evidence_dirty_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"tracked.txt").write_text("base\n")
            subprocess.run(["git","add","tracked.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","base"],cwd=root,check=True,capture_output=True)

            lab=root/"lab"; lab.mkdir()
            (lab/"mcp-external-client-interop-progress.json").write_text("{}\n")
            mod.require_c7w_source_freeze(root)

            (root/"tracked.txt").write_text("changed\n")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_NOT_FROZEN"):
                mod.require_c7w_source_freeze(root)

    def test_source_freeze_rejects_non_main_branch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"tracked.txt").write_text("base\n")
            subprocess.run(["git","add","tracked.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","base"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","checkout","-b","feature"],cwd=root,check=True,capture_output=True)
            with self.assertRaisesRegex(RuntimeError,"BRANCH_NOT_MAIN"):
                mod.require_c7w_source_freeze(root)

    def test_active_campaign_source_allows_evidence_only_descendant_and_rejects_code_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"tracked.txt").write_text("base\n")
            subprocess.run(["git","add","tracked.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","base"],cwd=root,check=True,capture_output=True)
            certified=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()
            campaign={"sourceCommitSHA":certified}

            self.assertEqual(certified,mod.require_active_campaign_source(root,campaign))

            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"; progress.write_text("{}\n")
            subprocess.run(["git","add",progress.relative_to(root).as_posix()],cwd=root,check=True)
            subprocess.run(["git","commit","-m","evidence progress"],cwd=root,check=True,capture_output=True)
            evidence_head=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()
            self.assertEqual(evidence_head,mod.require_active_campaign_source(root,campaign))

            (root/"tracked.txt").write_text("changed\n")
            subprocess.run(["git","add","tracked.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","code drift"],cwd=root,check=True,capture_output=True)
            with self.assertRaisesRegex(RuntimeError,"SOURCE_DELTA_NOT_EVIDENCE_ONLY"):
                mod.require_active_campaign_source(root,campaign)

    def test_git_handoff_requires_committed_c7w_evidence_before_c9(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"seed.txt").write_text("seed\n")
            subprocess.run(["git","add","seed.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","seed"],cwd=root,check=True,capture_output=True)

            certified=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text("{}\n"); evidence.write_text(json.dumps({"sourceCommitSHA":certified})+"\n")
            pending=mod.git_handoff(root,evidence,progress)
            self.assertEqual("COMMIT_C7W_EVIDENCE",pending["nextActionCode"])
            self.assertEqual(["git","add","lab/mcp-external-client-interop-progress.json","lab/mcp-external-client-interoperability-evidence.json"],pending["nextCommand"])
            self.assertIn("git"," ".join(pending["followupCommand"]))

            subprocess.run(["git","add","lab"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","evidence"],cwd=root,check=True,capture_output=True)
            ready=mod.git_handoff(root,evidence,progress)
            self.assertEqual("RUN_C9_SEAL",ready["nextActionCode"])
            self.assertEqual([sys.executable,"scripts/seal_final_exact_release.py","--root",".","--out","lab/final-exact-release-evidence.json"],ready["nextCommand"])
            self.assertRegex(ready["sourceCommitSHA"],r"^[0-9a-f]{40}$")

    def test_c9_handoff_requires_exact_linux_host_on_windows(self):
        source_sha="a"*40
        with mock.patch.object(mod.sys,"platform","win32"):
            out=mod.c9_handoff(source_sha)
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST",out["nextActionCode"])
        self.assertEqual([],out["nextCommand"])
        self.assertEqual("linux-amd64-exact-toolchain",out["requiredHost"])
        self.assertEqual(source_sha,out["requiredSourceCommitSHA"])
        self.assertEqual("<python>",out["preflightCommandTemplate"][0])
        self.assertEqual("--preflight",out["preflightCommandTemplate"][-1])
        self.assertEqual("<python>",out["nextCommandTemplate"][0])
        self.assertIn("scripts/seal_final_exact_release.py",out["nextCommandTemplate"])
        self.assertNotIn("make",json.dumps(out).lower())

    def test_c9_handoff_is_directly_executable_on_linux(self):
        with mock.patch.object(mod.sys,"platform","linux"):
            out=mod.c9_handoff("b"*40)
        self.assertEqual("RUN_C9_SEAL",out["nextActionCode"])
        self.assertEqual(mod.c9_seal_command(),out["nextCommand"])
        self.assertEqual(mod.c9_preflight_command(),out["preflightCommand"])
        self.assertEqual("--preflight",out["preflightCommand"][-1])
        self.assertEqual("linux-amd64-exact-toolchain",out["requiredHost"])

    def test_git_handoff_never_recommends_c9_with_unrelated_dirty_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"seed.txt").write_text("seed\n")
            subprocess.run(["git","add","seed.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","seed"],cwd=root,check=True,capture_output=True)
            certified=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text("{}\n"); evidence.write_text(json.dumps({"sourceCommitSHA":certified})+"\n")
            subprocess.run(["git","add","lab"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","evidence"],cwd=root,check=True,capture_output=True)
            (root/"seed.txt").write_text("dirty source\n")
            handoff=mod.git_handoff(root,evidence,progress)
            self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",handoff["nextActionCode"])
            self.assertEqual(["git","status","--short"],handoff["nextCommand"])
            self.assertNotIn("RUN_C9_SEAL",json.dumps(handoff))

    def test_incomplete_status_emits_executable_external_client_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            (state/"campaign.json").write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=root/"progress.json",evidence_out=root/"evidence.json")
            with mock.patch.object(mod,"progress_status",return_value={"complete":False,"certified":[],"missing":["chatgpt","claude","gemini","grok"],"nextClient":"chatgpt","campaignPrepared":True}):
                out=mod.status(args)
            self.assertEqual("RUN_EXTERNAL_CLIENT",out["nextActionCode"])
            expected_capture=str(state/"captures"/"chatgpt.capture.json")
            self.assertEqual([],out["nextCommand"])
            handoff=out["nextClientHandoff"]
            self.assertEqual("chatgpt",handoff["clientId"])
            self.assertEqual(str(state/"packets"/"chatgpt.json"),handoff["packetPath"])
            self.assertEqual(str(state/"capture-templates"/"chatgpt.json"),handoff["captureTemplatePath"])
            self.assertEqual(expected_capture,handoff["expectedCapturePath"])
            self.assertEqual("MCP_EXTERNAL_CLIENT_CAPTURE_V1",handoff["requiredCaptureAuthority"])
            self.assertEqual(handoff["admitCommand"],out["postExternalExecutionCommand"])
            self.assertNotIn("/secure/",json.dumps(handoff))

    def test_status_never_sends_next_client_on_stale_campaign_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            (state/"campaign.json").write_text(json.dumps({"sourceCommitSHA":"1"*40}))
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=root/"progress.json",evidence_out=root/"evidence.json")
            with (
                mock.patch.object(mod,"progress_status",return_value={"complete":False,"certified":["chatgpt"],"missing":["claude","gemini","grok"],"nextClient":"claude","campaignPrepared":True}),
                mock.patch.object(mod,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(mod.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="2"*40+"\n")),
            ):
                out=mod.status(args)
            self.assertEqual("RERUN_C7W_ON_CURRENT_SOURCE",out["nextActionCode"])
            self.assertNotIn("RUN_EXTERNAL_CLIENT",json.dumps(out))
            self.assertEqual("STATUS",out["action"])
            self.assertFalse(out["physicalCertified"])

    def test_seal_requires_complete_canonical_progress(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=root/"progress.json",evidence_out=root/"evidence.json")
            with mock.patch.object(mod,"progress_status",return_value={"complete":False,"nextClient":"claude"}):
                with self.assertRaisesRegex(RuntimeError,"SEAL_PROGRESS_INCOMPLETE next=claude"):
                    mod.seal(args)

    def test_seal_requires_incremental_and_bulk_evidence_to_match(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            progress=root/"progress.json"; progress.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=root/"evidence.json")
            with (
                mock.patch.object(mod,"progress_status",return_value={"complete":True,"nextClient":None}),
                mock.patch.object(mod.core,"load",return_value={}),
                mock.patch.object(mod.admission,"final_evidence",return_value={"authority":"progress"}),
                mock.patch.object(mod.core,"seal",return_value={"authority":"bulk"}),
            ):
                with self.assertRaisesRegex(RuntimeError,"SEAL_PROGRESS_BULK_DRIFT"):
                    mod.seal(args)

    def test_status_turns_expired_campaign_into_actionable_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=mod.secure_state_dir(root/"state")
            campaign={"campaignId":"mcp-interop-expired-unit"}
            (state/"campaign.json").write_text(json.dumps(campaign))
            progress=root/"progress.json"; progress.write_text("{}")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=root/"evidence.json")
            with mock.patch.object(mod,"progress_status",side_effect=RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")):
                out=mod.status(args)
            self.assertEqual("PREPARE_REPLACEMENT_C7W_CAMPAIGN",out["nextActionCode"])
            self.assertTrue(out["recoveryRequired"])
            self.assertEqual("CAMPAIGN_EXPIRED",out["recoveryReason"])
            self.assertTrue(out["replacementAdmitRequiresCampaignSupersede"])
            self.assertEqual({"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"},out["followupAdmitEnvironment"])
            self.assertEqual(sys.executable,out["nextCommand"][0])
            self.assertEqual("scripts/run_mcp_external_interop.py",out["nextCommand"][1])
            self.assertEqual("prepare",out["nextCommand"][-1])

    def test_status_without_state_is_explicitly_pending_and_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"missing-state"
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=Path(td)/"progress.json",evidence_out=Path(td)/"evidence.json")
            out=mod.status(args)
            self.assertFalse(state.exists())
            self.assertFalse(out["campaignPrepared"])
            self.assertFalse(out["complete"])
            self.assertEqual("chatgpt",out["nextClient"])
            self.assertEqual(list(mod.core.CLIENTS),out["missing"])
            self.assertEqual("PREPARE_C7W_CAMPAIGN",out["nextActionCode"])
            self.assertEqual(["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],out["requiredInputs"])


if __name__=="__main__":
    unittest.main()
