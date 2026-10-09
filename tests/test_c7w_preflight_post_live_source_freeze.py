import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_preflight_post_live_source_freeze",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightPostLiveSourceFreezeTests(unittest.TestCase):
    def test_source_change_during_live_readback_blocks_ready_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state"/"private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}\n",encoding="utf-8")
            execution=private/"c7w-execution-bindings.json"; execution.write_text("{}\n",encoding="utf-8")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"
            source_sha="a"*40
            changed_sha="b"*40
            bindings={client:client+"-oauth" for client in mod.core.CLIENTS}
            trusted={client:{"trustedClientId":"trusted-"+client} for client in mod.core.CLIENTS}
            execution_doc={
                "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
                "credentialProfileContractSha256":"sha256:"+"c"*64,
            }
            runtime={
                "authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1",
                "product":"4SO Platform Factory",
                "version":"0.0.unit",
                "sourceCommitSHA":source_sha,
            }
            with (
                mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False),
                mock.patch.object(mod,"_existing_state_handoff",return_value=None),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),
                mock.patch.object(mod,"git_source_commit",side_effect=[source_sha,changed_sha]),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
                mock.patch.object(mod.execution_bindings,"load",return_value=(execution_doc,"sha256:"+"d"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
                mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),
                mock.patch.object(mod.campaign,"trusted_client_readback",return_value=trusted),
            ):
                out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN",execution)
        self.assertFalse(out["ready"])
        self.assertEqual(["MCP_EXTERNAL_LOCAL_SOURCE_CHANGED_DURING_PREFLIGHT"],out["blockers"])
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])
        self.assertEqual(["git","status","--short"],out["nextCommand"])
        self.assertEqual(str(root.resolve()),out["workingDirectory"])
        self.assertNotIn("secret",str(out))


if __name__=="__main__":
    unittest.main()
