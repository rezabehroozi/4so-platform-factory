import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_preflight",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightReconcileHandoffTests(unittest.TestCase):
    def test_trusted_client_failure_returns_exact_reconcile_command_without_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state"/"private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"
            bindings={client:f"oauth-{client}" for client in mod.core.CLIENTS}
            runtime={
                "authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1",
                "product":"4SO Platform Factory",
                "version":"0.0.unit",
                "sourceCommitSHA":"a"*40,
            }
            with (
                mock.patch.dict(os.environ,{"TOKEN_ENV":"super-secret"},clear=False),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),
                mock.patch.object(mod,"git_source_commit",return_value="a"*40),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
                mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),
                mock.patch.object(
                    mod.campaign,
                    "trusted_client_readback",
                    side_effect=RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_IDENTITY_INVALID chatgpt"),
                ),
            ):
                out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN_ENV")

        self.assertFalse(out["ready"])
        self.assertEqual("RECONCILE_C7W_TRUSTED_CLIENTS",out["nextActionCode"])
        self.assertEqual(str(root),out["workingDirectory"])
        self.assertEqual(sys.executable,out["nextCommand"][0])
        self.assertIn("scripts/reconcile_c7w_trusted_clients.py",out["nextCommand"])
        self.assertIn("--endpoint",out["nextCommand"])
        self.assertIn("https://mcp.example.test/mcp",out["nextCommand"])
        self.assertIn("--oauth-client-map",out["nextCommand"])
        self.assertIn(str(oauth),out["nextCommand"])
        self.assertIn("--token-env",out["nextCommand"])
        self.assertIn("TOKEN_ENV",out["nextCommand"])
        self.assertNotIn("super-secret",str(out))
        self.assertFalse(out["physicalCertified"])


if __name__=="__main__":
    unittest.main()
