import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
CORE_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(CORE_SPEC); CORE_SPEC.loader.exec_module(core)
sys.modules["seal_mcp_external_interop"]=core
FETCH_SPEC=importlib.util.spec_from_file_location("fetch_mcp_external_audit_window",ROOT/"scripts"/"fetch_mcp_external_audit_window.py")
fetcher=importlib.util.module_from_spec(FETCH_SPEC); FETCH_SPEC.loader.exec_module(fetcher)


class C7WAuditExistingWitnessSnapshotTests(unittest.TestCase):
    def test_existing_witness_verifies_the_stable_snapshot_not_the_live_path(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"chatgpt.json"
            raw=b"[]\n"
            path.write_bytes(raw)
            witness={"auditHeadSequence":1}
            with (
                mock.patch.object(core,"_stable_file_bytes",return_value=raw) as stable,
                mock.patch.object(core,"verify_server_audit",return_value=witness) as verify,
            ):
                observed=fetcher._existing_witness(path,raw,{},"chatgpt")
            self.assertEqual(witness,observed)
            self.assertGreaterEqual(stable.call_count,2)
            verified_path=verify.call_args.args[0]
            self.assertNotEqual(path,verified_path)
            self.assertFalse(verified_path.exists())


if __name__=="__main__":
    unittest.main()
