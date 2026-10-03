import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)

core_spec=importlib.util.spec_from_file_location("seal_mcp_external_interop_historical_row_test",ROOT/"scripts/seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(core_spec); core_spec.loader.exec_module(core)
sys.modules["seal_mcp_external_interop"]=core
admission_spec=importlib.util.spec_from_file_location("admit_mcp_external_receipt_historical_row_test",ROOT/"scripts/admit_mcp_external_receipt.py")
admission=importlib.util.module_from_spec(admission_spec); admission_spec.loader.exec_module(admission)


class C7WHistoricalRowBindingTests(unittest.TestCase):
    def test_row_binding_uses_historical_campaign_window(self):
        campaign={}
        spec={}
        expected={"endpoint":"https://mcp.example.test/mcp"}
        rows={}
        with mock.patch.object(core,"campaign_time_window",return_value=(core.datetime(2026,10,1,tzinfo=core.timezone.utc),core.datetime(2026,10,2,tzinfo=core.timezone.utc),60)) as window:
            admission.validate_existing_campaign_rows(rows,expected,campaign,spec)
        self.assertFalse(window.call_args.kwargs["require_live"])


if __name__=="__main__":
    unittest.main()
