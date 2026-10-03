import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_execution_binding_cli",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightExecutionBindingCLITests(unittest.TestCase):
    def test_materializer_followup_canonical_execution_binding_path_is_accepted_by_preflight_cli(self):
        canonical=mod.DEFAULT_EXECUTION_BINDING_REL
        captured={}
        def fake_preflight(root,matrix,endpoint,oauth_client_map,token_env,execution_binding_path=None):
            captured["path"]=execution_binding_path
            return {"ready":True,"physicalCertified":False}
        argv=["c7w_preflight.py","--execution-bindings",str(canonical)]
        with (
            mock.patch.object(sys,"argv",argv),
            mock.patch.dict(os.environ,{},clear=True),
            mock.patch.object(mod,"preflight",side_effect=fake_preflight),
        ):
            self.assertEqual(0,mod.main())
        self.assertEqual(canonical,captured["path"])


if __name__=="__main__":
    unittest.main()
