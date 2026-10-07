import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
CORE_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(CORE_SPEC); CORE_SPEC.loader.exec_module(core)
sys.modules["seal_mcp_external_interop"]=core
FETCH_SPEC=importlib.util.spec_from_file_location("fetch_mcp_external_audit_window",ROOT/"scripts"/"fetch_mcp_external_audit_window.py")
fetcher=importlib.util.module_from_spec(FETCH_SPEC); FETCH_SPEC.loader.exec_module(fetcher)


class _Response:
    status=200
    def __init__(self,url,body): self._url=url; self._body=body
    def geturl(self): return self._url
    def read(self,_limit): return self._body
    def __enter__(self): return self
    def __exit__(self,*_args): return False


class _Opener:
    def __init__(self,body): self.body=body
    def open(self,request,timeout=20): return _Response(request.full_url,self.body)


class C7WAuditFetchDigestBindingTests(unittest.TestCase):
    def test_fetch_returns_digest_from_verified_witness_not_live_output_path(self):
        matrix={
            "authority":core.MATRIX_AUTHORITY,
            "spec":{"sharedRequiredChecks":list(core.REQUIRED_CHECKS),"protocol":"2026-07-28"},
        }
        receipt={
            "endpoint":"https://mcp.example.test/mcp",
            "requestIds":{name:f"request-{idx:02d}" for idx,name in enumerate(core.AUDITED_CHECKS,1)},
        }
        verified_digest="sha256:"+"1"*64
        live_path_digest="sha256:"+"2"*64
        witness={
            "auditExportSha256":verified_digest,
            "auditHeadSequence":6,
            "auditHeadDigest":"sha256:"+"3"*64,
            "interopBindingDigest":"sha256:"+"4"*64,
        }
        body=json.dumps([{"placeholder":True}]).encode()
        with (
            mock.patch.object(core,"load",return_value=matrix),
            mock.patch.object(core,"verify_campaign",return_value={}),
            mock.patch.object(core,"verify_receipt",return_value=receipt),
            mock.patch.object(fetcher,"exact_https_opener",return_value=_Opener(body)),
            mock.patch.object(fetcher.ssl,"create_default_context",return_value=object()),
            mock.patch.object(fetcher,"atomic_write",return_value=witness),
            mock.patch.object(core,"sha256",return_value=live_path_digest),
            mock.patch.dict(fetcher.os.environ,{"TOKEN":"admin-token"},clear=False),
        ):
            result=fetcher.fetch(Path("matrix.json"),Path("campaign.json"),Path("receipt.json"),"chatgpt","TOKEN",Path("audit.json"),1,0)
        self.assertEqual(verified_digest,result["auditExportSha256"])


if __name__=="__main__":
    unittest.main()
