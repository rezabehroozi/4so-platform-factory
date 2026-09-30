import hashlib, importlib.util, json, tempfile, unittest, sys
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SEAL_SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop",ROOT/"scripts"/"seal_mcp_external_interop.py")
seal=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(seal); sys.modules["seal_mcp_external_interop"]=seal
FETCH_SPEC=importlib.util.spec_from_file_location("fetch_mcp_external_audit_window",ROOT/"scripts"/"fetch_mcp_external_audit_window.py")
fetcher=importlib.util.module_from_spec(FETCH_SPEC); FETCH_SPEC.loader.exec_module(fetcher)

class C7WAuditFetchEvidenceTests(unittest.TestCase):
    def receipt(self):
        client="chatgpt"
        challenge="sha256:"+hashlib.sha256(b"challenge").hexdigest()
        binding=seal.interop_binding_digest("mcp-interop-testcampaign",client,challenge)
        return {
            "clientId":client,
            "challengeSha256":challenge,
            "interopBindingAuthority":seal.INTEROP_BINDING_AUTHORITY,
            "interopBindingDigest":binding,
            "requestIds":{name:f"{client}-{idx:02d}-request" for idx,name in enumerate(seal.AUDITED_CHECKS,1)},
        }

    def audit(self,receipt):
        rows=[]; previous=""
        for seq,check in enumerate(seal.AUDITED_CHECKS,1):
            category,decision,reason=seal.AUDIT_REQUIREMENTS[check]
            row={
                "id":f"sau-{seq}","sequence":seq,"occurredAt":"2026-09-29T00:00:00Z",
                "methodVersion":seal.AUDIT_METHOD_VERSION,"category":category,"decision":decision,
                "actorId":"external-user","authentication":"oidc","method":"POST","path":"/mcp",
                "statusCode":200 if decision=="ALLOW" else 403,"reasonCode":reason,
                "requestId":receipt["requestIds"][check],
                "mcpInteropBindingDigest":receipt["interopBindingDigest"],"previousDigest":previous,
            }
            row["digest"]=seal.audit_event_digest(row); rows.append(row); previous=row["digest"]
        return rows

    def raw(self,rows):
        return (json.dumps(rows,indent=2,sort_keys=True)+"\n").encode()

    def test_admin_audit_fetch_opener_refuses_redirects(self):
        opener=fetcher.exact_https_opener(fetcher.ssl.create_default_context())
        self.assertTrue(any(isinstance(handler,fetcher.RejectRedirects) for handler in opener.handlers))
        req=fetcher.Request("https://mcp.example.test/api/v1/security-audit-events")
        handler=fetcher.RejectRedirects()
        self.assertIsNone(handler.redirect_request(req,None,307,"Temporary Redirect",{},"https://other.example.test/audit"))

    def test_atomic_audit_write_is_idempotent_but_not_replaceable(self):
        receipt=self.receipt(); raw=self.raw(self.audit(receipt))
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"chatgpt.json"
            first=fetcher.atomic_write(path,raw,receipt,"chatgpt")
            second=fetcher.atomic_write(path,raw,receipt,"chatgpt")
            self.assertEqual(first["auditHeadDigest"],second["auditHeadDigest"])
            altered=json.loads(raw.decode()); altered[0]["actorId"]="other-user"; altered[0]["digest"]=seal.audit_event_digest(altered[0])
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_REPLACEMENT_FORBIDDEN"):
                fetcher.atomic_write(path,self.raw(altered),receipt,"chatgpt")

    def test_concurrent_different_evidence_cannot_win_publication_race(self):
        receipt=self.receipt(); rows=self.audit(receipt); raw=self.raw(rows)
        altered=list(rows); altered=json.loads(json.dumps(rows)); altered[0]["actorId"]="racing-writer"
        previous=""
        for row in altered:
            row["previousDigest"]=previous; row["digest"]=seal.audit_event_digest(row); previous=row["digest"]
        raced_raw=self.raw(altered)
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"chatgpt.json"
            def race_link(_src,dst,follow_symlinks=False):
                Path(dst).write_bytes(raced_raw)
                raise FileExistsError(dst)
            with mock.patch.object(fetcher.os,"link",side_effect=race_link):
                with self.assertRaisesRegex(RuntimeError,"OUTPUT_REPLACEMENT_FORBIDDEN"):
                    fetcher.atomic_write(path,raw,receipt,"chatgpt")
            self.assertEqual(raced_raw,path.read_bytes())

    def test_audit_output_parent_symlink_is_rejected(self):
        receipt=self.receipt(); raw=self.raw(self.audit(receipt))
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); real=root/"real"; real.mkdir()
            alias=root/"alias"; alias.symlink_to(real,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PARENT_INVALID"):
                fetcher.atomic_write(alias/"chatgpt.json",raw,receipt,"chatgpt")
            self.assertFalse((real/"chatgpt.json").exists())

    def test_semantically_unbound_audit_is_rejected_before_persist(self):
        receipt=self.receipt(); rows=self.audit(receipt)
        rows[0]["mcpInteropBindingDigest"]="sha256:"+"0"*64
        previous=""
        for row in rows:
            row["previousDigest"]=previous; row["digest"]=seal.audit_event_digest(row); previous=row["digest"]
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"chatgpt.json"
            with self.assertRaisesRegex(RuntimeError,"AUDIT_INTEROP_BINDING_MISSING"):
                fetcher.atomic_write(path,self.raw(rows),receipt,"chatgpt")
            self.assertFalse(path.exists())

if __name__=="__main__":
    unittest.main()
