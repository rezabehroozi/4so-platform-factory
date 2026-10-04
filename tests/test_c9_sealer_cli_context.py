import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_cli_context",ROOT/"scripts/seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9SealerCLIContextTests(unittest.TestCase):
    def test_main_emits_canonical_working_directory_for_post_seal_handoff(self):
        evidence={
            "authority":mod.AUTHORITY,
            "sourceCommitSHA":"a"*40,
            "releaseArchive":"release.zip",
            "releaseArchiveSha256":"sha256:"+"b"*64,
            "fullVerifierPass":True,
            "physicalCertified":False,
        }
        handoff={
            "nextActionCode":"COMMIT_C9_EVIDENCE",
            "nextCommand":["git","add","lab/final-exact-release-evidence.json"],
            "followupCommand":["git","commit","-m","evidence: seal final exact pre-certification release"],
        }
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            out=root/"lab/final-exact-release-evidence.json"
            with (
                mock.patch.object(sys,"argv",["seal_final_exact_release.py","--root",str(root),"--out",str(out)]),
                mock.patch.object(mod,"execute",return_value=evidence),
                mock.patch.object(mod,"admit_output_path",return_value=out),
                mock.patch.object(mod,"final_git_handoff",return_value=handoff),
            ):
                buf=io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc=mod.main()
        self.assertEqual(0,rc)
        result=json.loads(buf.getvalue())
        self.assertEqual(str(root),result["workingDirectory"])
        self.assertEqual("COMMIT_C9_EVIDENCE",result["nextActionCode"])


if __name__=="__main__":
    unittest.main()
