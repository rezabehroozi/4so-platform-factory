import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_admission_fence_test",ROOT/"scripts/seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9AdmissionSourceRevalidationTests(unittest.TestCase):
    def test_exact_source_admission_revalidates_worktree_before_cleanup(self):
        source_sha="a"*40
        admitted={"authority":mod.admission.AUTHORITY,"admitted":True,"physicalCertified":False}
        events=[]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            fake_worktree=root/"detached-source"
            with (
                mock.patch.object(mod,"prepare_exact_worktree",return_value=fake_worktree),
                mock.patch.object(mod.admission,"verify",side_effect=lambda *a,**k: events.append("admit") or admitted),
                mock.patch.object(mod,"verify_worktree_source_unchanged",side_effect=lambda *a,**k: events.append("revalidate")) as fence,
                mock.patch.object(mod,"remove_exact_worktree",side_effect=lambda *a,**k: events.append("remove")),
            ):
                result=mod.exact_source_admission(root,source_sha)
        self.assertEqual(admitted,result)
        self.assertEqual(["admit","revalidate","remove"],events)
        fence.assert_called_once_with(fake_worktree,source_sha)

    def test_native_build_admission_is_revalidated_before_toolchain_access(self):
        source=(ROOT/"scripts/seal_final_exact_release.py").read_text(encoding="utf-8")
        start=source.index("def execute(")
        end=source.index("\ndef main",start)
        execute_source=source[start:end]
        admit=execute_source.index("admission.verify(worktree")
        fence=execute_source.index("verify_worktree_source_unchanged(worktree, source_sha)",admit)
        toolchain=execute_source.index("safe_toolchain_archive(root, lock)",admit)
        self.assertLess(admit,fence)
        self.assertLess(fence,toolchain)


if __name__=="__main__":
    unittest.main()
