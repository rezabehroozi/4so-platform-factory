import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location(
    "c9_stable_snapshot_publication_parent_race_test",
    ROOT/"scripts"/"c9_stable_snapshot.py",
)
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9PublicationParentRaceTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os,"symlink"),"symlink unavailable")
    def test_publication_rejects_parent_swap_before_temp_creation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            source=root/"verified.zip"; source.write_bytes(b"verified-release-bytes")
            target_parent=root/"release"/"exact-sha"/("a"*40)
            target_parent.mkdir(parents=True)
            target=target_parent/"release.zip"
            outside=Path(td)/"outside"; outside.mkdir()
            parked=root/"parked-source-parent"
            real_mkstemp=mod.tempfile.mkstemp

            def swap_parent_then_create(*args,**kwargs):
                target_parent.rename(parked)
                target_parent.symlink_to(outside,target_is_directory=True)
                return real_mkstemp(*args,**kwargs)

            with mock.patch.object(mod.tempfile,"mkstemp",side_effect=swap_parent_then_create):
                with self.assertRaisesRegex(RuntimeError,"FINAL_EXACT_RELEASE_PUBLICATION_PARENT_CHANGED"):
                    mod.publish_verified_file(source,target)

            self.assertFalse((outside/target.name).exists())


if __name__=="__main__":
    unittest.main()
