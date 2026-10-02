import importlib.util,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("closure",ROOT/"scripts"/"close_openchoreo_production_zot.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class OpenChoreoProductionClosureTests(unittest.TestCase):
    def test_plan_is_ordered_and_one_registry(self):
        with tempfile.TemporaryDirectory() as td:
            out=mod.plan(Path(td)/"work","zot.platform.internal:5000/4so/openchoreo")
            self.assertEqual("zot.platform.internal:5000",out["registryIdentity"])
            self.assertEqual("zot.platform.internal:5000/4so/openchoreo/openchoreo-runtime",out["executorRepository"])
            self.assertEqual([
              "mirror-exact-runtime-images","prepare-offline-executor-context","buildkit-push-executor",
              "seal-runtime-source","live-zot-digest-readback","promote-production-source-authority"
            ],out["steps"])
    def test_loopback_or_scheme_registry_rejects(self):
        for bad in ("127.0.0.1:5000/4so/openchoreo","https://zot.example/4so/openchoreo"):
            with self.assertRaises(RuntimeError): mod.registry_contract(bad)
    def test_atomic_copy_rejects_symlink_target_and_replaces_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); src=d/"src"; src.write_text("new"); dst=d/"dst"; dst.write_text("old")
            mod.atomic_copy(src,dst,"TEST"); self.assertEqual("new",dst.read_text())
            target=d/"target"; target.write_text("x"); link=d/"link"; link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError,"SYMLINK"): mod.atomic_copy(src,link,"TEST")
    def test_recoverable_workdir_preserves_known_checkpoints_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); work=root/"work"
            outputs=mod.plan(work,"zot.platform.internal:5000/4so/openchoreo")["outputs"]
            work.mkdir()
            known=Path(outputs["mirrorEvidence"]); known.write_text("{}\n")
            tmp=known.with_suffix(known.suffix+".tmp"); tmp.write_text("partial")
            stage=work/".4so-openchoreo-executor-crash"; stage.mkdir(); (stage/"partial").write_text("x")
            self.assertEqual(work,mod.recoverable_workdir(work,outputs))
            self.assertTrue(known.is_file())
            self.assertFalse(tmp.exists())
            self.assertFalse(stage.exists())
            (work/"unknown.bin").write_text("unexpected")
            with self.assertRaisesRegex(RuntimeError,"UNKNOWN_ENTRY"):
                mod.recoverable_workdir(work,outputs)

    def test_canonical_evidence_is_write_once_or_identical(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); src=root/"source"; dst=root/"evidence"
            src.write_text("sealed\n")
            mod.publish_once_or_identical(src,dst,"TEST")
            mod.publish_once_or_identical(src,dst,"TEST")
            self.assertEqual("sealed\n",dst.read_text())
            src.write_text("different\n")
            with self.assertRaisesRegex(RuntimeError,"REPLACEMENT_FORBIDDEN"):
                mod.publish_once_or_identical(src,dst,"TEST")

    def test_selection_promotion_is_compare_and_replace_fenced(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); promoted=root/"promoted"; selection=root/"selection"
            selection.write_text("pending\n"); promoted.write_text("sealed\n")
            before=selection.read_bytes()
            mod.replace_if_unchanged(promoted,selection,before,"TEST")
            self.assertEqual("sealed\n",selection.read_text())
            mod.replace_if_unchanged(promoted,selection,before,"TEST")
            selection.write_text("other-writer\n")
            with self.assertRaisesRegex(RuntimeError,"CONCURRENT_DRIFT"):
                mod.replace_if_unchanged(promoted,selection,before,"TEST")

    def test_preflight_file_helpers_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); real=d/"real"; real.write_text("x"); link=d/"link"; link.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError,"FILE_INVALID"): mod.regular_file(link,"TEST")
            exe=d/"exe"; exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
            self.assertEqual(exe,mod.regular_file(exe,"TEST",True))
if __name__=="__main__": unittest.main()
