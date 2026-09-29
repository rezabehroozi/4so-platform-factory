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
    def test_preflight_file_helpers_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); real=d/"real"; real.write_text("x"); link=d/"link"; link.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError,"FILE_INVALID"): mod.regular_file(link,"TEST")
            exe=d/"exe"; exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
            self.assertEqual(exe,mod.regular_file(exe,"TEST",True))
if __name__=="__main__": unittest.main()
