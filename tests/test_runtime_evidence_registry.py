import copy,importlib.util,json,tempfile,unittest,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("rer",ROOT/"scripts/runtime_evidence_registry.py")
mod=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(mod)
class RuntimeEvidenceRegistryTests(unittest.TestCase):
    def test_canonical_evidence_is_claim_scoped(self):
        out=mod.verify_all(ROOT)
        self.assertTrue(out["ocMirror"]["transportRealismPass"])
        self.assertFalse(out["ocMirror"]["fullDisconnectedOKDInstallCertified"])
        reg=out["upgradeRegistry"]
        self.assertEqual(2,reg["summary"]["componentsWithAnyRuntimeEvidence"])
        self.assertEqual(1,reg["summary"]["fullyRuntimeUpgradeCertifiedComponents"])
        gateway=next(r for r in reg["components"] if r["component"]=="gateway-api")
        self.assertEqual("partial-runtime-evidence",gateway["status"])
        self.assertEqual([{"fromRelease":"1.5.0","toRelease":"1.5.1"}],gateway["pendingEdges"])
    def copy_files(self):
        td=tempfile.TemporaryDirectory();dst=Path(td.name)
        for rel in ("lab/oc-mirror-disconnected-transport-evidence.json","lab/managed-okd-oc-mirror-source-lock.json","lab/management-workload-external-image-receipt.json","catalog/component-runtime-upgrade-evidence.json","catalog/component-runtime-upgrade-matrix.json","lab/gateway-api-upgrade-runtime-matrix-evidence.json","lab/snapshot-controller-upgrade-runtime-matrix-evidence.json"):
            p=dst/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,p)
        return td,dst
    def test_oc_mirror_scope_inflation_rejected(self):
        td,dst=self.copy_files()
        try:
            p=dst/"lab/oc-mirror-disconnected-transport-evidence.json";d=json.loads(p.read_text());d["runtimeCertified"]=True;p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"SCOPE_INFLATED"):mod.verify_oc_mirror(dst)
        finally:td.cleanup()
    def test_oc_mirror_binary_drift_rejected(self):
        td,dst=self.copy_files()
        try:
            p=dst/"lab/oc-mirror-disconnected-transport-evidence.json";d=json.loads(p.read_text());d["ocMirrorBinarySha256"]="sha256:"+"0"*64;p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"BINARY_BINDING"):mod.verify_oc_mirror(dst)
        finally:td.cleanup()
    def test_upgrade_registry_cannot_promote_one_edge_to_full_component_certification(self):
        td,dst=self.copy_files()
        try:
            p=dst/"catalog/component-runtime-upgrade-evidence.json";d=json.loads(p.read_text());g=next(r for r in d["components"] if r["component"]=="gateway-api");g["runtimeUpgradeCertified"]=True;p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"CERTIFICATION_SCOPE"):mod.verify_upgrade_registry(dst)
        finally:td.cleanup()
    def test_upgrade_registry_rejects_unexecuted_edge_fabrication(self):
        td,dst=self.copy_files()
        try:
            p=dst/"catalog/component-runtime-upgrade-evidence.json";d=json.loads(p.read_text());a=next(r for r in d["components"] if r["component"]=="alloy");a["executedEdges"]=[{"fromRelease":"1.10.1","toRelease":"1.11.0"}];a["pendingEdges"]=[];a["status"]="runtime-evidence-complete";a["runtimeUpgradeCertified"]=True;p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"UNSUPPORTED_RUNTIME_UPGRADE_EVIDENCE_CLAIM"):mod.verify_upgrade_registry(dst)
        finally:td.cleanup()
if __name__=="__main__":unittest.main()
