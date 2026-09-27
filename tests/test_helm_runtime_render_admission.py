import copy,importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("hra",ROOT/"scripts"/"helm_runtime_render_admission.py")
mod=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(mod)

class HelmRuntimeRenderAdmissionTests(unittest.TestCase):
    def test_verify_rejects_binding_drift_and_scope_inflation(self):
        for component,release in (("argocd","10.2.3"),("external-secrets","2.8.0")):
            lock_path,artifact,lock=mod.load_lock(component,release)
            g=lock["generation"]
            evidence={"authority":mod.AUTHORITY,"component":component,"release":release,
                "sourceLockSha256":mod.digest(lock_path),"artifactSha256":mod.digest(artifact),
                "helmVersion":g["toolVersion"],"releaseName":g["releaseName"],
                "namespace":g["namespace"],"includeCRDs":True,
                "kubernetesRenderDigests":{v:"sha256:"+"1"*64 for v in g["kubernetesVersions"]},
                "networkSourceFetchRequired":False,"runtimeCertified":False,"physicalCertified":False}
            self.assertEqual(set(g["kubernetesVersions"]),set(mod.verify(component,release,evidence)))
            bad=copy.deepcopy(evidence);bad["sourceLockSha256"]="sha256:"+"0"*64
            with self.assertRaisesRegex(RuntimeError,"SOURCE_BINDING"): mod.verify(component,release,bad)
            bad=copy.deepcopy(evidence);bad["runtimeCertified"]=True
            with self.assertRaisesRegex(RuntimeError,"SCOPE_INFLATED"): mod.verify(component,release,bad)

    def test_existing_source_digest_matrix_remains_primary_authority(self):
        _,_,lock=mod.load_lock("argocd","10.2.2")
        self.assertEqual({"1.34.0","1.35.0"},set(lock["generation"]["kubernetesRenderDigests"]))
if __name__=="__main__":
    unittest.main()
