import hashlib,importlib.util,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mos",ROOT/"scripts"/"seal_managed_okd_machine_os.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ManagedOKDMachineOSSealTests(unittest.TestCase):
    def lock(self):
        return {"authority":mod.LOCK_AUTHORITY,"distribution":"okd-scos","machineOS":{"name":"CentOS Stream CoreOS","version":"9.0.20250827-0"},"artifacts":[{"role":"openshift-install","sha256":"a"*64}],"pendingAuthorities":[{"id":"fcos"},{"id":"agent-iso-workspace"},{"id":"oc-mirror-v2"}],"managedInstallContentReady":False,"runtimeCertified":False,"physicalCertified":False}
    def stream(self,digest):
        return {"architectures":{"x86_64":{"artifacts":{"metal":{"release":"9.0.20250827-0","formats":{"4k.raw.xz":{"disk":{"location":"https://example.test/scos-4k.raw.xz","sha256":"b"*64}},"raw.xz":{"disk":{"location":"https://example.test/scos.raw.xz","sha256":digest}}}}}}}}
    def test_seal_exact_machine_os_bytes(self):
        payload=b"exact-machine-os"; digest=hashlib.sha256(payload).hexdigest()
        found=mod.discover(self.lock(),self.stream(digest))
        self.assertEqual("raw.xz",found["format"])
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"machine-os"; p.write_bytes(payload)
            out=mod.seal(self.lock(),found,p)
        self.assertTrue(out["machineOSArtifact"]["byteVerified"])
        self.assertEqual({"agent-iso-workspace","oc-mirror-v2"},{r["id"] for r in out["pendingAuthorities"]})
        self.assertFalse(out["managedInstallContentReady"])
        self.assertFalse(out["physicalCertified"])
    def test_release_and_digest_drift_fail_closed(self):
        digest=hashlib.sha256(b"expected").hexdigest()
        bad=self.stream(digest); bad["architectures"]["x86_64"]["artifacts"]["metal"]["release"]="wrong"
        with self.assertRaisesRegex(RuntimeError,"RELEASE_MISMATCH"): mod.discover(self.lock(),bad)
        found=mod.discover(self.lock(),self.stream(digest))
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"machine-os"; p.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError,"DIGEST_MISMATCH"): mod.seal(self.lock(),found,p)

if __name__=="__main__": unittest.main()
