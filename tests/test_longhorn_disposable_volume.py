import json
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import longhorn_disposable_volume as LV


def objects(*, disposable=True, operation="storage-smoke-1", phase="Released", state="detached"):
    labels = {
        LV.OWNER_LABEL: LV.OWNER,
        LV.DISPOSABLE_LABEL: "true" if disposable else "false",
        LV.OPERATION_LABEL: operation,
    }
    pvc = {
        "metadata": {"name": "smoke", "namespace": "storage-smoke", "uid": "pvc-uid-1", "labels": labels},
        "spec": {"storageClassName": "replicated-rwx", "volumeName": "pv-smoke"},
    }
    pv = {
        "metadata": {"name": "pv-smoke", "uid": "pv-uid-1"},
        "spec": {
            "storageClassName": "replicated-rwx",
            "persistentVolumeReclaimPolicy": "Retain",
            "claimRef": {"name": "smoke", "namespace": "storage-smoke", "uid": "pvc-uid-1"},
            "csi": {"driver": LV.LONGHORN_DRIVER, "volumeHandle": "lh-volume-1"},
        },
        "status": {"phase": phase},
    }
    volume = {"metadata": {"name": "lh-volume-1", "uid": "lh-uid-1"}, "status": {"state": state}}
    return pvc, pv, volume


class LonghornDisposableVolumeTest(unittest.TestCase):
    def test_binding_evidence_records_exact_identity_chain(self):
        pvc, pv, volume = objects()
        evidence = LV.validate_smoke_binding(pvc, pv, volume, "storage-smoke-1")
        self.assertEqual(evidence["authority"], LV.AUTHORITY)
        self.assertEqual(evidence["pvc"]["uid"], "pvc-uid-1")
        self.assertEqual(evidence["pv"]["uid"], "pv-uid-1")
        self.assertEqual(evidence["longhornVolume"], {"name": "lh-volume-1", "uid": "lh-uid-1"})
        self.assertTrue(evidence["identityDigest"].startswith("sha256:"))

    def test_unowned_or_non_disposable_pvc_is_rejected(self):
        pvc, pv, volume = objects(disposable=False)
        with self.assertRaisesRegex(LV.ContractError, "OWNERSHIP_MISMATCH"):
            LV.validate_smoke_binding(pvc, pv, volume, "storage-smoke-1")

    def test_cleanup_first_removes_only_exact_owned_pvc(self):
        pvc, pv, volume = objects()
        evidence = LV.validate_smoke_binding(pvc, pv, volume, "storage-smoke-1")
        self.assertEqual(LV.cleanup_plan(evidence, pvc, pv, volume), ["delete-pvc"])
        pvc["metadata"]["uid"] = "replacement-pvc"
        with self.assertRaisesRegex(LV.ContractError, "PVC_IDENTITY_MISMATCH"):
            LV.cleanup_plan(evidence, pvc, pv, volume)

    def test_released_detached_binding_allows_exact_backend_cleanup(self):
        pvc, pv, volume = objects()
        evidence = LV.validate_smoke_binding(pvc, pv, volume, "storage-smoke-1")
        self.assertEqual(LV.cleanup_plan(evidence, None, pv, volume), ["delete-longhorn-volume", "delete-pv"])
        self.assertEqual(LV.cleanup_plan(evidence, None, None, None), [])

    def test_attached_or_nonreleased_storage_fails_closed(self):
        pvc, pv, volume = objects(phase="Bound", state="attached")
        evidence = LV.validate_smoke_binding(pvc, pv, volume, "storage-smoke-1")
        with self.assertRaisesRegex(LV.ContractError, "PV_NOT_RELEASED"):
            LV.cleanup_plan(evidence, None, pv, volume)
        pv["status"]["phase"] = "Released"
        with self.assertRaisesRegex(LV.ContractError, "LONGHORN_NOT_DETACHED"):
            LV.cleanup_plan(evidence, None, pv, volume)

    def test_unknown_historical_volume_cannot_be_adopted_without_evidence(self):
        _, pv, volume = objects()
        fake = {"schemaVersion": 1, "authority": "UNTRUSTED"}
        with self.assertRaisesRegex(LV.ContractError, "EVIDENCE_AUTHORITY_INVALID"):
            LV.cleanup_plan(fake, None, pv, volume)

    def test_manifest_is_explicitly_disposable_and_operation_scoped(self):
        manifest = LV.smoke_manifest("storage-smoke", "smoke-pvc", "replicated-rwx", "storage-smoke-abc")
        for fragment in (
            f"{LV.OWNER_LABEL}: {LV.OWNER}",
            f'{LV.DISPOSABLE_LABEL}: "true"',
            f"{LV.OPERATION_LABEL}: storage-smoke-abc",
            "storageClassName: replicated-rwx",
        ):
            self.assertIn(fragment, manifest)


if __name__ == "__main__":
    unittest.main()
