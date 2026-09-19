#!/usr/bin/env python3
"""Create and clean exact-evidence Longhorn disposable storage probes.

This tool never scans for deletion candidates. Cleanup requires evidence created
for one exact smoke PVC/PV/Longhorn-volume identity chain.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
import uuid

AUTHORITY = "LONGHORN_DISPOSABLE_VOLUME_EVIDENCE_V1"
OWNER = "4so-platform-factory-storage-smoke"
OWNER_LABEL = "platform.4so.io/test-owner"
DISPOSABLE_LABEL = "platform.4so.io/test-disposable"
OPERATION_LABEL = "platform.4so.io/test-operation-id"
LONGHORN_DRIVER = "driver.longhorn.io"


class ContractError(RuntimeError):
    pass


def _metadata(obj: dict) -> dict:
    value = obj.get("metadata")
    return value if isinstance(value, dict) else {}


def _labels(obj: dict) -> dict:
    value = _metadata(obj).get("labels")
    return value if isinstance(value, dict) else {}


def _uid(obj: dict, label: str) -> str:
    value = str(_metadata(obj).get("uid") or "").strip()
    if not value:
        raise ContractError(f"{label}_UID_MISSING")
    return value


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_smoke_binding(pvc: dict, pv: dict, volume: dict, operation_id: str) -> dict:
    labels = _labels(pvc)
    if labels.get(OWNER_LABEL) != OWNER or labels.get(DISPOSABLE_LABEL) != "true" or labels.get(OPERATION_LABEL) != operation_id:
        raise ContractError("DISPOSABLE_PVC_OWNERSHIP_MISMATCH")

    pvc_meta = _metadata(pvc)
    pvc_name = str(pvc_meta.get("name") or "").strip()
    pvc_namespace = str(pvc_meta.get("namespace") or "").strip()
    pvc_uid = _uid(pvc, "PVC")
    pvc_spec = pvc.get("spec") if isinstance(pvc.get("spec"), dict) else {}
    storage_class = str(pvc_spec.get("storageClassName") or "").strip()
    pv_name = str(pvc_spec.get("volumeName") or "").strip()
    if not pvc_name or not pvc_namespace or not storage_class or not pv_name:
        raise ContractError("DISPOSABLE_PVC_BINDING_INCOMPLETE")

    pv_meta = _metadata(pv)
    if str(pv_meta.get("name") or "").strip() != pv_name:
        raise ContractError("DISPOSABLE_PV_NAME_MISMATCH")
    pv_uid = _uid(pv, "PV")
    pv_spec = pv.get("spec") if isinstance(pv.get("spec"), dict) else {}
    claim = pv_spec.get("claimRef") if isinstance(pv_spec.get("claimRef"), dict) else {}
    if (
        str(claim.get("namespace") or "").strip() != pvc_namespace
        or str(claim.get("name") or "").strip() != pvc_name
        or str(claim.get("uid") or "").strip() != pvc_uid
    ):
        raise ContractError("DISPOSABLE_PV_CLAIMREF_MISMATCH")
    if str(pv_spec.get("storageClassName") or "").strip() != storage_class:
        raise ContractError("DISPOSABLE_STORAGECLASS_MISMATCH")
    if str(pv_spec.get("persistentVolumeReclaimPolicy") or "").strip() != "Retain":
        raise ContractError("DISPOSABLE_PV_RECLAIM_POLICY_MISMATCH")
    csi = pv_spec.get("csi") if isinstance(pv_spec.get("csi"), dict) else {}
    if str(csi.get("driver") or "").strip() != LONGHORN_DRIVER:
        raise ContractError("DISPOSABLE_PV_DRIVER_MISMATCH")
    handle = str(csi.get("volumeHandle") or "").strip()
    if not handle:
        raise ContractError("DISPOSABLE_VOLUME_HANDLE_MISSING")

    volume_meta = _metadata(volume)
    if str(volume_meta.get("name") or "").strip() != handle:
        raise ContractError("DISPOSABLE_LONGHORN_NAME_MISMATCH")
    volume_uid = _uid(volume, "LONGHORN_VOLUME")

    identity = "\n".join((operation_id, pvc_uid, pv_uid, volume_uid, handle))
    return {
        "schemaVersion": 1,
        "authority": AUTHORITY,
        "id": "longhorn-disposable-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20],
        "operationId": operation_id,
        "owner": OWNER,
        "pvc": {"namespace": pvc_namespace, "name": pvc_name, "uid": pvc_uid},
        "pv": {"name": pv_name, "uid": pv_uid},
        "longhornVolume": {"name": handle, "uid": volume_uid},
        "storageClass": storage_class,
        "reclaimPolicy": "Retain",
        "driver": LONGHORN_DRIVER,
        "identityDigest": _sha256_text(identity),
        "createdAt": int(time.time()),
    }


def validate_evidence(evidence: dict) -> None:
    if not isinstance(evidence, dict) or evidence.get("schemaVersion") != 1 or evidence.get("authority") != AUTHORITY:
        raise ContractError("DISPOSABLE_EVIDENCE_AUTHORITY_INVALID")
    if evidence.get("owner") != OWNER or evidence.get("driver") != LONGHORN_DRIVER or evidence.get("reclaimPolicy") != "Retain":
        raise ContractError("DISPOSABLE_EVIDENCE_SCOPE_INVALID")
    for key in ("id", "operationId", "storageClass", "identityDigest"):
        if not str(evidence.get(key) or "").strip():
            raise ContractError("DISPOSABLE_EVIDENCE_IDENTITY_INCOMPLETE")
    for key in ("pvc", "pv", "longhornVolume"):
        value = evidence.get(key)
        if not isinstance(value, dict) or not str(value.get("uid") or "").strip() or not str(value.get("name") or "").strip():
            raise ContractError("DISPOSABLE_EVIDENCE_BINDING_INCOMPLETE")


def cleanup_plan(evidence: dict, pvc: dict | None, pv: dict | None, volume: dict | None) -> list[str]:
    validate_evidence(evidence)
    expected_pvc = evidence["pvc"]
    expected_pv = evidence["pv"]
    expected_volume = evidence["longhornVolume"]
    operation_id = evidence["operationId"]

    if pvc is not None:
        if (
            _uid(pvc, "PVC") != expected_pvc["uid"]
            or str(_metadata(pvc).get("namespace") or "").strip() != expected_pvc["namespace"]
            or str(_metadata(pvc).get("name") or "").strip() != expected_pvc["name"]
        ):
            raise ContractError("DISPOSABLE_CLEANUP_PVC_IDENTITY_MISMATCH")
        labels = _labels(pvc)
        if labels.get(OWNER_LABEL) != OWNER or labels.get(DISPOSABLE_LABEL) != "true" or labels.get(OPERATION_LABEL) != operation_id:
            raise ContractError("DISPOSABLE_CLEANUP_PVC_OWNERSHIP_MISMATCH")
        return ["delete-pvc"]

    actions: list[str] = []
    if pv is not None:
        if _uid(pv, "PV") != expected_pv["uid"] or str(_metadata(pv).get("name") or "").strip() != expected_pv["name"]:
            raise ContractError("DISPOSABLE_CLEANUP_PV_IDENTITY_MISMATCH")
        spec = pv.get("spec") if isinstance(pv.get("spec"), dict) else {}
        claim = spec.get("claimRef") if isinstance(spec.get("claimRef"), dict) else {}
        csi = spec.get("csi") if isinstance(spec.get("csi"), dict) else {}
        phase = str((pv.get("status") or {}).get("phase") or "").strip()
        if str(claim.get("uid") or "").strip() != expected_pvc["uid"]:
            raise ContractError("DISPOSABLE_CLEANUP_PV_CLAIMREF_MISMATCH")
        if str(csi.get("driver") or "").strip() != LONGHORN_DRIVER or str(csi.get("volumeHandle") or "").strip() != expected_volume["name"]:
            raise ContractError("DISPOSABLE_CLEANUP_PV_DRIVER_MISMATCH")
        if str(spec.get("persistentVolumeReclaimPolicy") or "").strip() != "Retain" or phase != "Released":
            raise ContractError("DISPOSABLE_CLEANUP_PV_NOT_RELEASED")
        actions.append("delete-pv")

    if volume is not None:
        if _uid(volume, "LONGHORN_VOLUME") != expected_volume["uid"] or str(_metadata(volume).get("name") or "").strip() != expected_volume["name"]:
            raise ContractError("DISPOSABLE_CLEANUP_LONGHORN_IDENTITY_MISMATCH")
        state = str((volume.get("status") or {}).get("state") or "").strip().lower()
        if state != "detached":
            raise ContractError("DISPOSABLE_CLEANUP_LONGHORN_NOT_DETACHED")
        actions.insert(0, "delete-longhorn-volume")
    return actions


def kubectl_json(kubectl: str, kubeconfig: str, args: list[str], *, missing_ok: bool = False) -> dict | None:
    command = [kubectl, "--kubeconfig", kubeconfig, *args, "-o", "json"]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        if missing_ok and ("NotFound" in completed.stderr or "not found" in completed.stderr.lower()):
            return None
        raise ContractError("KUBECTL_FAILED: " + completed.stderr.strip())
    if not completed.stdout.strip():
        return None if missing_ok else {}
    return json.loads(completed.stdout)


def kubectl_run(kubectl: str, kubeconfig: str, args: list[str], *, input_text: str | None = None) -> None:
    completed = subprocess.run([kubectl, "--kubeconfig", kubeconfig, *args], input=input_text, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise ContractError("KUBECTL_FAILED: " + completed.stderr.strip())


def atomic_json(path: Path, document: dict) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(document, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def smoke_manifest(namespace: str, pvc: str, storage_class: str, operation_id: str) -> str:
    for value in (namespace, pvc, storage_class, operation_id):
        if not value or any(ch.isspace() for ch in value):
            raise ContractError("DISPOSABLE_SMOKE_IDENTITY_INVALID")
    return f"""apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    {OWNER_LABEL}: {OWNER}
    {OPERATION_LABEL}: {operation_id}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {pvc}
  namespace: {namespace}
  labels:
    {OWNER_LABEL}: {OWNER}
    {DISPOSABLE_LABEL}: "true"
    {OPERATION_LABEL}: {operation_id}
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: {storage_class}
  resources:
    requests:
      storage: 1Gi
"""


def wait_binding(kubectl: str, kubeconfig: str, namespace: str, pvc_name: str, timeout: int) -> tuple[dict, dict, dict]:
    deadline = time.time() + timeout
    last = "PVC_NOT_BOUND"
    while time.time() < deadline:
        pvc = kubectl_json(kubectl, kubeconfig, ["-n", namespace, "get", "pvc", pvc_name])
        pv_name = str(((pvc or {}).get("spec") or {}).get("volumeName") or "").strip()
        if pv_name:
            pv = kubectl_json(kubectl, kubeconfig, ["get", "pv", pv_name])
            handle = str((((pv or {}).get("spec") or {}).get("csi") or {}).get("volumeHandle") or "").strip()
            if handle:
                volume = kubectl_json(kubectl, kubeconfig, ["-n", "longhorn-system", "get", "volumes.longhorn.io", handle], missing_ok=True)
                if volume is not None:
                    return pvc, pv, volume
            last = "LONGHORN_VOLUME_NOT_OBSERVED"
        time.sleep(2)
    raise ContractError(last)


def command_create(args: argparse.Namespace) -> int:
    operation_id = args.operation_id or ("storage-smoke-" + uuid.uuid4().hex[:16])
    manifest = smoke_manifest(args.namespace, args.pvc, args.storage_class, operation_id)
    kubectl_run(args.kubectl, args.kubeconfig, ["apply", "-f", "-"], input_text=manifest)
    pvc, pv, volume = wait_binding(args.kubectl, args.kubeconfig, args.namespace, args.pvc, args.timeout)
    evidence = validate_smoke_binding(pvc, pv, volume, operation_id)
    atomic_json(Path(args.evidence), evidence)
    print("LONGHORN_DISPOSABLE_VOLUME_EVIDENCE_PASS", evidence["id"])
    return 0


def command_cleanup(args: argparse.Namespace) -> int:
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    validate_evidence(evidence)
    if args.confirm != evidence["id"]:
        raise ContractError("DISPOSABLE_CLEANUP_CONFIRMATION_MISMATCH")

    expected_pvc = evidence["pvc"]
    expected_pv = evidence["pv"]
    expected_volume = evidence["longhornVolume"]
    for _ in range(90):
        pvc = kubectl_json(args.kubectl, args.kubeconfig, ["-n", expected_pvc["namespace"], "get", "pvc", expected_pvc["name"]], missing_ok=True)
        pv = kubectl_json(args.kubectl, args.kubeconfig, ["get", "pv", expected_pv["name"]], missing_ok=True)
        volume = kubectl_json(args.kubectl, args.kubeconfig, ["-n", "longhorn-system", "get", "volumes.longhorn.io", expected_volume["name"]], missing_ok=True)
        actions = cleanup_plan(evidence, pvc, pv, volume)
        if actions == ["delete-pvc"]:
            kubectl_run(args.kubectl, args.kubeconfig, ["-n", expected_pvc["namespace"], "delete", "pvc", expected_pvc["name"], "--wait=true"])
            continue
        if "delete-longhorn-volume" in actions:
            kubectl_run(args.kubectl, args.kubeconfig, ["-n", "longhorn-system", "delete", "volumes.longhorn.io", expected_volume["name"], "--wait=true"])
            continue
        if "delete-pv" in actions:
            kubectl_run(args.kubectl, args.kubeconfig, ["delete", "pv", expected_pv["name"], "--wait=true"])
            continue
        print("LONGHORN_DISPOSABLE_VOLUME_CLEANUP_PASS", evidence["id"])
        return 0
    raise ContractError("DISPOSABLE_CLEANUP_DID_NOT_CONVERGE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kubectl", default="/var/lib/rancher/rke2/bin/kubectl")
    parser.add_argument("--kubeconfig", default="/etc/rancher/rke2/rke2.yaml")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--namespace", default="platform-storage-smoke")
    create.add_argument("--pvc", default="longhorn-retention-smoke")
    create.add_argument("--storage-class", required=True)
    create.add_argument("--operation-id")
    create.add_argument("--evidence", required=True)
    create.add_argument("--timeout", type=int, default=180)
    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--evidence", required=True)
    cleanup.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        return command_create(args) if args.command == "create" else command_cleanup(args)
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())
