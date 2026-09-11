#!/usr/bin/env python3
import json, re, sys
from pathlib import Path

AUTHORITY = "RUNTIME_DEPENDENCY_TRANSITION_V1"
EXACT = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_GATEWAY_ASSETS = {
    "standard-install.yaml": (1170953, "24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"),
    "experimental-install.yaml": (1402117, "d7fa77650e4ef28fca0411536fcb5e237deb4d50301cfded3be49d9a1b7bbd02"),
}
EXPECTED_ORDER = [
    "acquire-and-verify-gateway-api-1.6.1",
    "acquire-and-verify-kgateway-2.4.1",
    "acquire-and-verify-cilium-1.20.1",
    "certify-gateway-api-upgrade-1.5.1-to-1.6.1",
    "certify-kgateway-2.4.1-on-gateway-api-1.6.1",
    "certify-cilium-1.20.1-on-gateway-api-1.6.1",
]

def load_json(path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"RUNTIME_DEPENDENCY_TRANSITION_PATH_INVALID {path}")
    return json.loads(path.read_text())

def comp(root: Path, name: str):
    return load_json(root / "catalog" / "components" / f"{name}.json")["spec"]

def validate(root: Path):
    doc = load_json(root / "catalog" / "runtime-dependency-transition.json")
    if doc.get("apiVersion") != "platform.4so.io/v1alpha1" or doc.get("kind") != "RuntimeDependencyTransition":
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_TYPE_INVALID")
    spec = doc.get("spec") or {}
    if spec.get("authority") != AUTHORITY:
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_AUTHORITY_INVALID")
    if spec.get("policy") != {
        "sourceAcquisitionIndependentOfRuntimeSuitability": True,
        "mutationBeforeSourceResolution": False,
        "runtimeCertificationRequired": True,
        "physicalPassInference": False,
    }:
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_POLICY_INVALID")
    admission = load_json(root / "catalog" / "upstream-admission.json")
    rows = {r["component"]: r for r in admission["spec"]["components"]}
    gateway, kgateway, cilium = comp(root,"gateway-api"), comp(root,"kgateway"), comp(root,"cilium")
    ga = spec.get("gatewayApi") or {}
    if ga.get("currentRelease") != gateway.get("release") or bool(ga.get("currentSourceResolved")) != bool(gateway.get("source",{}).get("resolved")):
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_CURRENT_DRIFT")
    if ga.get("targetRelease") != "1.6.1" or not EXACT.fullmatch(str(ga.get("targetRelease") or "")):
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_TARGET_INVALID")
    assets = ga.get("assets") or []
    names = {a.get("name") for a in assets}
    if names != {"standard-install.yaml","experimental-install.yaml"}:
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_ASSET_SET_INVALID")
    for a in assets:
        expected = EXPECTED_GATEWAY_ASSETS.get(a.get("name"))
        if not str(a.get("url") or "").startswith(f"https://github.com/kubernetes-sigs/gateway-api/releases/download/v{ga['targetRelease']}/") or not expected or (int(a.get("size") or 0), str(a.get("sha256") or "")) != expected or not SHA.fullmatch(str(a.get("sha256") or "")):
            raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_ASSET_INVALID")
    kg = spec.get("kgateway") or {}
    kr = rows.get("kgateway") or {}
    if kg.get("targetRelease") != kgateway.get("release") or kr.get("selectedVersion") != kg.get("targetRelease") or kr.get("status") != "ready-for-acquisition" or kr.get("runtimeStatus") != "eligible-after-source-resolution":
        raise RuntimeError("RUNTIME_DEPENDENCY_KGATEWAY_DRIFT")
    if kg.get("gatewayApiCompatibility") != "1.4-1.6":
        raise RuntimeError("RUNTIME_DEPENDENCY_KGATEWAY_COMPATIBILITY_INVALID")
    ci = spec.get("cilium") or {}
    cr = rows.get("cilium") or {}
    if ci.get("targetRelease") != cilium.get("release") or cr.get("selectedVersion") != ci.get("targetRelease") or cr.get("status") != "ready-for-acquisition":
        raise RuntimeError("RUNTIME_DEPENDENCY_CILIUM_DRIFT")
    if ci.get("requiredGatewayApiRelease") != ga.get("targetRelease") or cr.get("runtimeStatus") != "dependency-transition-required" or ci.get("runtimeStatus") != "dependency-transition-required":
        raise RuntimeError("RUNTIME_DEPENDENCY_CILIUM_RUNTIME_STATUS_INVALID")
    if spec.get("ordering") != EXPECTED_ORDER:
        raise RuntimeError("RUNTIME_DEPENDENCY_ORDER_INVALID")
    if spec.get("status") != "acquisition-pending":
        raise RuntimeError("RUNTIME_DEPENDENCY_STATUS_INFLATED")
    return {"authority": AUTHORITY, "status": spec["status"], "gatewayTarget":ga["targetRelease"], "kgatewayTarget":kg["targetRelease"], "ciliumTarget":ci["targetRelease"]}

def main():
    root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[1]
    try:
        out=validate(root)
    except Exception as exc:
        print(str(exc), file=sys.stderr); return 3
    print(f"PASS runtime-dependency-transition authority={out['authority']} status={out['status']} gateway={out['gatewayTarget']} kgateway={out['kgatewayTarget']} cilium={out['ciliumTarget']}")
    return 0
if __name__ == '__main__': raise SystemExit(main())
