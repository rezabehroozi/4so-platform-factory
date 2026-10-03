#!/usr/bin/env python3
"""Fail closed when exact-release build/packaging authority drifts across entrypoints."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

AUTHORITY="RELEASE_TOOL_AUTHORITY_GATE_V1"
EXPECTED_RELEASE_BINARIES=(
    "platform-api","platformctl","platform-installer","platform-agent",
    "platform-probe","virtual-cluster-renderer","openchoreo-runtime","dapr-runtime",
)
EXPECTED_BUILD_TARGETS=(
    ("platform-api","./cmd/platform-api","1"),
    ("platformctl","./cmd/platformctl","0"),
    ("platform-installer","./cmd/platform-installer","0"),
    ("platform-agent","./cmd/platform-agent","0"),
    ("platform-probe","./cmd/platform-probe","0"),
    ("virtual-cluster-renderer","./cmd/virtual-cluster-renderer","0"),
    ("openchoreo-runtime","./cmd/openchoreo-runtime","0"),
    ("dapr-runtime","./cmd/dapr-runtime","0"),
)


def read_required(root:Path,rel:str,errors:list[tuple[str,str]])->str:
    path=root/rel
    if path.is_symlink() or not path.is_file():
        errors.append(("RELEASE_TOOL_AUTHORITY_FILE_MISSING",rel))
        return ""
    try:
        return path.read_text(encoding="utf-8",errors="strict")
    except (OSError,UnicodeDecodeError) as exc:
        errors.append(("RELEASE_TOOL_AUTHORITY_FILE_INVALID",f"{rel}:{exc}"))
        return ""


def literal_assignment(source:str,name:str):
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return None
    for node in tree.body:
        if isinstance(node,ast.Assign):
            targets=node.targets; value=node.value
        elif isinstance(node,ast.AnnAssign):
            targets=[node.target]; value=node.value
        else:
            continue
        if any(isinstance(target,ast.Name) and target.id==name for target in targets):
            try:
                return ast.literal_eval(value)
            except (ValueError,TypeError):
                return None
    return None


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve()
    errors:list[tuple[str,str]]=[]
    builder=read_required(root,"scripts/build_release_binaries.py",errors)
    verifier=read_required(root,"scripts/verify_release_build_toolchain.py",errors)
    packager=read_required(root,"scripts/build_release.py",errors)
    release_verifier=read_required(root,"scripts/verify_release.py",errors)
    exact_packager=read_required(root,"scripts/package_release_exact.py",errors)
    sealer=read_required(root,"scripts/seal_final_exact_release.py",errors)
    preflight=read_required(root,"scripts/c9_preflight.py",errors)
    makefile=read_required(root,"Makefile",errors)

    builder_markers=(
        'AUTHORITY="NATIVE_RELEASE_BINARY_BUILD_AUTHORITY_V1"',
        "release_build_environment",
        "require_go_binary_identity",
        "require_cgo_toolchain_identity",
        "require_release_build_host",
        "normalized_machine",
        'env["GOPROXY"]="off"',
        'env["GOSUMDB"]="off"',
        'env["GOWORK"]="off"',
        'env["GOENV"]="off"',
        'env["PYTHONDONTWRITEBYTECODE"]="1"',
        'env["PYTHONNOUSERSITE"]="1"',
        '"PYTHONHOME","PYTHONPATH","PYTHONSTARTUP","PYTHONINSPECT"',
    )
    missing=[marker for marker in builder_markers if marker not in builder]
    if missing:
        errors.append(("RELEASE_BINARY_BUILDER_ENVIRONMENT_INVALID",",".join(missing)))

    builder_targets=literal_assignment(builder,"TARGETS")
    packager_binaries=literal_assignment(packager,"BINARIES")
    verifier_binaries=literal_assignment(release_verifier,"RELEASE_BINARIES")
    if builder_targets!=EXPECTED_BUILD_TARGETS:
        errors.append(("RELEASE_BINARY_TARGET_SET_INVALID",str(builder_targets)))
    if packager_binaries!=EXPECTED_RELEASE_BINARIES:
        errors.append(("RELEASE_PACKAGER_BINARY_SET_INVALID",str(packager_binaries)))
    if verifier_binaries!=EXPECTED_RELEASE_BINARIES:
        errors.append(("RELEASE_VERIFIER_BINARY_SET_INVALID",str(verifier_binaries)))

    verifier_markers=(
        "verification_environment",
        "release_binary_builder.release_build_environment()",
        "current_go(env)",
        "validate_active_cgo(lock,env)",
    )
    missing=[marker for marker in verifier_markers if marker not in verifier]
    if missing:
        errors.append(("RELEASE_TOOLCHAIN_VERIFIER_ENVIRONMENT_INVALID",",".join(missing)))

    verifier_line='GO="$(GO)" $(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted'
    builder_line='$(PYTHON) scripts/build_release_binaries.py --root . --go "$(GO)"'
    if verifier_line not in makefile or builder_line not in makefile:
        errors.append(("RELEASE_TOOLCHAIN_GO_SELECTOR_DRIFT","Makefile build-release must verify and build the same $(GO) selector"))

    packager_markers=(
        'AUTHORITY="EXACT_RELEASE_PACKAGER_EXECUTION_V1"',
        "release_binary_builder.release_build_environment()",
        "release_binary_builder.require_go_binary_identity",
        "release_binary_builder.require_cgo_toolchain_identity",
        'env["GO"]=go_binary',
        '[sys.executable,"scripts/build_release.py","."]',
    )
    missing=[marker for marker in packager_markers if marker not in exact_packager]
    if missing:
        errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID",",".join(missing)))

    canonical_packager_line='GO="$(GO)" $(PYTHON) scripts/package_release_exact.py --root .'
    if canonical_packager_line not in makefile:
        errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID","Makefile release bypasses exact packager owner"))

    if '"scripts/package_release_exact.py"' not in sealer or '[sys.executable, "scripts/build_release.py", "."]' in sealer:
        errors.append(("FINAL_EXACT_RELEASE_PACKAGER_OWNER_INVALID","C9 must route packaging only through scripts/package_release_exact.py"))

    host_markers=(
        "normalized_machine",
        "FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED",
        '"observedArchitecture"',
        '"requiredArchitecture"',
    )
    if any(marker not in sealer for marker in host_markers) or "require_release_build_host" not in builder:
        errors.append(("RELEASE_HOST_ARCHITECTURE_GUARD_INVALID","exact release must fail closed outside linux/amd64 in both builder and C9"))

    preflight_markers=(
        'AUTHORITY = "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_V1"',
        "sealer.exact_release_environment_preflight",
        "validate_existing_evidence",
        '"INSPECT_C9_EXISTING_EVIDENCE"',
        '"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_FIELDS_INVALID"',
        '"RUN_C9_ON_EXACT_LINUX_HOST"',
        '"PROVIDE_C9_ENVIRONMENT_INPUTS"',
        '"RUN_C9_SEAL"',
        '"requiredInputs"',
        '"physicalCertified"',
    )
    missing=[marker for marker in preflight_markers if marker not in preflight]
    if missing:
        errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_INVALID",",".join(missing)))
    if 'c9-preflight:' not in makefile or 'scripts/c9_preflight.py --root .' not in makefile:
        errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_ENTRYPOINT_INVALID","Makefile c9-preflight must use scripts/c9_preflight.py"))

    return errors


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("."))
    args=parser.parse_args()
    errors=validate(args.root)
    if errors:
        for code,detail in errors:
            print(f"{code} {detail}")
        return 1
    print(f"RELEASE_TOOL_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
