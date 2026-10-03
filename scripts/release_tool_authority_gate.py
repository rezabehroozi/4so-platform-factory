#!/usr/bin/env python3
"""Fail closed when exact-release or C7W execution authority drifts across entrypoints."""
from __future__ import annotations

import argparse
import ast
import importlib.util
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
        if isinstance(node,ast.Assign): targets=node.targets; value=node.value
        elif isinstance(node,ast.AnnAssign): targets=[node.target]; value=node.value
        else: continue
        if any(isinstance(target,ast.Name) and target.id==name for target in targets):
            try: return ast.literal_eval(value)
            except (ValueError,TypeError): return None
    return None


def direct_git_calls_without_env(source:str)->list[int]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return [0]
    missing=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or not node.args:
            continue
        func=node.func
        command=node.args[0]
        if not (
            isinstance(func,ast.Attribute)
            and func.attr=="run"
            and isinstance(func.value,ast.Name)
            and func.value.id=="subprocess"
            and isinstance(command,ast.List)
            and command.elts
            and isinstance(command.elts[0],ast.Constant)
            and command.elts[0].value=="git"
        ):
            continue
        if not any(keyword.arg=="env" for keyword in node.keywords):
            missing.append(getattr(node,"lineno",0))
    return missing


def function_call_lines(source:str,function_name:str)->dict[str,int]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return {}
    fn=next((node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==function_name),None)
    if fn is None:
        return {}
    calls:dict[str,int]={}
    for node in ast.walk(fn):
        if not isinstance(node,ast.Call):
            continue
        name=""
        if isinstance(node.func,ast.Name):
            name=node.func.id
        elif isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            name=f"{node.func.value.id}.{node.func.attr}"
        if name:
            calls[name]=min(calls.get(name,node.lineno),node.lineno)
    return calls


def ordered_calls(calls:dict[str,int],names:tuple[str,...])->bool:
    if any(name not in calls for name in names):
        return False
    return all(calls[left]<calls[right] for left,right in zip(names,names[1:]))


def c7w_execution_errors(root:Path)->list[tuple[str,str]]:
    gate=root/"scripts/c7w_execution_authority_gate.py"
    if gate.is_symlink() or not gate.is_file():
        return [("C7W_EXECUTION_AUTHORITY_GATE_MISSING","scripts/c7w_execution_authority_gate.py")]
    spec=importlib.util.spec_from_file_location("c7w_execution_authority_gate_release",gate)
    if spec is None or spec.loader is None:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","module spec unavailable")]
    module=importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID",str(exc))]
    validate=getattr(module,"validate",None)
    if not callable(validate):
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","validate() missing")]
    try:
        rows=validate(root)
    except Exception as exc:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID",str(exc))]
    return list(rows) if isinstance(rows,list) else [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","validate() result invalid")]


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve(); errors:list[tuple[str,str]]=[]
    errors.extend(c7w_execution_errors(root))
    builder=read_required(root,"scripts/build_release_binaries.py",errors)
    verifier=read_required(root,"scripts/verify_release_build_toolchain.py",errors)
    packager=read_required(root,"scripts/build_release.py",errors)
    release_verifier=read_required(root,"scripts/verify_release.py",errors)
    exact_packager=read_required(root,"scripts/package_release_exact.py",errors)
    sealer=read_required(root,"scripts/seal_final_exact_release.py",errors)
    admission=read_required(root,"scripts/final_exact_release_admission.py",errors)
    stable_snapshot=read_required(root,"scripts/c9_stable_snapshot.py",errors)
    preflight=read_required(root,"scripts/c9_preflight.py",errors)
    makefile=read_required(root,"Makefile",errors)

    git_authority_sources=(
        ("scripts/build_release_binaries.py",builder),
        ("scripts/package_release_exact.py",exact_packager),
        ("scripts/seal_final_exact_release.py",sealer),
        ("scripts/final_exact_release_admission.py",admission),
        ("scripts/c9_stable_snapshot.py",stable_snapshot),
    )
    for rel,text in git_authority_sources:
        missing_env=direct_git_calls_without_env(text)
        if missing_env:
            errors.append(("RELEASE_GIT_ENVIRONMENT_AUTHORITY_INVALID",f"{rel}:lines={','.join(str(x) for x in missing_env)}"))

    builder_markers=(
        'AUTHORITY="NATIVE_RELEASE_BINARY_BUILD_AUTHORITY_V1"',"release_build_environment","require_go_binary_identity",
        "require_cgo_toolchain_identity","require_release_build_host","normalized_machine",'env["GOPROXY"]="off"',
        'env["GOSUMDB"]="off"','env["GOWORK"]="off"','env["GOENV"]="off"','env["PYTHONDONTWRITEBYTECODE"]="1"',
        'env["PYTHONNOUSERSITE"]="1"','"PYTHONHOME","PYTHONPATH","PYTHONSTARTUP","PYTHONINSPECT"',
    )
    missing=[marker for marker in builder_markers if marker not in builder]
    if missing: errors.append(("RELEASE_BINARY_BUILDER_ENVIRONMENT_INVALID",",".join(missing)))

    builder_targets=literal_assignment(builder,"TARGETS"); packager_binaries=literal_assignment(packager,"BINARIES"); verifier_binaries=literal_assignment(release_verifier,"RELEASE_BINARIES")
    if builder_targets!=EXPECTED_BUILD_TARGETS: errors.append(("RELEASE_BINARY_TARGET_SET_INVALID",str(builder_targets)))
    if packager_binaries!=EXPECTED_RELEASE_BINARIES: errors.append(("RELEASE_PACKAGER_BINARY_SET_INVALID",str(packager_binaries)))
    if verifier_binaries!=EXPECTED_RELEASE_BINARIES: errors.append(("RELEASE_VERIFIER_BINARY_SET_INVALID",str(verifier_binaries)))

    verifier_markers=("verification_environment","release_binary_builder.release_build_environment()","current_go(env)","validate_active_cgo(lock,env)")
    missing=[marker for marker in verifier_markers if marker not in verifier]
    if missing: errors.append(("RELEASE_TOOLCHAIN_VERIFIER_ENVIRONMENT_INVALID",",".join(missing)))

    verifier_line='GO="$(GO)" $(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted'
    builder_line='$(PYTHON) scripts/build_release_binaries.py --root . --go "$(GO)"'
    if verifier_line not in makefile or builder_line not in makefile:
        errors.append(("RELEASE_TOOLCHAIN_GO_SELECTOR_DRIFT","Makefile build-release must verify and build the same $(GO) selector"))

    packager_markers=('AUTHORITY="EXACT_RELEASE_PACKAGER_EXECUTION_V1"',"release_binary_builder.release_build_environment()","release_binary_builder.require_go_binary_identity","release_binary_builder.require_cgo_toolchain_identity",'env["GO"]=go_binary','[sys.executable,"scripts/build_release.py","."]')
    missing=[marker for marker in packager_markers if marker not in exact_packager]
    if missing: errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID",",".join(missing)))
    canonical_packager_line='GO="$(GO)" $(PYTHON) scripts/package_release_exact.py --root .'
    if canonical_packager_line not in makefile: errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID","Makefile release bypasses exact packager owner"))
    if '"scripts/package_release_exact.py"' not in sealer or '[sys.executable, "scripts/build_release.py", "."]' in sealer:
        errors.append(("FINAL_EXACT_RELEASE_PACKAGER_OWNER_INVALID","C9 must route packaging only through scripts/package_release_exact.py"))

    host_markers=("normalized_machine","FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED",'"observedArchitecture"','"requiredArchitecture"')
    if any(marker not in sealer for marker in host_markers) or "require_release_build_host" not in builder:
        errors.append(("RELEASE_HOST_ARCHITECTURE_GUARD_INVALID","exact release must fail closed outside linux/amd64 in both builder and C9"))

    execute_calls=function_call_lines(sealer,"execute")
    resume_calls=function_call_lines(sealer,"resume_existing_evidence")
    if not ordered_calls(execute_calls,("git_source","exact_source_admission","require_exact_release_host","require_exact_release_environment")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","fresh seal must admit exact source before host/environment work"))
    if not ordered_calls(resume_calls,("exact_source_admission","require_exact_release_host","require_exact_release_environment")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","resume must re-admit sealed source before host/environment work"))
    if not ordered_calls(execute_calls,("admission.verify","safe_toolchain_archive","stage_toolchain_archive","extract_toolchain")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","detached exact-source admission must precede toolchain extraction"))

    preflight_markers=(
        'AUTHORITY = "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_V1"',
        "sealer.exact_release_environment_preflight",
        "sealer.exact_source_admission",
        "validate_existing_evidence",
        '"INSPECT_C9_EXISTING_EVIDENCE"',
        '"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_FIELDS_INVALID"',
        '"MCP_EXTERNAL_INTEROP_PENDING"',
        '"RUN_C7W_PREFLIGHT"',
        '"RUN_C9_ON_EXACT_LINUX_HOST"',
        '"PROVIDE_C9_ENVIRONMENT_INPUTS"',
        '"RUN_C9_SEAL"',
        '"admissionReady"',
        '"requiredInputs"',
        '"physicalCertified"',
    )
    missing=[marker for marker in preflight_markers if marker not in preflight]
    if missing: errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_INVALID",",".join(missing)))
    if 'c9-preflight:' not in makefile or 'scripts/c9_preflight.py --root .' not in makefile:
        errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_ENTRYPOINT_INVALID","Makefile c9-preflight must use scripts/c9_preflight.py"))
    return errors


def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--root",type=Path,default=Path(".")); args=parser.parse_args(); errors=validate(args.root)
    if errors:
        for code,detail in errors: print(f"{code} {detail}")
        return 1
    print(f"RELEASE_TOOL_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0


if __name__=="__main__": raise SystemExit(main())