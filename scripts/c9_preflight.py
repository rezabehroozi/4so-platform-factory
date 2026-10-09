#!/usr/bin/env python3
"""Machine-actionable C9 environment and admission preflight handoff.

The final exact sealer remains the validation authority. This wrapper translates
source, final-admission and environment blockers into the next executable local
action so agents do not need to interpret free-form errors.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

try:
    import seal_final_exact_release as sealer
except ModuleNotFoundError:
    from scripts import seal_final_exact_release as sealer

AUTHORITY = "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_V1"
FINAL_EVIDENCE_REL = Path("lab/final-exact-release-evidence.json")
C7W_PREFLIGHT_COMMAND = [sys.executable, "scripts/c7w_preflight.py", "--root", "."]
ADMISSION_STATUS_COMMAND = [
    sys.executable,
    "scripts/final_exact_release_admission.py",
    "--root",
    ".",
    "--allow-pending",
]
C9_COMMAND = [
    sys.executable,
    "scripts/seal_final_exact_release.py",
    "--root",
    ".",
    "--out",
    str(FINAL_EVIDENCE_REL),
]
C9_COMMAND_TEMPLATE = [
    "<python>",
    "scripts/seal_final_exact_release.py",
    "--root",
    "<exact-source-checkout-root>",
    "--out",
    str(FINAL_EVIDENCE_REL),
]
TOOLCHAIN_ARCHIVE_BLOCKERS = {
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISSING",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISMATCH",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_INVALID",
}
TOOLCHAIN_SOURCE_BLOCKERS = {
    "FINAL_EXACT_RELEASE_TOOLCHAIN_AUTHORITY_INVALID",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_NOT_ADMITTED",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_PATH_INVALID",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID",
}


def bind_execution_context(root:Path,result:dict)->dict:
    root=Path(root).resolve()
    out=dict(result)
    if out.get("nextCommand"):
        out["workingDirectory"]=str(root)
    if out.get("nextCommandTemplate"):
        if out.get("nextActionCode")=="RUN_C9_ON_EXACT_LINUX_HOST":
            out["requiredWorkingDirectory"]="<exact-source-checkout-root>"
        else:
            out["workingDirectory"]=str(root)
    return out


def load_existing_evidence_snapshot(path:Path)->dict:
    absolute=Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID")
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    try:
        fd=os.open(absolute,flags)
    except OSError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID") from exc
    try:
        before=os.fstat(fd)
        try:
            named=os.stat(absolute,follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or not os.path.samestat(before,named)
            or before.st_size<=0
            or before.st_size>1024*1024
        ):
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID")

        def read_once()->bytes:
            chunks=[]; total=0
            while True:
                chunk=os.read(fd,min(1024*1024,1024*1024+1-total))
                if not chunk:
                    break
                chunks.append(chunk); total+=len(chunk)
                if total>1024*1024:
                    raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID")
            return b"".join(chunks)

        first=read_once()
        middle=os.fstat(fd)
        os.lseek(fd,0,os.SEEK_SET)
        second=read_once()
        after=os.fstat(fd)
        try:
            named_after=os.stat(absolute,follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_CHANGED_DURING_READ") from exc
        stable_identity=os.path.samestat(before,middle) and os.path.samestat(before,after) and os.path.samestat(before,named_after)
        stable_meta=(before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(middle.st_size,middle.st_mtime_ns,middle.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        if not stat.S_ISREG(named_after.st_mode) or not stable_identity or not stable_meta or first!=second or len(first)!=before.st_size:
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_CHANGED_DURING_READ")
        try:
            value=json.loads(first.decode("utf-8"))
        except (UnicodeDecodeError,json.JSONDecodeError) as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID") from exc
        return value
    finally:
        os.close(fd)


def enrich(result: dict) -> dict:
    if not isinstance(result, dict):
        raise RuntimeError("FINAL_EXACT_RELEASE_PREFLIGHT_RESULT_INVALID")
    out = dict(result)
    blockers = [str(x) for x in out.get("blockers") or []]
    blocker_set = set(blockers)
    required_inputs: list[str] = []
    if any(code.startswith("UI_BROWSER_AUTHORITY_") for code in blockers):
        required_inputs.append(sealer.browser_authority.ENV_AUTHORITY)
    if blocker_set & TOOLCHAIN_ARCHIVE_BLOCKERS:
        required_inputs.append("vendor/toolchains/<admitted-go-archive>")
    missing_host_tools = [str(x) for x in out.get("missingHostTools") or []]
    out.update(
        {
            "handoffAuthority": AUTHORITY,
            "requiredInputs": required_inputs,
            "requiredHostTools": missing_host_tools,
            "nextCommand": [],
            "nextCommandTemplate": [],
        }
    )
    if blocker_set & TOOLCHAIN_SOURCE_BLOCKERS or any(code.startswith("FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_SOURCE_") for code in blockers):
        out.update(
            {
                "nextActionCode": "INSPECT_C9_SOURCE_AUTHORITY",
                "nextCommand": ["git", "status", "--short", "--", "lab/release-build-toolchain-lock.json"],
                "requiredInputs": [],
                "detail": "the tracked C9 toolchain authority/lock is invalid; inspect source authority rather than replacing environment inputs",
            }
        )
    elif "FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED" in blocker_set:
        out.update(
            {
                "nextActionCode": "RUN_C9_ON_EXACT_LINUX_HOST",
                "nextCommandTemplate": list(C9_COMMAND_TEMPLATE),
                "detail": "run the exact committed source on a linux/amd64 host with the admitted offline toolchain and browser authority",
            }
        )
    elif blockers:
        out.update(
            {
                "nextActionCode": "PROVIDE_C9_ENVIRONMENT_INPUTS",
                "detail": "satisfy only the reported local tool/input blockers, then rerun c9-preflight",
            }
        )
    else:
        out.update(
            {
                "nextActionCode": "RUN_C9_SEAL",
                "nextCommand": list(C9_COMMAND),
                "detail": "C9 final admission and environment are ready for the local exact release seal",
            }
        )
    out["physicalCertified"] = False
    return out


def _source_failure(root: Path, exc: RuntimeError) -> dict:
    code = str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_GIT_SOURCE_INVALID"
    out = enrich(
        {
            "authority": sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready": False,
            "requiredHost": "linux-amd64-exact-toolchain",
            "missingHostTools": [],
            "blockers": [code],
            "physicalCertified": False,
        }
    )
    out.update(
        {
            "nextActionCode": "RESTORE_C9_SOURCE_AUTHORITY",
            "nextCommand": ["git", "status", "--short"],
            "requiredInputs": [],
            "sourceCommitSHA": "",
            "resumeExistingEvidence": False,
            "admissionReady": False,
            "detail": f"{code}; restore canonical clean main at the exact repository root before evaluating C9 admission/environment readiness",
        }
    )
    return out


def _existing_evidence_failure(code: str, source_sha: str) -> dict:
    out = enrich(
        {
            "authority": sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready": False,
            "requiredHost": "linux-amd64-exact-toolchain",
            "missingHostTools": [],
            "blockers": [code],
            "physicalCertified": False,
        }
    )
    out.update(
        {
            "nextActionCode": "INSPECT_C9_EXISTING_EVIDENCE",
            "nextCommand": ["git", "status", "--short", "--", FINAL_EVIDENCE_REL.as_posix()],
            "requiredInputs": [],
            "sourceCommitSHA": source_sha,
            "resumeExistingEvidence": True,
            "admissionReady": False,
            "detail": f"{code}; the canonical final evidence exists but is not safe to resume; inspect or restore that exact evidence rather than starting a new C9 run",
        }
    )
    return out


def validate_existing_evidence(root: Path, evidence: Path, current_sha: str) -> dict:
    value=load_existing_evidence_snapshot(evidence)
    if not isinstance(value, dict) or set(value) != sealer.FINAL_EVIDENCE_KEYS:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_FIELDS_INVALID")
    sealed_sha = str(value.get("sourceCommitSHA") or "").strip().lower()
    try:
        sealer.validate_final_evidence_lineage(root, sealed_sha, current_sha, evidence)
    except RuntimeError as exc:
        code = str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID"
        raise RuntimeError(code) from exc
    return value


def _admission_failure(root:Path,source_sha:str,exc:BaseException)->dict:
    code=str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_ADMISSION_INVALID"
    out=enhance={
        "authority":sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
        "ready":False,
        "requiredHost":"linux-amd64-exact-toolchain",
        "missingHostTools":[],
        "blockers":[code],
        "physicalCertified":False,
    }
    out=enrich(out)
    out.update({
        "sourceCommitSHA":source_sha,
        "resumeExistingEvidence":False,
        "admissionAuthority":sealer.admission.AUTHORITY,
        "admissionReady":False,
        "requiredInputs":[],
    })
    if isinstance(exc,sealer.admission.Pending) and code=="MCP_EXTERNAL_INTEROP_PENDING":
        try:
            progress=sealer.admission.external_client_progress(root)
        except RuntimeError:
            progress={
                "authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1",
                "certifiedClientCount":0,
                "certifiedClients":[],
                "missingClients":list(sealer.admission.CLIENTS),
                "nextClient":sealer.admission.CLIENTS[0],
                "complete":False,
                "evidenceSealPending":False,
            }
        out.update({
            "nextActionCode":"RUN_C7W_PREFLIGHT",
            "nextCommand":list(C7W_PREFLIGHT_COMMAND),
            "externalClientProgress":progress,
            "detail":"C9 is blocked by unsealed external MCP interoperability evidence; continue the canonical C7W preflight/status flow before any C9 environment work",
        })
    elif isinstance(exc,sealer.admission.Pending) and code=="APPLIANCE_DISTRIBUTION_PENDING":
        out.update({
            "nextActionCode":"COMPLETE_S1_APPLIANCE_DISTRIBUTION",
            "nextCommand":list(ADMISSION_STATUS_COMMAND),
            "detail":"C9 is blocked by the canonical appliance distribution authority; complete S1 before C9 environment work",
        })
    else:
        out.update({
            "nextActionCode":"INSPECT_C9_ADMISSION_AUTHORITY",
            "nextCommand":list(ADMISSION_STATUS_COMMAND),
            "detail":f"{code}; final exact release admission is invalid for the exact source SHA",
        })
    return out


def _admission_preflight(root:Path,source_sha:str)->tuple[dict|None,dict|None]:
    try:
        admitted=sealer.exact_source_admission(root,source_sha)
    except (sealer.admission.Pending,RuntimeError) as exc:
        return _admission_failure(root,source_sha,exc),None
    if (
        not isinstance(admitted,dict)
        or admitted.get("authority")!=sealer.admission.AUTHORITY
        or admitted.get("admitted") is not True
        or admitted.get("physicalCertified") is not False
    ):
        return _admission_failure(root,source_sha,RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_INVALID")),None
    return None,admitted


def preflight(root: Path) -> dict:
    root = root.resolve()
    evidence = root / FINAL_EVIDENCE_REL
    evidence_present=evidence.exists() or evidence.is_symlink()
    if evidence_present and (evidence.is_symlink() or not evidence.is_file()):
        return bind_execution_context(root,_existing_evidence_failure("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID", ""))
    resume = evidence_present
    try:
        source_sha = sealer.git_source_for_resume(root, evidence) if resume else sealer.git_source(root)
    except RuntimeError as exc:
        return bind_execution_context(root,_source_failure(root, exc))

    sealed_evidence=None
    admission_source_sha=source_sha
    if resume:
        try:
            sealed_evidence=validate_existing_evidence(root, evidence, source_sha)
            admission_source_sha=str(sealed_evidence.get("sourceCommitSHA") or "").strip().lower()
        except RuntimeError as exc:
            code = str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID"
            return bind_execution_context(root,_existing_evidence_failure(code, source_sha))

    admission_failure,admitted=_admission_preflight(root,admission_source_sha)
    if admission_failure is not None:
        admission_failure["sourceCommitSHA"]=source_sha
        admission_failure["resumeExistingEvidence"]=resume
        if admission_source_sha!=source_sha:
            admission_failure["sealedSourceCommitSHA"]=admission_source_sha
        return bind_execution_context(root,admission_failure)

    try:
        toolchain_lock,_=sealer.exact_source_toolchain_lock(root,admission_source_sha)
    except RuntimeError as exc:
        code=str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_SOURCE_OBJECT_INVALID"
        out=enrich({
            "authority":sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready":False,
            "requiredHost":"linux-amd64-exact-toolchain",
            "missingHostTools":[],
            "blockers":[code],
            "physicalCertified":False,
        })
        out["sourceCommitSHA"]=source_sha
        out["resumeExistingEvidence"]=resume
        out["admissionAuthority"]=admitted["authority"]
        out["admissionReady"]=True
        if admission_source_sha!=source_sha:
            out["sealedSourceCommitSHA"]=admission_source_sha
        return bind_execution_context(root,out)

    out = enrich(sealer.exact_release_environment_preflight(root,toolchain_lock=toolchain_lock))
    out["sourceCommitSHA"] = source_sha
    out["resumeExistingEvidence"] = resume
    out["admissionAuthority"] = admitted["authority"]
    out["admissionReady"] = True
    if admission_source_sha!=source_sha:
        out["sealedSourceCommitSHA"]=admission_source_sha
    try:
        final_source_sha=sealer.git_source_for_resume(root,evidence) if resume else sealer.git_source(root)
    except RuntimeError as exc:
        failure=_source_failure(root,exc)
        failure["sourceCommitSHA"]=source_sha
        failure["resumeExistingEvidence"]=resume
        return bind_execution_context(root,failure)
    if final_source_sha!=source_sha:
        failure=_source_failure(root,RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_PREFLIGHT"))
        failure["sourceCommitSHA"]=source_sha
        failure["resumeExistingEvidence"]=resume
        return bind_execution_context(root,failure)
    if resume and out.get("ready") is True:
        out["detail"] = "existing final evidence is present at the canonical path; final admission remains valid and the exact sealer must perform full resume revalidation before post-seal Git handoff"
    return bind_execution_context(root,out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--preflight", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    result = preflight(args.root)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ready") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
