#!/usr/bin/env python3
"""Execute top-level Python contract tests missed by unittest discovery.

The repository intentionally avoids an unpinned pytest dependency. TestCase
methods remain owned by unittest discovery; this runner executes only module-
level test_* functions. Supported fixtures are explicit and fail closed.
"""
from __future__ import annotations
import ast
import importlib.util
import inspect
from pathlib import Path
import sys
import tempfile
import traceback

ROOT=Path(__file__).resolve().parents[1]
TESTS=ROOT/"tests"
SUPPORTED={"tmp_path"}

def top_level_tests(path:Path)->list[str]:
    tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
    return [n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith("test_")]

def load_module(path:Path):
    name="fourso_contract_"+path.stem
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"PYTHON_CONTRACT_IMPORT_SPEC_INVALID {path}")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def invoke(fn):
    params=inspect.signature(fn).parameters
    unknown=sorted(set(params)-SUPPORTED)
    if unknown:
        raise RuntimeError("PYTHON_CONTRACT_UNSUPPORTED_FIXTURE "+fn.__module__+"."+fn.__name__+" "+",".join(unknown))
    with tempfile.TemporaryDirectory(prefix="4so-python-contract-") as td:
        kwargs={}
        if "tmp_path" in params:
            kwargs["tmp_path"]=Path(td)
        result=fn(**kwargs)
        if inspect.isawaitable(result):
            raise RuntimeError("PYTHON_CONTRACT_ASYNC_UNSUPPORTED "+fn.__module__+"."+fn.__name__)

def main()->int:
    failures=[]; count=0; modules=0
    for path in sorted(TESTS.glob("test_*.py")):
        names=top_level_tests(path)
        if not names:
            continue
        modules+=1
        try:
            mod=load_module(path)
        except Exception:
            failures.append((str(path.relative_to(ROOT)),"<import>",traceback.format_exc()))
            continue
        for name in names:
            count+=1
            try:
                invoke(getattr(mod,name))
            except Exception:
                failures.append((str(path.relative_to(ROOT)),name,traceback.format_exc()))
    for path,name,tb in failures:
        print(f"PYTHON_CONTRACT_TEST_FAIL {path}::{name}\n{tb}",file=sys.stderr)
    if failures:
        print(f"PYTHON_CONTRACT_TESTS_FAIL tests={count} modules={modules} failures={len(failures)}",file=sys.stderr)
        return 1
    print(f"PYTHON_CONTRACT_TESTS_PASS tests={count} modules={modules}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
