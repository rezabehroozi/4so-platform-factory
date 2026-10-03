import ast
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ADMISSION_PATH=ROOT/"scripts/final_exact_release_admission.py"
SEALER_PATH=ROOT/"scripts/seal_final_exact_release.py"
SPEC=importlib.util.spec_from_file_location("final_exact_release_admission_source_fence_test",ADMISSION_PATH)
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


def call_name(node):
    if isinstance(node.func,ast.Name):
        return node.func.id
    if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return ""


def function_calls(path:Path,function_name:str):
    tree=ast.parse(path.read_text(encoding="utf-8"))
    fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==function_name)
    calls=[]
    for node in ast.walk(fn):
        if isinstance(node,ast.Call):
            name=call_name(node)
            if name:
                calls.append((name,node.lineno))
    returns=[node.lineno for node in ast.walk(fn) if isinstance(node,ast.Return)]
    return calls,returns


class C9AdmissionSourceRevalidationTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_source_workspace_fence_rejects_dirty_and_index_masked_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"authority.json"; tracked.write_text('{"value":"exact"}\n',encoding="utf-8")
            self.git(root,"add","authority.json"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            self.assertEqual(head,mod.require_exact_source_workspace(root,head))

            tracked.write_text('{"value":"dirty"}\n',encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_WORKSPACE_NOT_CLEAN"):
                mod.require_exact_source_workspace(root,head)

            self.git(root,"checkout","--","authority.json")
            self.git(root,"update-index","--assume-unchanged","authority.json")
            tracked.write_text('{"value":"masked"}\n',encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_WORKSPACE_INDEX_FLAGS_FORBIDDEN"):
                mod.require_exact_source_workspace(root,head)

    def test_final_admission_fences_source_before_and_after_evidence_validation(self):
        calls,returns=function_calls(ADMISSION_PATH,"verify")
        fences=[line for name,line in calls if name=="require_exact_source_workspace"]
        snapshots=[line for name,line in calls if name=="load_snapshot"]
        witnesses=[line for name,line in calls if name=="mcp_contract.validate_server_audit_witness"]
        self.assertEqual(2,len(fences))
        self.assertTrue(snapshots)
        self.assertTrue(witnesses)
        self.assertLess(fences[0],min(snapshots))
        self.assertGreater(fences[1],max(witnesses))
        self.assertLess(fences[1],max(returns))

    def test_native_build_consumes_final_admission_before_toolchain_access(self):
        calls,_=function_calls(SEALER_PATH,"execute")
        admission_lines=[line for name,line in calls if name=="admission.verify"]
        toolchain_lines=[line for name,line in calls if name=="safe_toolchain_archive"]
        self.assertTrue(admission_lines)
        self.assertTrue(toolchain_lines)
        self.assertLess(min(admission_lines),min(toolchain_lines))


if __name__=="__main__":
    unittest.main()
