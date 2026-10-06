import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("project_runtime_git_environment_authority",ROOT/"scripts"/"project_runtime.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ProjectRuntimeGitEnvironmentAuthorityTests(unittest.TestCase):
    def git(self,root:Path,*args:str)->str:
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root:Path,label:str)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"source.txt").write_text(label+"\n",encoding="utf-8")
        self.git(root,"add","source.txt")
        self.git(root,"commit","-m",label)
        return self.git(root,"rev-parse","HEAD")

    def test_runtime_git_identity_ignores_inherited_git_repository_overrides(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); source=base/"source"; decoy=base/"decoy"; source.mkdir(); decoy.mkdir()
            source_head=self.repo(source,"source")
            decoy_head=self.repo(decoy,"decoy")
            self.assertNotEqual(source_head,decoy_head)
            poisoned={"GIT_DIR":str(decoy/".git"),"GIT_WORK_TREE":str(decoy)}
            with mock.patch.dict(os.environ,poisoned,clear=False):
                observed=mod.git(source)
            self.assertEqual(source_head,observed["head"])
            self.assertEqual("main",observed["branch"])

    def test_runtime_git_rejects_repository_subdirectory_as_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.repo(root,"source")
            child=root/"child"; child.mkdir()
            with self.assertRaisesRegex(RuntimeError,"GIT_ROOT_INVALID"):
                mod.git(child)

    def test_clean_git_env_removes_all_git_prefixed_variables(self):
        with mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/decoy","GIT_WORK_TREE":"/tmp/decoy","GIT_CONFIG_COUNT":"1","SAFE_RUNTIME":"yes"},clear=False):
            env=mod.clean_git_env()
        self.assertEqual("yes",env["SAFE_RUNTIME"])
        self.assertFalse(any(key.startswith("GIT_") for key in env))

    def test_command_wrapper_execs_child_with_clean_git_environment(self):
        gated={"command":["python3","child.py"],"runId":"run-test"}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with mock.patch.dict(
                os.environ,
                {
                    "GIT_CONFIG_COUNT":"1",
                    "GIT_CONFIG_KEY_0":"core.fsmonitor",
                    "GIT_CONFIG_VALUE_0":"/tmp/evil-fsmonitor",
                    "GIT_DIR":"/tmp/decoy.git",
                    "SAFE_RUNTIME":"yes",
                },
                clear=False,
            ), mock.patch.object(mod,"ticks",return_value="123"), mock.patch.object(mod,"read_state",return_value=gated), mock.patch.object(mod,"command_gate_state",return_value=gated), mock.patch.object(mod,"execution_source_status",return_value={"matched":True}), mock.patch.object(mod.os,"execvpe",side_effect=OSError("stop")) as execvpe, mock.patch.object(mod,"record_command_exec_failure"):
                self.assertEqual(125,mod.command_wrapper(root,"run-test"))
        env=execvpe.call_args.args[2]
        self.assertEqual("yes",env.get("SAFE_RUNTIME"))
        self.assertFalse(any(key.startswith("GIT_") for key in env),env)


if __name__=="__main__":
    unittest.main()
