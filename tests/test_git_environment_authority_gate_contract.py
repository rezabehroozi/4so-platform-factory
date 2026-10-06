import ast
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod

release_gate=load("scripts/release_tool_authority_gate.py","release_tool_authority_gate_contract")
c7w_gate=load("scripts/c7w_execution_authority_gate.py","c7w_execution_authority_gate_contract")


class GitEnvironmentAuthorityGateContractTests(unittest.TestCase):
    BAD='import subprocess\ndef f():\n    subprocess.run(["git","rev-parse","HEAD"],check=False)\n'
    GOOD='import subprocess\ndef f(env):\n    subprocess.run(["git","rev-parse","HEAD"],env=env,check=False)\n'
    TUPLE_BAD='import subprocess\ndef f():\n    subprocess.run(("git","rev-parse","HEAD"),check=False)\n'
    TUPLE_GOOD='import subprocess\ndef f(env):\n    subprocess.run(("git","rev-parse","HEAD"),env=env,check=False)\n'
    COMPUTED_BAD='import subprocess\ndef f():\n    subprocess.run(["g"+"it","rev-parse","HEAD"],check=False)\n'
    COMPUTED_GOOD='import subprocess\ndef f(env):\n    subprocess.run(["g"+"it","rev-parse","HEAD"],env=env,check=False)\n'

    def test_release_gate_detects_direct_git_call_without_env(self):
        self.assertTrue(release_gate.direct_git_calls_without_env(self.BAD))
        self.assertEqual([],release_gate.direct_git_calls_without_env(self.GOOD))

    def test_release_gate_detects_tuple_git_call_without_env(self):
        self.assertTrue(release_gate.direct_git_calls_without_env(self.TUPLE_BAD))
        self.assertEqual([],release_gate.direct_git_calls_without_env(self.TUPLE_GOOD))

    def test_release_gate_detects_computed_constant_git_call_without_env(self):
        self.assertTrue(release_gate.direct_git_calls_without_env(self.COMPUTED_BAD))
        self.assertEqual([],release_gate.direct_git_calls_without_env(self.COMPUTED_GOOD))

    def test_c7w_gate_detects_direct_git_call_without_env(self):
        self.assertTrue(c7w_gate.direct_git_calls_without_env(self.BAD))
        self.assertEqual([],c7w_gate.direct_git_calls_without_env(self.GOOD))

    def test_c7w_gate_detects_tuple_git_call_without_env(self):
        self.assertTrue(c7w_gate.direct_git_calls_without_env(self.TUPLE_BAD))
        self.assertEqual([],c7w_gate.direct_git_calls_without_env(self.TUPLE_GOOD))

    def test_c7w_gate_detects_computed_constant_git_call_without_env(self):
        self.assertTrue(c7w_gate.direct_git_calls_without_env(self.COMPUTED_BAD))
        self.assertEqual([],c7w_gate.direct_git_calls_without_env(self.COMPUTED_GOOD))


if __name__=="__main__":
    unittest.main()