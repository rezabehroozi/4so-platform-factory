import ast
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SEALER=ROOT/"scripts"/"seal_final_exact_release.py"


class C9SealerGitEnvironmentFamilyContractTests(unittest.TestCase):
    def test_every_direct_git_subprocess_run_has_explicit_environment(self):
        tree=ast.parse(SEALER.read_text(encoding="utf-8"),filename=str(SEALER))
        missing=[]
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):
                continue
            func=node.func
            if not (
                isinstance(func,ast.Attribute)
                and func.attr=="run"
                and isinstance(func.value,ast.Name)
                and func.value.id=="subprocess"
                and node.args
                and isinstance(node.args[0],ast.List)
                and node.args[0].elts
                and isinstance(node.args[0].elts[0],ast.Constant)
                and node.args[0].elts[0].value=="git"
            ):
                continue
            if not any(keyword.arg=="env" for keyword in node.keywords):
                missing.append(getattr(node,"lineno",0))
        self.assertEqual([],missing,f"direct git subprocess calls missing env= at lines {missing}")


if __name__=="__main__":
    unittest.main()
