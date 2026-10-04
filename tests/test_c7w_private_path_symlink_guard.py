import ast
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OWNERS=(
    ("scripts/reconcile_c7w_trusted_clients.py","_private_oauth_map"),
    ("scripts/c7w_preflight.py","private_path"),
)


def unsafe_exists_gated_symlink_checks(source:str,owner_name:str)->list[int]:
    tree=ast.parse(source)
    owner=next(
        node for node in tree.body
        if isinstance(node,ast.FunctionDef) and node.name==owner_name
    )
    unsafe=[]
    for node in ast.walk(owner):
        if not isinstance(node,ast.BoolOp) or not isinstance(node.op,ast.And):
            continue
        calls=[]
        for value in node.values:
            if not isinstance(value,ast.Call) or not isinstance(value.func,ast.Attribute):
                continue
            if isinstance(value.func.value,ast.Name) and value.func.value.id=="candidate":
                calls.append(value.func.attr)
        if "exists" in calls and "is_symlink" in calls:
            unsafe.append(getattr(node,"lineno",0))
    return unsafe


class C7WPrivatePathSymlinkGuardTests(unittest.TestCase):
    def test_private_parent_symlink_checks_do_not_depend_on_exists(self):
        for rel,owner_name in OWNERS:
            with self.subTest(owner=rel):
                source=(ROOT/rel).read_text(encoding="utf-8")
                self.assertEqual(
                    [],
                    unsafe_exists_gated_symlink_checks(source,owner_name),
                    "broken parent symlinks must be rejected even when exists() is false",
                )


if __name__=="__main__":
    unittest.main()
