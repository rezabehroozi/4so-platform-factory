import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("release_tool_authority_gate",ROOT/"scripts"/"release_tool_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReleaseToolAuthorityScopeTests(unittest.TestCase):
    def test_function_call_lines_ignore_nested_dead_functions(self):
        source='''\ndef execute():\n    git_source()\n    exact_source_admission()\n    def dead_path():\n        require_exact_release_host()\n        require_exact_release_environment()\n    return None\n'''
        calls=mod.function_call_lines(source,"execute")
        self.assertIn("git_source",calls)
        self.assertIn("exact_source_admission",calls)
        self.assertNotIn("require_exact_release_host",calls)
        self.assertNotIn("require_exact_release_environment",calls)


if __name__=="__main__":
    unittest.main()
