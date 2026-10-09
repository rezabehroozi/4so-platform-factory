import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class C7WMakePreparePreflightTests(unittest.TestCase):
    def test_c7w_prepare_runs_authoritative_preflight_before_runner_prepare(self):
        makefile=(ROOT/"Makefile").read_text(encoding="utf-8")
        block=makefile.split("c7w-prepare:\n",1)[1].split("\nc7w-admit:\n",1)[0]
        preflight='scripts/c7w_preflight.py --root .'
        runner='scripts/run_mcp_external_interop.py --state-dir "$(C7W_STATE_DIR)" prepare'
        self.assertIn(preflight,block)
        self.assertIn(runner,block)
        self.assertLess(block.index(preflight),block.index(runner))
        self.assertIn('--endpoint "$(C7W_MCP_ENDPOINT)"',block)
        self.assertIn('--token-env "$(C7W_PLATFORM_ADMIN_TOKEN_ENV)"',block)
        self.assertIn('$(if $(strip $(C7W_OAUTH_CLIENT_MAP)),--oauth-client-map "$(C7W_OAUTH_CLIENT_MAP)",)',block)
        self.assertIn('--source-commit-sha "$(GIT_SOURCE_COMMIT)"',block)

    def test_c7w_make_default_state_tracks_current_source_prefix(self):
        makefile=(ROOT/"Makefile").read_text(encoding="utf-8")
        self.assertIn("C7W_SOURCE_PREFIX :=",makefile)
        self.assertIn("GIT_SOURCE_COMMIT",makefile)
        self.assertIn("C7W_STATE_DIR ?= .state/c7w-external-interop-$(C7W_SOURCE_PREFIX)",makefile)
        self.assertNotIn("C7W_STATE_DIR ?= .state/c7w-external-interop\n",makefile)


if __name__=="__main__":
    unittest.main()
