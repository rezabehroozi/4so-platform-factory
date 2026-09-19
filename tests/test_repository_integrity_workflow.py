#!/usr/bin/env python3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "repository-integrity.yml"


class RepositoryIntegrityWorkflowTests(unittest.TestCase):
    def test_explicit_clean_clone_checks_out_trigger_sha_before_verification(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        marker = "Explicit clean-clone verification"
        self.assertIn(marker, text)
        section = text[text.index(marker):]
        checkout = 'git checkout --quiet --detach "${GITHUB_SHA}"'
        verify = 'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"'
        self.assertIn(checkout, section)
        self.assertIn(verify, section)
        self.assertLess(section.index(checkout), section.index(verify))

    def test_clean_clone_does_not_assume_branch_head_stays_fixed(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        section = text[text.index("Explicit clean-clone verification"):]
        clone = "git clone --quiet"
        checkout = 'git checkout --quiet --detach "${GITHUB_SHA}"'
        self.assertIn(clone, section)
        self.assertIn(checkout, section)


if __name__ == "__main__":
    unittest.main()
