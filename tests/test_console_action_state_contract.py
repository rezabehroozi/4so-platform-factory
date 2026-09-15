"""Console mutation preconditions must be bound to markup the console actually emits."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_repository", ROOT / "scripts" / "validate_repository.py")
VALIDATE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VALIDATE)

GUARD_JS = """
const explicitMutationKeys=new Set(['notificationRetryDeadLetter']);
function operationalActionStateReason(button) {
  if(button.dataset.notificationRetryDeadLetter){item=find(state.notificationDeliveries,button.dataset.notificationRetryDeadLetter);if(!item)return 'gone';}
  return '';
}
"""


class ConsoleActionStateContractTests(unittest.TestCase):
    def test_guard_bound_to_an_emitted_value_passes(self):
        markup = GUARD_JS + '<button type="button" data-notification-retry-dead-letter="${esc(item.id)}">Requeue</button>'
        self.assertEqual([], VALIDATE.console_action_state_failures(GUARD_JS, markup, "app.js"))

    def test_valueless_flag_silently_skips_the_guard(self):
        markup = GUARD_JS + '<button type="button" data-notification-retry-dead-letter class="primary">Requeue</button>'
        failures = VALIDATE.console_action_state_failures(GUARD_JS, markup, "app.js")
        self.assertEqual(1, len(failures), failures)
        self.assertIn("precondition is silently skipped", failures[0])
        self.assertIn("notification-retry-dead-letter", failures[0])

    def test_binding_declared_in_the_static_page_counts_as_emitted(self):
        script = "function guard(button){if(button.dataset.gitCredentialAction){return '';}}"
        markup = script + '<button data-git-credential-action="revoke" id="git-credential-revoke" type="button">'
        self.assertEqual([], VALIDATE.console_action_state_failures(script, markup, "app.js"))

    def test_mutation_key_without_any_markup_is_dead(self):
        script = "const explicitMutationKeys=new Set(['gitLkgRollback']);"
        failures = VALIDATE.console_action_state_failures(script, script, "app.js")
        self.assertEqual(1, len(failures), failures)
        self.assertIn("explicitMutationKeys lists gitLkgRollback", failures[0])

    def test_shipped_consoles_bind_every_declared_guard(self):
        errors: list[tuple[str, str]] = []
        checked = VALIDATE.validate_console_action_state_contract(ROOT, errors)
        self.assertEqual([], errors)
        self.assertGreaterEqual(checked, 30, "the guard surface must not silently shrink")


if __name__ == "__main__":
    unittest.main()
