from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class StandaloneSmokeAuthBoundaryTests(unittest.TestCase):
    def test_api_spawning_smokes_do_not_depend_on_parent_development_mode(self):
        missing = []
        for path in sorted((ROOT / "scripts").glob("smoke_*.py")):
            text = path.read_text()
            if "Popen" not in text or "PLATFORM_FACTORY_LISTEN" not in text:
                continue
            if "PLATFORM_FACTORY_OIDC_ENABLED" in text:
                continue
            if "PLATFORM_FACTORY_DEVELOPMENT_MODE" not in text:
                missing.append(path.name)
        self.assertEqual([], missing, f"standalone API smoke tools missing explicit auth mode: {missing}")

if __name__ == "__main__":
    unittest.main()
