import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("smoke_ui_quality", ROOT / "scripts" / "smoke_ui_quality.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class UIQualityShardingTests(unittest.TestCase):
    def test_default_is_full_backward_compatible_gate(self):
        args = module.parse_args([])
        self.assertEqual(args.scope, "all")
        self.assertEqual(args.shard, (0, 1))
        self.assertEqual(module.select_shard(module.CONSOLE_PAGES, args.shard), module.CONSOLE_PAGES)
        self.assertEqual(module.select_shard(module.INSTALLER_PAGES, args.shard), module.INSTALLER_PAGES)

    def test_route_shards_are_disjoint_and_exhaustive(self):
        shards = [module.select_shard(module.CONSOLE_PAGES, (i, 3)) for i in range(3)]
        flattened = [route for shard in shards for route in shard]
        self.assertEqual(set(flattened), set(module.CONSOLE_PAGES))
        self.assertEqual(len(flattened), len(module.CONSOLE_PAGES))

    def test_invalid_shard_is_rejected(self):
        with self.assertRaises(Exception):
            module.parse_shard("3/3")
        with self.assertRaises(Exception):
            module.parse_shard("x/y")

    def test_installer_sharding_is_deterministic(self):
        self.assertEqual(
            module.select_shard(module.INSTALLER_PAGES, (1, 2)),
            [route for index, route in enumerate(module.INSTALLER_PAGES) if index % 2 == 1],
        )


if __name__ == "__main__":
    unittest.main()
