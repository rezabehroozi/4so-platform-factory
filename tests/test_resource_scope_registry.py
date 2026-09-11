import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_scope_registry_covers_every_route_family_and_never_infers_missing_owners():
    registry = json.loads((ROOT / "internal" / "api" / "resource_scope_registry.json").read_text())
    parity = json.loads((ROOT / "internal" / "api" / "mcp_route_parity_registry.json").read_text())
    expected = sorted({row["family"] for row in parity["routes"]})
    assert registry["authority"] == "RESOURCE_SCOPE_REGISTRY_V1"
    assert [row["family"] for row in registry["families"]] == expected
    assert registry["familyCount"] == len(expected)
    for row in registry["families"]:
        if row["status"] == "OWNER_REVIEW_REQUIRED":
            assert row["scope"] == "UNCLASSIFIED"
            assert row["evidence"] == ""
    subprocess.run(["python3", "scripts/generate_resource_scope_registry.py", "--check", "."], cwd=ROOT, check=True)


def test_high_impact_resource_families_are_explicitly_owner_classified():
    registry = json.loads((ROOT / "internal" / "api" / "resource_scope_registry.json").read_text())
    by_family = {row["family"]: row for row in registry["families"]}
    expected = {
        "projects": "ORGANIZATION_SCOPED",
        "workspaces": "PROJECT_SCOPED",
        "provider-profiles": "PROJECT_SCOPED",
        "provider-clusters": "PROJECT_SCOPED",
        "finops": "DYNAMIC_SCOPED",
        "ai": "DYNAMIC_SCOPED",
    }
    for family, scope in expected.items():
        assert by_family[family]["scope"] == scope
        assert by_family[family]["status"] == "OWNER_CLASSIFIED"
