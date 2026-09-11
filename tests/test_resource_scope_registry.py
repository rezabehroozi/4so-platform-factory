import importlib.util
import json
import pathlib
import re
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


def test_every_stable_resource_family_has_source_reviewed_owner_classification():
    contract = json.loads((ROOT / "sdk" / "product-api-contract.json").read_text())
    classifications = json.loads((ROOT / "internal" / "api" / "resource_scope_owner_classifications.json").read_text())
    expected = sorted({row["family"] for row in contract["routes"]})
    reviewed = classifications["families"]
    missing = sorted(set(expected) - set(reviewed))
    extra = sorted(set(reviewed) - set(expected))
    assert extra == []
    assert missing == [], f"unreviewed stable Product API families: {missing}"
    assert len(reviewed) == len(expected) == contract["routeCount"] * 0 + 73
    for family in expected:
        row = reviewed[family]
        assert row["scope"] in {"PLATFORM_SCOPED", "ORGANIZATION_SCOPED", "PROJECT_SCOPED", "DYNAMIC_SCOPED"}
        assert row["evidence"].strip(), f"{family} is missing source evidence"


def test_owner_classification_evidence_references_existing_source_files():
    classifications = json.loads((ROOT / "internal" / "api" / "resource_scope_owner_classifications.json").read_text())
    source_path_re = re.compile(r"(?:internal|scripts|sdk|webconsole|migrations)/[A-Za-z0-9_./-]+\.(?:go|py|json|sql|js|html)")
    failures = []
    for family, row in sorted(classifications["families"].items()):
        paths = source_path_re.findall(row["evidence"])
        existing = [path for path in paths if (ROOT / path).is_file()]
        if not existing:
            failures.append((family, paths))
    assert failures == [], f"classification evidence must name at least one existing source file: {failures}"


def test_repository_validator_rejects_stale_scope_evidence_path(tmp_path):
    source_api = ROOT / "internal" / "api"
    target_api = tmp_path / "internal" / "api"
    target_api.mkdir(parents=True)
    for name in ("resource_scope_registry.json", "resource_scope_owner_classifications.json", "mcp_route_parity_registry.json"):
        (target_api / name).write_bytes((source_api / name).read_bytes())
    classifications_path = target_api / "resource_scope_owner_classifications.json"
    classifications = json.loads(classifications_path.read_text())
    classifications["families"]["projects"]["evidence"] = "internal/api/does_not_exist.go; explicit owner source"
    classifications_path.write_text(json.dumps(classifications, indent=2, sort_keys=True) + "\n")
    registry_path = target_api / "resource_scope_registry.json"
    registry = json.loads(registry_path.read_text())
    for row in registry["families"]:
        if row["family"] == "projects":
            row["evidence"] = classifications["families"]["projects"]["evidence"]
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
    spec = importlib.util.spec_from_file_location("validate_repository", ROOT / "scripts" / "validate_repository.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = []
    module.validate_resource_scope_registry(tmp_path, errors)
    assert any(code == "RESOURCE_SCOPE_EVIDENCE_SOURCE_MISSING" for code, _ in errors), errors
