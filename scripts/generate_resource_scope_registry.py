#!/usr/bin/env python3
"""Generate an explicit route-family ownership registry without scope inference.

Missing owner classifications remain UNCLASSIFIED/OWNER_REVIEW_REQUIRED. This is
intentional: a route name, tenant-looking table or URL shape must never silently
be treated as global/project-scoped authority.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

AUTHORITY = "RESOURCE_SCOPE_REGISTRY_V1"
CLASS_AUTHORITY = "RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1"
ALLOWED = {"PLATFORM_SCOPED", "ORGANIZATION_SCOPED", "PROJECT_SCOPED", "DYNAMIC_SCOPED"}


def args(argv):
    check = "--check" in argv
    rest = [x for x in argv if x != "--check"]
    if len(rest) > 1:
        raise SystemExit("usage: generate_resource_scope_registry.py [--check] [root]")
    return Path(rest[0] if rest else ".").resolve(), check


def main():
    root, check = args(sys.argv[1:])
    parity = json.loads((root / "internal/api/mcp_route_parity_registry.json").read_text())
    classifications = json.loads((root / "internal/api/resource_scope_owner_classifications.json").read_text())
    if parity.get("authority") != "MCP_ROUTE_PARITY_AUTHORITY_V1":
        raise SystemExit("route parity authority mismatch")
    if classifications.get("authority") != CLASS_AUTHORITY:
        raise SystemExit("scope classification authority mismatch")
    policy = classifications.get("policy", {})
    if policy.get("inferenceAllowed") is not False or policy.get("defaultScope") != "UNCLASSIFIED":
        raise SystemExit("scope classifications must be fail-closed and non-inferential")
    route_families = sorted({row["family"] for row in parity["routes"]})
    configured = classifications.get("families", {})
    unknown = sorted(set(configured) - set(route_families))
    if unknown:
        raise SystemExit("scope classifications reference unknown route families: " + ", ".join(unknown))
    rows = []
    classified = 0
    for family in route_families:
        item = configured.get(family)
        if item is None:
            rows.append({"evidence": "", "family": family, "scope": "UNCLASSIFIED", "status": "OWNER_REVIEW_REQUIRED"})
            continue
        scope = str(item.get("scope", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        if scope not in ALLOWED or not evidence:
            raise SystemExit(f"invalid explicit owner classification for {family}")
        classified += 1
        rows.append({"evidence": evidence, "family": family, "scope": scope, "status": "OWNER_CLASSIFIED"})
    out = {
        "authority": AUTHORITY,
        "classificationAuthority": CLASS_AUTHORITY,
        "classifiedCount": classified,
        "families": rows,
        "familyCount": len(rows),
        "ownerReviewRequiredCount": len(rows) - classified,
        "policy": {
            "inferenceAllowed": False,
            "missingClassification": "OWNER_REVIEW_REQUIRED",
            "missingScope": "UNCLASSIFIED",
            "registryIsAuditAuthorityNotAuthorizationBypass": True,
        },
        "sourceAuthority": "MCP_ROUTE_PARITY_AUTHORITY_V1",
    }
    expected = json.dumps(out, indent=2, sort_keys=True) + "\n"
    path = root / "internal/api/resource_scope_registry.json"
    if check:
        if not path.exists() or path.read_text() != expected:
            raise SystemExit("resource scope registry drift")
    else:
        path.write_text(expected)
    print(json.dumps({"familyCount": len(rows), "classifiedCount": classified, "ownerReviewRequiredCount": len(rows)-classified, "check": check}, sort_keys=True))


if __name__ == "__main__":
    main()
