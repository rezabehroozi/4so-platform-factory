#!/usr/bin/env python3
from __future__ import annotations
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pattern = "TestRollbackFeasibilityProvesDeleteAndRestorePreimage|TestRollbackFeasibilityBlocksDeniedDeleteAndSecretPreimage|TestRollbackBaselineExecutesBoundStrategiesAndRejectsTamper"
    result = subprocess.run(
        ["go", "test", "./cmd/platform-agent", "-run", pattern, "-count=1"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        raise SystemExit(result.returncode)
    print("GENERIC_ROLLBACK_FEASIBILITY_SMOKE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
