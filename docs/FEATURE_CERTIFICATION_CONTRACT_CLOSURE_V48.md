# Feature Certification Contract Closure V48

## Problem

The previous `FEATURE_CERTIFICATION_REGISTRY_V1` named broad product features and certification levels, but it did not bind every mandatory Core Freeze phase to an explicit owner contract. It also had no machine-readable negative-control requirement. As a result, C9 correctly retained `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE` even though many individual feature tests already existed.

## V48 authority

`FEATURE_CERTIFICATION_REGISTRY_V2` is now embedded in `PROGRAM_PHASE_MODEL_V48` and exposed through the existing target-architecture API/MCP authority. Every mandatory Core phase before C9 has at least one owner contract.

The coverage authority is `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`:

- required Core owner phases before C9: **24**;
- covered owner phases: **24**;
- missing owner phases: **0**;
- completeness: **true**.

A contract contains:

- `feature`;
- `ownerPhases`;
- `requiredLevels`;
- `physicalScenarios` when Exact-SHA or chaos execution is required;
- `negativeControls`.

## Fail-closed validation

`ValidateFeatureCertificationRegistry` rejects:

- empty or duplicate feature IDs;
- missing/unknown owner phases;
- empty or unknown certification levels;
- Exact-SHA/chaos contracts without scenario rows;
- contracts without negative controls;
- any mandatory pre-C9 Core phase left uncovered.

Negative regression tests deliberately remove the C7W owner contract and remove negative controls from another contract. Both must fail validation.

## Physical truth

Completing the contract registry is not execution evidence. M00-M13 remain independent certification work. Connected OKD, disconnected OKD, component upgrade pairs, external MCP clients and exact supply-chain acquisition remain blocked exactly as before.

For this reason Core source closure stays **19/25 = 76%**. C9 loses only `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE`; it remains blocked on `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN` and `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`.
