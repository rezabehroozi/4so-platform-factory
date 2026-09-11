# Compliance Scan Center V37 Foundation

`PROGRAM_PHASE_MODEL_V37` adds the first executable compliance-analysis primitive without pretending G5 is complete.

## Authority

`4SO_KUBERNETES_SECURITY_BASELINE_V1` is a product-owned deterministic evaluator for Kubernetes object evidence. It does **not** claim CIS certification, FIPS certification, vendor scanner equivalence, or Physical PASS.

The V37 foundation currently evaluates four high-value classes:

- `RBAC_CLUSTER_ADMIN_BINDING` — RoleBinding/ClusterRoleBinding grants `cluster-admin`.
- `WORKLOAD_HOST_NAMESPACE` — Pod-template use of `hostNetwork`, `hostPID`, or `hostIPC`.
- `WORKLOAD_PRIVILEGED_CONTAINER` — privileged init/container workloads.
- `IMAGE_MUTABLE_LATEST_TAG` — untagged or `:latest` images; digest-pinned images are accepted.

Every finding receives a stable SHA-256 fingerprint over baseline authority, rule and resource identity/evidence so future durable ScanRun/Finding authority can preserve identity across rechecks.

## Operator surface

```bash
platformctl compliance evaluate -f kubernetes-objects.json
```

The input is a Kubernetes JSON object, `kind: List`, or JSON array. V37 intentionally avoids a YAML dependency in the core binary; collection/conversion belongs to the future Agent-backed durable scan workflow.

## Explicit non-closure

G5 remains `blocked`. V37 does not yet provide:

- durable `ComplianceProfile` / `ScanRun` state;
- Agent lease/fence scan execution;
- durable Finding/Evidence/Waiver/Recheck lifecycle;
- Keycloak SAML identity-provider lifecycle and Console workflow;
- CIS/conformance/vulnerability certification backed by admitted external toolchains.

Those gaps are represented by `SAML_ENTERPRISE_SSO_PENDING` and `COMPLIANCE_DURABLE_SCAN_CENTER_PENDING`. No source/physical release claim may infer their completion from the baseline evaluator.
