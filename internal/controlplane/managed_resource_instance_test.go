package controlplane

import "testing"

func TestManagedResourcePlanIsDeterministicAndProjectScoped(t *testing.T) {
	typeDef, err := NormalizeManagedResourceType(ManagedResourceType{ProjectID: "project-a", Name: "postgres", Version: "1.0.0", Category: "database", Provisioner: "product-api", InputSchemaDigest: testMRDigest('a'), DeletePolicy: "delete", ReadinessConditions: []string{"ready"}, Outputs: []ManagedResourceOutput{{Name: "endpoint", Type: "endpoint"}, {Name: "password", Type: "secret-reference", Sensitive: true, SecretReference: true}}})
	if err != nil { t.Fatal(err) }
	typeDef.ID = "amr_type_1"
	dep := ManagedResourceInstance{ResourceMeta: ResourceMeta{ID: "mri_dep", Revision: 3}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: "dep-type", TypeDigest: testMRDigest('b'), Name: "network", State: ManagedResourceReady, ObservedDigest: testMRDigest('c')}
	req := ManagedResourceRequest{ProjectID: "project-a", TypeID: typeDef.ID, Name: "orders-db", InputDigest: testMRDigest('d'), DependencyInstanceIDs: []string{dep.ID}}
	plan1, err := BuildManagedResourcePlan(typeDef, req, []ManagedResourceInstance{dep}); if err != nil { t.Fatal(err) }
	plan2, err := BuildManagedResourcePlan(typeDef, req, []ManagedResourceInstance{dep}); if err != nil { t.Fatal(err) }
	if plan1.Authority != ResourceRequestPlanAuthority || plan1.PlanDigest == "" || plan1.PlanDigest != plan2.PlanDigest || plan1.ProjectID != "project-a" || len(plan1.DependencyInstanceIDs) != 1 { t.Fatalf("deterministic resource plan drift: %#v %#v", plan1, plan2) }
	dep.ProjectID = "project-b"
	if _, err := BuildManagedResourcePlan(typeDef, req, []ManagedResourceInstance{dep}); err == nil { t.Fatal("cross-project dependency must be rejected") }
}

func TestManagedResourceDependencyGraphRejectsCycles(t *testing.T) {
	instances := []ManagedResourceInstance{{ResourceMeta: ResourceMeta{ID: "a", Revision: 1}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: "t", TypeDigest: testMRDigest('a'), Name: "a", State: ManagedResourceReady}, {ResourceMeta: ResourceMeta{ID: "b", Revision: 1}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: "t", TypeDigest: testMRDigest('a'), Name: "b", State: ManagedResourceReady}, {ResourceMeta: ResourceMeta{ID: "c", Revision: 1}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: "t", TypeDigest: testMRDigest('a'), Name: "c", State: ManagedResourceReady}}
	if _, err := BuildManagedResourceDependencyGraph("project-a", instances, []ManagedResourceDependency{{FromInstanceID: "a", ToInstanceID: "b"}, {FromInstanceID: "b", ToInstanceID: "c"}}); err != nil { t.Fatal(err) }
	if _, err := BuildManagedResourceDependencyGraph("project-a", instances, []ManagedResourceDependency{{FromInstanceID: "a", ToInstanceID: "b"}, {FromInstanceID: "b", ToInstanceID: "c"}, {FromInstanceID: "c", ToInstanceID: "a"}}); err == nil { t.Fatal("resource dependency cycle must fail closed") }
}

func TestManagedResourceOutputsBindExactTypeIdentityAndNeverExposeSensitiveValues(t *testing.T) {
	typeDef, err := NormalizeManagedResourceType(ManagedResourceType{ProjectID: "project-a", Name: "postgres", Version: "1.0.0", Category: "database", Provisioner: "product-api", InputSchemaDigest: testMRDigest('a'), DeletePolicy: "delete", ReadinessConditions: []string{"ready"}, Outputs: []ManagedResourceOutput{{Name: "endpoint", Type: "endpoint"}, {Name: "password", Type: "secret-reference", Sensitive: true, SecretReference: true}}})
	if err != nil { t.Fatal(err) }
	typeDef.ID = "type-1"
	instance := ManagedResourceInstance{ResourceMeta: ResourceMeta{ID: "mri_1", Revision: 2}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: typeDef.ID, TypeDigest: typeDef.Digest, Name: "orders-db", State: ManagedResourceReady}
	values := []ManagedResourceOutputValue{{Name: "endpoint", Type: "endpoint", Value: "postgres://db.internal:5432"}, {Name: "password", Type: "secret-reference", SecretReference: "external-secret://4so-resource-system/orders-db-password"}}
	normalized, digest, err := NormalizeManagedResourceOutputs(typeDef, instance, values); if err != nil { t.Fatal(err) }
	if len(normalized) != 2 || digest == "" || normalized[1].Value != "" || normalized[1].SecretReference == "" { t.Fatalf("typed output normalization drift: %#v %s", normalized, digest) }
	wrongType := instance; wrongType.TypeID = "type-2"
	if _, _, err := NormalizeManagedResourceOutputs(typeDef, wrongType, values); err == nil { t.Fatal("same digest with different type identity must be rejected") }
	if _, _, err := NormalizeManagedResourceOutputs(typeDef, instance, []ManagedResourceOutputValue{{Name: "endpoint", Type: "endpoint", Value: "postgres://db.internal:5432"}, {Name: "password", Type: "secret-reference", Value: "plaintext-secret"}}); err == nil { t.Fatal("sensitive output value must never be admitted") }
}

func TestManagedResourceOperationUnknownOutcomeRequiresReadbackRecovery(t *testing.T) {
	plan := ManagedResourcePlan{Authority: ResourceRequestPlanAuthority, ProjectID: "project-a", TypeID: "type-1", TypeDigest: testMRDigest('a'), Name: "orders-db", InputDigest: testMRDigest('b')}
	plan.PlanDigest = managedResourcePlanDigest(plan)
	op, err := NewManagedResourceOperation(plan, "mri_1", 4, "op-1", "idem-1", 9, ManagedResourceProvision); if err != nil { t.Fatal(err) }
	unknown := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, ManagedResourceReadback{})
	if unknown.State != ManagedResourceRecoveryRequired || !unknown.RecoveryRequired || unknown.RetryAllowed { t.Fatalf("unknown external outcome must require recovery without replay: %#v", unknown) }
	resolved := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, ManagedResourceReadback{Observed: true, OperationID: op.OperationID, FenceToken: op.FenceToken, PlanDigest: op.PlanDigest, InstanceID: "mri_1", Revision: 5, State: ManagedResourceReady, ObservedDigest: testMRDigest('d'), EvidenceDigest: testMRDigest('e')})
	if resolved.State != ManagedResourceReady || resolved.RecoveryRequired || resolved.EvidenceDigest == "" { t.Fatalf("matching authoritative readback must resolve unknown provision: %#v", resolved) }
	stale := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, ManagedResourceReadback{Observed: true, OperationID: op.OperationID, FenceToken: op.FenceToken, PlanDigest: op.PlanDigest, InstanceID: "mri_1", Revision: 4, State: ManagedResourceReady, ObservedDigest: testMRDigest('d'), EvidenceDigest: testMRDigest('e')})
	if stale.State != ManagedResourceRecoveryRequired { t.Fatalf("stale readback must not resolve ambiguous outcome: %#v", stale) }
}

func TestManagedResourceBindingIsSameProjectAndBoundToExactOutputsDigest(t *testing.T) {
	values := []ManagedResourceOutputValue{{Name: "endpoint", Type: "endpoint", Value: "postgres://db.internal:5432"}, {Name: "password", Type: "secret-reference", SecretReference: "external-secret://4so-resource-system/orders-db-password"}}
	instance := ManagedResourceInstance{ResourceMeta: ResourceMeta{ID: "mri_1", Revision: 7}, Authority: ManagedResourceInstanceAuthority, ProjectID: "project-a", TypeID: "type-1", TypeDigest: testMRDigest('a'), Name: "orders-db", State: ManagedResourceReady}
	instance.OutputsDigest = managedResourceOutputValuesDigest(instance, values)
	env := EnvironmentBinding{ResourceMeta: ResourceMeta{ID: "env_1", Revision: 2}, ProjectID: "project-a", ReleaseID: "rel_1", WorkspaceID: "ws_1", WorkspaceBindingID: "wsb_1", ClusterID: "cluster-a", Namespace: "orders", Environment: "prod", Digest: testMRDigest('c')}
	binding, err := BuildManagedResourceBinding(instance, env, []string{"endpoint", "password"}, values); if err != nil { t.Fatal(err) }
	if binding.Authority != ResourceOutputBindingAuthority || binding.ProjectID != "project-a" || binding.Digest == "" || len(binding.OutputNames) != 2 { t.Fatalf("managed resource binding drift: %#v", binding) }
	tampered := append([]ManagedResourceOutputValue(nil), values...); tampered[0].Value = "postgres://attacker.invalid:5432"
	if _, err := BuildManagedResourceBinding(instance, env, []string{"endpoint"}, tampered); err == nil { t.Fatal("binding must reject values that do not match instance outputs digest") }
	env.ProjectID = "project-b"
	if _, err := BuildManagedResourceBinding(instance, env, []string{"endpoint"}, values); err == nil { t.Fatal("cross-project managed resource binding must fail closed") }
}

func testMRDigest(ch byte) string { buf := make([]byte, 64); for i := range buf { buf[i] = ch }; return "sha256:" + string(buf) }
