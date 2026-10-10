package controlplane

import "testing"

func TestManagedResourceOperationRejectsTamperedPlanContentAddress(t *testing.T) {
	typeDef, err := NormalizeManagedResourceType(ManagedResourceType{
		ProjectID: "project-a",
		Name: "postgres",
		Version: "1.0.0",
		Category: "database",
		Provisioner: "product-api",
		InputSchemaDigest: testMRDigest('a'),
		DeletePolicy: "delete",
		ReadinessConditions: []string{"ready"},
		Outputs: []ManagedResourceOutput{{Name: "endpoint", Type: "endpoint"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	typeDef.ID = "type-1"
	plan, err := BuildManagedResourcePlan(typeDef, ManagedResourceRequest{
		ProjectID: "project-a",
		TypeID: typeDef.ID,
		Name: "orders-db",
		InputDigest: testMRDigest('b'),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	foreignScope := plan
	foreignScope.ProjectID = "project-b"
	if _, err := NewManagedResourceOperation(foreignScope, "mri_1", 4, "op-1", "idem-1", 9, ManagedResourceProvision); err == nil {
		t.Fatal("managed resource operation must reject plan content changed after its digest was sealed")
	}

	dependencyPlan := ManagedResourcePlan{
		Authority: ResourceRequestPlanAuthority,
		ProjectID: "project-a",
		TypeID: "type-1",
		TypeDigest: testMRDigest('a'),
		Name: "orders-db",
		InputDigest: testMRDigest('b'),
		Provisioner: "product-api",
		DeletePolicy: "delete",
		DependencyInstanceIDs: []string{"mri_dep"},
		DependencySnapshots: []ManagedResourceDependencySnapshot{{InstanceID: "mri_dep", Revision: 3, ObservedDigest: testMRDigest('c')}},
	}
	dependencyPlan.PlanDigest = managedResourcePlanDigest(dependencyPlan)
	tamperedDependencies := dependencyPlan
	tamperedDependencies.DependencyInstanceIDs = []string{"mri_other"}
	if _, err := NewManagedResourceOperation(tamperedDependencies, "mri_1", 4, "op-2", "idem-2", 10, ManagedResourceProvision); err == nil {
		t.Fatal("managed resource operation must reject dependency identities changed after plan sealing")
	}
}
