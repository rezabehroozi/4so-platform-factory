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

	plan.ProjectID = "project-b"
	if _, err := NewManagedResourceOperation(plan, "mri_1", 4, "op-1", "idem-1", 9, ManagedResourceProvision); err == nil {
		t.Fatal("managed resource operation must reject plan content changed after its digest was sealed")
	}
}
