package controlplane

func managedResourcePlanDigest(plan ManagedResourcePlan) string {
	return digestApplicationPlatformMaterial(struct {
		Authority             string                              `json:"authority"`
		ProjectID             string                              `json:"projectId"`
		TypeID                string                              `json:"typeId"`
		TypeDigest            string                              `json:"typeDigest"`
		Name                  string                              `json:"name"`
		InputDigest           string                              `json:"inputDigest"`
		Provisioner           string                              `json:"provisioner"`
		DeletePolicy          string                              `json:"deletePolicy"`
		DependencyInstanceIDs []string                            `json:"dependencyInstanceIds,omitempty"`
		DependencySnapshots   []ManagedResourceDependencySnapshot `json:"dependencySnapshots,omitempty"`
		OutputSchema          []ManagedResourceOutput             `json:"outputSchema"`
	}{
		plan.Authority,
		plan.ProjectID,
		plan.TypeID,
		plan.TypeDigest,
		plan.Name,
		plan.InputDigest,
		plan.Provisioner,
		plan.DeletePolicy,
		plan.DependencyInstanceIDs,
		plan.DependencySnapshots,
		plan.OutputSchema,
	})
}
