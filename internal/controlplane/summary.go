package controlplane

// ControlPlaneSummaryCounts is the bounded aggregate view used by the operator
// dashboard. Runtime stores should calculate it without materializing the full
// canonical snapshot, because snapshot payloads include append-only history and
// sealed evidence bytes that grow independently of dashboard cardinalities.
type ControlPlaneSummaryCounts struct {
	Organizations           int
	Projects                int
	BlueprintRevisions      int
	Assignments             int
	Operations              int
	OperationStates         map[OperationState]int
	UnpublishedOutbox       int
	AuditEvents             int
	Evidence                int
	ClusterImports          int
	ManagedClusters         int
	BaselineDeployments     int
	RuntimeVerifications    int
	RuntimeClosureCampaigns int
	Entitlements            int
	OEMProfiles             int
	Tenants                 int
	ProviderProfiles        int
	ProviderClusters        int
}
