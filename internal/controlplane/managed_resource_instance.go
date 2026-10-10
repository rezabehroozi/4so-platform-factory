package controlplane

import (
	"fmt"
	"sort"
	"strings"
)

const (
	ManagedResourceInstanceAuthority = "MANAGED_RESOURCE_INSTANCE_AUTHORITY_V1"
	ResourceRequestPlanAuthority     = "RESOURCE_REQUEST_PLAN_AUTHORITY_V1"
	ResourceDependencyGraphAuthority = "RESOURCE_DEPENDENCY_GRAPH_AUTHORITY_V1"
	ResourceProvisionOperationAuthority = "RESOURCE_PROVISION_OPERATION_AUTHORITY_V1"
	ResourceOutputBindingAuthority   = "RESOURCE_OUTPUT_BINDING_AUTHORITY_V1"
)

type ManagedResourceState string

const (
	ManagedResourceRequested        ManagedResourceState = "REQUESTED"
	ManagedResourceProvisioning     ManagedResourceState = "PROVISIONING"
	ManagedResourceReady            ManagedResourceState = "READY"
	ManagedResourceDeleting         ManagedResourceState = "DELETING"
	ManagedResourceRetained         ManagedResourceState = "RETAINED"
	ManagedResourceDeleted          ManagedResourceState = "DELETED"
	ManagedResourceRecoveryRequired ManagedResourceState = "RECOVERY_REQUIRED"
	ManagedResourceFailed           ManagedResourceState = "FAILED"
)

type ManagedResourceRequest struct {
	ProjectID             string   `json:"projectId"`
	TypeID                string   `json:"typeId"`
	Name                  string   `json:"name"`
	InputDigest           string   `json:"inputDigest"`
	DependencyInstanceIDs []string `json:"dependencyInstanceIds,omitempty"`
}

type ManagedResourceDependencySnapshot struct {
	InstanceID     string `json:"instanceId"`
	Revision       int64  `json:"revision"`
	ObservedDigest string `json:"observedDigest"`
}

type ManagedResourcePlan struct {
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
	PlanDigest            string                              `json:"planDigest"`
}

type ManagedResourceInstance struct {
	ResourceMeta
	Authority             string               `json:"authority"`
	ProjectID             string               `json:"projectId"`
	TypeID                string               `json:"typeId"`
	TypeDigest            string               `json:"typeDigest"`
	Name                  string               `json:"name"`
	InputDigest           string               `json:"inputDigest,omitempty"`
	PlanDigest            string               `json:"planDigest,omitempty"`
	DependencyInstanceIDs []string             `json:"dependencyInstanceIds,omitempty"`
	State                 ManagedResourceState `json:"state"`
	OutputsDigest         string               `json:"outputsDigest,omitempty"`
	ObservedDigest        string               `json:"observedDigest,omitempty"`
	LastEvidenceDigest    string               `json:"lastEvidenceDigest,omitempty"`
	LastError             string               `json:"lastError,omitempty"`
}

func BuildManagedResourcePlan(resourceType ManagedResourceType, request ManagedResourceRequest, dependencies []ManagedResourceInstance) (ManagedResourcePlan, error) {
	if strings.TrimSpace(resourceType.ID) == "" {
		return ManagedResourcePlan{}, fmt.Errorf("%w: managed resource type id is required", ErrValidation)
	}
	normalizedType, err := NormalizeManagedResourceType(resourceType)
	if err != nil {
		return ManagedResourcePlan{}, err
	}
	normalizedType.ID = strings.TrimSpace(resourceType.ID)
	request.ProjectID = strings.TrimSpace(request.ProjectID)
	request.TypeID = strings.TrimSpace(request.TypeID)
	request.Name = normalizeName(request.Name)
	request.InputDigest = strings.TrimSpace(request.InputDigest)
	if request.ProjectID == "" || request.ProjectID != normalizedType.ProjectID || request.TypeID != normalizedType.ID || !variableNamePattern.MatchString(request.Name) {
		return ManagedResourcePlan{}, fmt.Errorf("%w: managed resource request scope/type/name is invalid", ErrValidation)
	}
	if err := requireApplicationDigest("inputDigest", request.InputDigest); err != nil {
		return ManagedResourcePlan{}, err
	}
	requestedDeps, err := canonicalOpaqueIDs(request.DependencyInstanceIDs, "dependencyInstanceIds")
	if err != nil {
		return ManagedResourcePlan{}, err
	}
	provided := map[string]ManagedResourceInstance{}
	for _, dep := range dependencies {
		id := strings.TrimSpace(dep.ID)
		if id == "" || provided[id].ID != "" {
			return ManagedResourcePlan{}, fmt.Errorf("%w: dependency instances contain empty/duplicate identity", ErrValidation)
		}
		provided[id] = dep
	}
	if len(provided) != len(requestedDeps) {
		return ManagedResourcePlan{}, fmt.Errorf("%w: dependency instance set does not exactly match request", ErrValidation)
	}
	snapshots := make([]ManagedResourceDependencySnapshot, 0, len(requestedDeps))
	for _, id := range requestedDeps {
		dep, ok := provided[id]
		if !ok || dep.Authority != ManagedResourceInstanceAuthority || dep.ProjectID != request.ProjectID || dep.State != ManagedResourceReady || dep.Revision <= 0 {
			return ManagedResourcePlan{}, fmt.Errorf("%w: dependency %q is absent, cross-project, non-ready or unauthoritative", ErrValidation, id)
		}
		if err := requireApplicationDigest("dependency.observedDigest", dep.ObservedDigest); err != nil {
			return ManagedResourcePlan{}, err
		}
		snapshots = append(snapshots, ManagedResourceDependencySnapshot{InstanceID: id, Revision: dep.Revision, ObservedDigest: dep.ObservedDigest})
	}
	plan := ManagedResourcePlan{
		Authority: ResourceRequestPlanAuthority, ProjectID: request.ProjectID, TypeID: normalizedType.ID,
		TypeDigest: normalizedType.Digest, Name: request.Name, InputDigest: request.InputDigest,
		Provisioner: normalizedType.Provisioner, DeletePolicy: normalizedType.DeletePolicy,
		DependencyInstanceIDs: requestedDeps, DependencySnapshots: snapshots,
		OutputSchema: append([]ManagedResourceOutput(nil), normalizedType.Outputs...),
	}
	plan.PlanDigest = digestApplicationPlatformMaterial(struct {
		Authority             string                              `json:"authority"`
		ProjectID             string                              `json:"projectId"`
		TypeID                string                              `json:"typeId"`
		TypeDigest            string                              `json:"typeDigest"`
		Name                  string                              `json:"name"`
		InputDigest           string                              `json:"inputDigest"`
		Provisioner           string                              `json:"provisioner"`
		DeletePolicy          string                              `json:"deletePolicy"`
		DependencySnapshots   []ManagedResourceDependencySnapshot `json:"dependencySnapshots,omitempty"`
		OutputSchema          []ManagedResourceOutput             `json:"outputSchema"`
	}{plan.Authority, plan.ProjectID, plan.TypeID, plan.TypeDigest, plan.Name, plan.InputDigest, plan.Provisioner, plan.DeletePolicy, plan.DependencySnapshots, plan.OutputSchema})
	return plan, nil
}

func canonicalOpaqueIDs(values []string, field string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || seen[value] {
			return nil, fmt.Errorf("%w: %s contains empty or duplicate identity", ErrValidation, field)
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

type ManagedResourceDependency struct {
	FromInstanceID string `json:"fromInstanceId"`
	ToInstanceID   string `json:"toInstanceId"`
}

type ManagedResourceDependencyGraph struct {
	Authority string                      `json:"authority"`
	ProjectID string                      `json:"projectId"`
	Edges     []ManagedResourceDependency `json:"edges"`
	Digest    string                      `json:"digest"`
}

func BuildManagedResourceDependencyGraph(projectID string, instances []ManagedResourceInstance, edges []ManagedResourceDependency) (ManagedResourceDependencyGraph, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return ManagedResourceDependencyGraph{}, fmt.Errorf("%w: dependency graph projectId is required", ErrValidation)
	}
	known := map[string]bool{}
	for _, instance := range instances {
		id := strings.TrimSpace(instance.ID)
		if id == "" || known[id] || instance.Authority != ManagedResourceInstanceAuthority || instance.ProjectID != projectID {
			return ManagedResourceDependencyGraph{}, fmt.Errorf("%w: dependency graph instance set is invalid", ErrValidation)
		}
		known[id] = true
	}
	normalized := make([]ManagedResourceDependency, 0, len(edges))
	seen := map[string]bool{}
	adj := map[string][]string{}
	for _, edge := range edges {
		edge.FromInstanceID = strings.TrimSpace(edge.FromInstanceID)
		edge.ToInstanceID = strings.TrimSpace(edge.ToInstanceID)
		if edge.FromInstanceID == "" || edge.ToInstanceID == "" || edge.FromInstanceID == edge.ToInstanceID || !known[edge.FromInstanceID] || !known[edge.ToInstanceID] {
			return ManagedResourceDependencyGraph{}, fmt.Errorf("%w: dependency graph edge is invalid", ErrValidation)
		}
		key := edge.FromInstanceID + "\x00" + edge.ToInstanceID
		if seen[key] {
			return ManagedResourceDependencyGraph{}, fmt.Errorf("%w: duplicate dependency graph edge", ErrValidation)
		}
		seen[key] = true
		normalized = append(normalized, edge)
		adj[edge.FromInstanceID] = append(adj[edge.FromInstanceID], edge.ToInstanceID)
	}
	state := map[string]uint8{}
	var visit func(string) bool
	visit = func(node string) bool {
		if state[node] == 1 { return false }
		if state[node] == 2 { return true }
		state[node] = 1
		for _, next := range adj[node] { if !visit(next) { return false } }
		state[node] = 2
		return true
	}
	for id := range known { if !visit(id) { return ManagedResourceDependencyGraph{}, fmt.Errorf("%w: managed resource dependency graph contains a cycle", ErrValidation) } }
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].FromInstanceID != normalized[j].FromInstanceID { return normalized[i].FromInstanceID < normalized[j].FromInstanceID }
		return normalized[i].ToInstanceID < normalized[j].ToInstanceID
	})
	graph := ManagedResourceDependencyGraph{Authority: ResourceDependencyGraphAuthority, ProjectID: projectID, Edges: normalized}
	graph.Digest = digestApplicationPlatformMaterial(graph)
	return graph, nil
}

type ManagedResourceOutputValue struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Value           string `json:"value,omitempty"`
	SecretReference string `json:"secretReference,omitempty"`
}

func NormalizeManagedResourceOutputs(resourceType ManagedResourceType, instance ManagedResourceInstance, values []ManagedResourceOutputValue) ([]ManagedResourceOutputValue, string, error) {
	normalizedType, err := NormalizeManagedResourceType(resourceType)
	if err != nil { return nil, "", err }
	if instance.Authority != ManagedResourceInstanceAuthority || instance.ProjectID != normalizedType.ProjectID || instance.TypeDigest != normalizedType.Digest || instance.State != ManagedResourceReady || instance.Revision <= 0 {
		return nil, "", fmt.Errorf("%w: managed resource instance/type output authority is invalid", ErrValidation)
	}
	defs := map[string]ManagedResourceOutput{}
	for _, def := range normalizedType.Outputs { defs[def.Name] = def }
	if len(values) != len(defs) { return nil, "", fmt.Errorf("%w: managed resource output set must exactly match type schema", ErrValidation) }
	seen := map[string]bool{}
	out := make([]ManagedResourceOutputValue, 0, len(values))
	for _, value := range values {
		value.Name = normalizeName(value.Name)
		value.Type = strings.ToLower(strings.TrimSpace(value.Type))
		value.Value = strings.TrimSpace(value.Value)
		value.SecretReference = strings.TrimSpace(value.SecretReference)
		def, ok := defs[value.Name]
		if !ok || seen[value.Name] || value.Type != def.Type { return nil, "", fmt.Errorf("%w: managed resource output value does not match schema", ErrValidation) }
		seen[value.Name] = true
		if def.SecretReference || def.Sensitive {
			if value.Value != "" || !strings.HasPrefix(value.SecretReference, "external-secret://") || len(value.SecretReference) <= len("external-secret://") {
				return nil, "", fmt.Errorf("%w: sensitive output %q must contain only an external secret reference", ErrValidation, value.Name)
			}
		} else {
			if value.Value == "" || value.SecretReference != "" { return nil, "", fmt.Errorf("%w: non-secret output %q requires value and forbids secret reference", ErrValidation, value.Name) }
		}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	digest := digestApplicationPlatformMaterial(struct {
		Authority string                       `json:"authority"`
		InstanceID string                      `json:"instanceId"`
		Revision int64                         `json:"revision"`
		Values []ManagedResourceOutputValue    `json:"values"`
	}{ResourceOutputBindingAuthority, instance.ID, instance.Revision, out})
	return out, digest, nil
}

type ManagedResourceAction string
const (
	ManagedResourceProvision ManagedResourceAction = "PROVISION"
	ManagedResourceDelete    ManagedResourceAction = "DELETE"
)

type ManagedResourceOutcome string
const (
	ManagedResourceOutcomeApplied ManagedResourceOutcome = "APPLIED"
	ManagedResourceOutcomePending ManagedResourceOutcome = "PENDING"
	ManagedResourceOutcomeUnknown ManagedResourceOutcome = "UNKNOWN"
	ManagedResourceOutcomeFailed  ManagedResourceOutcome = "FAILED"
)

type ManagedResourceOperation struct {
	Authority        string                `json:"authority"`
	OperationID      string                `json:"operationId"`
	InstanceID       string                `json:"instanceId"`
	ExpectedRevision int64                 `json:"expectedRevision"`
	IdempotencyKey   string                `json:"idempotencyKey"`
	FenceToken       int64                 `json:"fenceToken"`
	Action           ManagedResourceAction `json:"action"`
	ProjectID        string                `json:"projectId"`
	PlanDigest       string                `json:"planDigest"`
	DeletePolicy     string                `json:"deletePolicy,omitempty"`
}

type ManagedResourceReadback struct {
	Observed       bool                 `json:"observed"`
	InstanceID     string               `json:"instanceId"`
	Revision       int64                `json:"revision"`
	State          ManagedResourceState `json:"state"`
	ObservedDigest string               `json:"observedDigest"`
	EvidenceDigest string               `json:"evidenceDigest"`
}

type ManagedResourceOperationResult struct {
	State            ManagedResourceState `json:"state"`
	RecoveryRequired bool                 `json:"recoveryRequired"`
	RetryAllowed     bool                 `json:"retryAllowed"`
	ObservedDigest   string               `json:"observedDigest,omitempty"`
	EvidenceDigest   string               `json:"evidenceDigest,omitempty"`
	Message          string               `json:"message,omitempty"`
}

func NewManagedResourceOperation(plan ManagedResourcePlan, instanceID string, expectedRevision int64, operationID, idempotencyKey string, fenceToken int64, action ManagedResourceAction) (ManagedResourceOperation, error) {
	instanceID = strings.TrimSpace(instanceID); operationID = strings.TrimSpace(operationID); idempotencyKey = strings.TrimSpace(idempotencyKey)
	if plan.Authority != ResourceRequestPlanAuthority || !applicationPlatformDigestPattern.MatchString(plan.PlanDigest) || instanceID == "" || expectedRevision <= 0 || operationID == "" || idempotencyKey == "" || fenceToken <= 0 {
		return ManagedResourceOperation{}, fmt.Errorf("%w: managed resource operation authority/identity/fence is incomplete", ErrValidation)
	}
	if action != ManagedResourceProvision && action != ManagedResourceDelete { return ManagedResourceOperation{}, fmt.Errorf("%w: unsupported managed resource action %q", ErrValidation, action) }
	return ManagedResourceOperation{Authority: ResourceProvisionOperationAuthority, OperationID: operationID, InstanceID: instanceID, ExpectedRevision: expectedRevision, IdempotencyKey: idempotencyKey, FenceToken: fenceToken, Action: action, ProjectID: plan.ProjectID, PlanDigest: plan.PlanDigest, DeletePolicy: plan.DeletePolicy}, nil
}

func ResolveManagedResourceOutcome(op ManagedResourceOperation, outcome ManagedResourceOutcome, readback ManagedResourceReadback) ManagedResourceOperationResult {
	if op.Authority != ResourceProvisionOperationAuthority || op.FenceToken <= 0 || !applicationPlatformDigestPattern.MatchString(op.PlanDigest) {
		return ManagedResourceOperationResult{State: ManagedResourceFailed, Message: "managed resource operation authority is invalid"}
	}
	converged := managedResourceReadbackConverged(op, readback)
	switch outcome {
	case ManagedResourceOutcomeUnknown:
		if converged { return ManagedResourceOperationResult{State: readback.State, ObservedDigest: readback.ObservedDigest, EvidenceDigest: readback.EvidenceDigest, Message: "ambiguous managed resource mutation resolved by authoritative readback"} }
		return ManagedResourceOperationResult{State: ManagedResourceRecoveryRequired, RecoveryRequired: true, RetryAllowed: false, Message: "managed resource mutation outcome is ambiguous; authoritative readback is required"}
	case ManagedResourceOutcomeApplied:
		if converged { return ManagedResourceOperationResult{State: readback.State, ObservedDigest: readback.ObservedDigest, EvidenceDigest: readback.EvidenceDigest} }
		if op.Action == ManagedResourceDelete { return ManagedResourceOperationResult{State: ManagedResourceDeleting, Message: "delete accepted; authoritative readback has not converged"} }
		return ManagedResourceOperationResult{State: ManagedResourceProvisioning, Message: "provision accepted; authoritative readback has not converged"}
	case ManagedResourceOutcomePending:
		if op.Action == ManagedResourceDelete { return ManagedResourceOperationResult{State: ManagedResourceDeleting} }
		return ManagedResourceOperationResult{State: ManagedResourceProvisioning}
	case ManagedResourceOutcomeFailed:
		return ManagedResourceOperationResult{State: ManagedResourceFailed, RetryAllowed: false, Message: "managed resource mutation failed"}
	default:
		return ManagedResourceOperationResult{State: ManagedResourceFailed, Message: "unsupported managed resource outcome"}
	}
}

func managedResourceReadbackConverged(op ManagedResourceOperation, readback ManagedResourceReadback) bool {
	if !readback.Observed || strings.TrimSpace(readback.InstanceID) != op.InstanceID || readback.Revision <= op.ExpectedRevision || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(readback.ObservedDigest)) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(readback.EvidenceDigest)) { return false }
	if op.Action == ManagedResourceProvision { return readback.State == ManagedResourceReady }
	if op.Action == ManagedResourceDelete {
		if op.DeletePolicy == "retain" { return readback.State == ManagedResourceRetained }
		return readback.State == ManagedResourceDeleted
	}
	return false
}

type ManagedResourceBinding struct {
	Authority            string   `json:"authority"`
	ProjectID            string   `json:"projectId"`
	InstanceID           string   `json:"instanceId"`
	InstanceRevision     int64    `json:"instanceRevision"`
	EnvironmentBindingID string   `json:"environmentBindingId"`
	EnvironmentDigest    string   `json:"environmentDigest"`
	OutputNames          []string `json:"outputNames"`
	OutputsDigest        string   `json:"outputsDigest"`
	Digest               string   `json:"digest"`
}

func BuildManagedResourceBinding(instance ManagedResourceInstance, environment EnvironmentBinding, outputNames []string, values []ManagedResourceOutputValue) (ManagedResourceBinding, error) {
	if instance.Authority != ManagedResourceInstanceAuthority || instance.State != ManagedResourceReady || instance.ProjectID == "" || instance.ProjectID != environment.ProjectID || instance.Revision <= 0 || !applicationPlatformDigestPattern.MatchString(instance.OutputsDigest) || !applicationPlatformDigestPattern.MatchString(environment.Digest) {
		return ManagedResourceBinding{}, fmt.Errorf("%w: managed resource/environment binding authority is invalid or cross-project", ErrValidation)
	}
	requested, err := canonicalApplicationTokens(outputNames, 1, 64, "outputNames")
	if err != nil { return ManagedResourceBinding{}, err }
	available := map[string]bool{}
	for _, value := range values { available[normalizeName(value.Name)] = true }
	for _, name := range requested { if !available[name] { return ManagedResourceBinding{}, fmt.Errorf("%w: requested output %q is absent", ErrValidation, name) } }
	binding := ManagedResourceBinding{Authority: ResourceOutputBindingAuthority, ProjectID: instance.ProjectID, InstanceID: instance.ID, InstanceRevision: instance.Revision, EnvironmentBindingID: environment.ID, EnvironmentDigest: environment.Digest, OutputNames: requested, OutputsDigest: instance.OutputsDigest}
	binding.Digest = digestApplicationPlatformMaterial(binding)
	return binding, nil
}
