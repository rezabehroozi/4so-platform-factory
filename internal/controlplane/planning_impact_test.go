package controlplane

import (
	"strings"
	"testing"
)

func impactInventory() ClusterInventory {
	inv := ClusterInventory{
		Distribution:            "rke2",
		KubernetesVersion:       "v1.34.1+rke2r1",
		Nodes:                   []ClusterNode{{Name: "worker-1", Architecture: "amd64", Ready: true}},
		Capacity:                ClusterCapacity{CPUAllocatableMilli: 8000, MemoryAllocatableBytes: 16 << 30, PodsAllocatable: 110},
		Networking:              ClusterNetworking{CNI: "cilium"},
		Capabilities:            []string{"read-only-inventory", "controlled-baseline-deployment", "cni-inventory", "runtime-probe-image-digest-pinned"},
		APIDiscoveryComplete:    true,
		CRDDiscoveryComplete:    true,
		SchemaDiscoveryVersion:  "OPENAPI_V3",
		SchemaDiscoveryDigest:   "sha256:" + strings.Repeat("8", 64),
		SchemaDiscoveryComplete: true,
		APIResources: []ClusterAPIResourceObservation{
			{APIVersion: "v1", Version: "v1", Kind: "ResourceQuota", Resource: "resourcequotas", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
			{APIVersion: "v1", Version: "v1", Kind: "LimitRange", Resource: "limitranges", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
			{APIVersion: "v1", Version: "v1", Kind: "ServiceAccount", Resource: "serviceaccounts", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
			{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
			{APIVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
			{APIVersion: "apps/v1", Group: "apps", Version: "v1", Kind: "Deployment", Resource: "deployments", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
		},
	}
	inv.Digest = ClusterInventoryDigest(inv)
	return inv
}

func impactSchemaEvidence(resources []BaselineTaskResource, inv ClusterInventory) map[string]PlanSchemaCompatibility {
	out := make(map[string]PlanSchemaCompatibility, len(resources))
	for _, r := range resources {
		out[r.Kind+"/"+r.Name] = PlanSchemaCompatibility{Status: "PASS", Method: PlanSchemaValidationMethod, HTTPStatus: 200, SchemaIndexVersion: inv.SchemaDiscoveryVersion, SchemaIndexDigest: inv.SchemaDiscoveryDigest}
	}
	return out
}

func impactRollbackEvidence(resources []BaselineTaskResource, changes []BaselinePlanChange, inv ClusterInventory) map[string]PlanRollbackResource {
	changeByResource := map[string]BaselinePlanChange{}
	for _, change := range changes {
		changeByResource[change.Resource] = change
	}
	out := make(map[string]PlanRollbackResource, len(resources))
	for _, r := range resources {
		key := r.Kind + "/" + r.Name
		change, ok := changeByResource[key]
		if !ok {
			change = BaselinePlanChange{Resource: key, Action: "NOOP"}
		}
		item := PlanRollbackResource{Resource: key, ChangeAction: change.Action, Status: "PASS", SchemaIndexVersion: inv.SchemaDiscoveryVersion, SchemaIndexDigest: inv.SchemaDiscoveryDigest}
		switch strings.ToUpper(change.Action) {
		case "NOOP":
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus = "NO_ACTION", "NOT_REQUIRED", "NOT_REQUIRED"
			item.ObservedUID = "uid-" + strings.ToLower(r.Kind) + "-" + r.Name
			item.ObservedObjectDigest = "sha256:" + strings.Repeat("a", 64)
		case "ADD":
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus = "DELETE_CREATED_RESOURCE", "PASS", "NOT_APPLICABLE"
		default:
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus, item.HTTPStatus = "RESTORE_PREIMAGE", "PASS", "PASS", 200
			item.ObservedUID = "uid-" + strings.ToLower(r.Kind) + "-" + r.Name
			restore := map[string]any{"apiVersion": r.APIVersion, "kind": r.Kind, "metadata": map[string]any{"name": r.Name, "namespace": r.Namespace}}
			item.RestoreObject = restore
			item.ObservedObjectDigest = RollbackRestoreObjectDigest(restore)
			item.RestoreObjectDigest = item.ObservedObjectDigest
		}
		out[key] = item
	}
	return out
}

func TestPlanningImpactUsesLiveAPISurfaceAndDisruptionEstimate(t *testing.T) {
	inv := impactInventory()
	resources := []BaselineTaskResource{
		{APIVersion: "v1", Kind: "ResourceQuota", Name: "quota", Object: map[string]any{"spec": map[string]any{"hard": map[string]any{"requests.cpu": "4", "requests.memory": "8Gi"}}}},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Name: "deny", Object: map[string]any{"spec": map[string]any{}}},
	}
	changes := []BaselinePlanChange{{Resource: "ResourceQuota/quota", Action: "ADD"}, {Resource: "NetworkPolicy/deny", Action: "ADD"}}
	impact := AnalyzePlanningImpactWithSchema(resources, map[string]map[string]any{}, changes, inv, impactSchemaEvidence(resources, inv), impactRollbackEvidence(resources, changes, inv))
	if !impact.ApprovalReady || impact.Digest == "" || impact.InventoryDigest != inv.Digest {
		t.Fatalf("impact=%+v", impact)
	}
	if impact.Disruption.Level != "MEDIUM" || impact.Disruption.MaintenanceRecommendation != "RECOMMENDED" {
		t.Fatalf("disruption=%+v", impact.Disruption)
	}
	if impact.Capacity.WorkloadResources != 0 || impact.Capacity.CeilingCheck != "NOT_APPLICABLE" || len(impact.Capacity.QuotaImpacts) != 1 {
		t.Fatalf("capacity=%+v", impact.Capacity)
	}
	if err := ValidatePlanningImpact(impact, inv.Digest, changes); err != nil {
		t.Fatal(err)
	}
	impact.Warnings = append(impact.Warnings, "tampered")
	if err := ValidatePlanningImpact(impact, inv.Digest, changes); err == nil {
		t.Fatal("tampered impact digest accepted")
	}
}

func TestPlanningImpactBlocksRemovedAPIAndUnknownDiscovery(t *testing.T) {
	inv := impactInventory()
	resources := []BaselineTaskResource{{APIVersion: "networking.k8s.io/v1beta1", Kind: "Ingress", Name: "legacy", Object: map[string]any{}}}
	changes := []BaselinePlanChange{{Resource: "Ingress/legacy", Action: "ADD"}}
	impact := AnalyzePlanningImpactWithSchema(resources, nil, changes, inv, impactSchemaEvidence(resources, inv), impactRollbackEvidence(resources, changes, inv))
	if impact.ApprovalReady || len(impact.Blockers) == 0 || impact.API[0].LifecycleStatus != "REMOVED_UPSTREAM" {
		t.Fatalf("removed api was not blocked: %+v", impact)
	}
	inv.APIDiscoveryComplete = false
	inv.APIResources = nil
	inv.Digest = ClusterInventoryDigest(inv)
	resources = []BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Name: "x", Object: map[string]any{}}}
	changes = []BaselinePlanChange{{Resource: "ConfigMap/x", Action: "ADD"}}
	impact = AnalyzePlanningImpactWithSchema(resources, nil, changes, inv, impactSchemaEvidence(resources, inv), impactRollbackEvidence(resources, changes, inv))
	if impact.ApprovalReady || !strings.Contains(strings.Join(impact.Blockers, " "), "discovery") {
		t.Fatalf("unknown discovery not blocked: %+v", impact)
	}
}

func TestPlanningImpactCRDAndWorkloadCapacity(t *testing.T) {
	inv := impactInventory()
	inv.APIResources = append(inv.APIResources, ClusterAPIResourceObservation{APIVersion: "widgets.example.io/v1", Group: "widgets.example.io", Version: "v1", Kind: "Widget", Resource: "widgets", Namespaced: true})
	inv.CRDs = []ClusterCRDObservation{{Name: "widgets.widgets.example.io", Group: "widgets.example.io", Kind: "Widget", Plural: "widgets", Scope: "Namespaced", Versions: []ClusterCRDVersionObservation{{Name: "v1", Served: true, Storage: true}}}}
	inv.Nodes = []ClusterNode{{Name: "n1", Architecture: "amd64", Ready: true}}
	inv.Digest = ClusterInventoryDigest(inv)
	custom := BaselineTaskResource{APIVersion: "widgets.example.io/v1", Kind: "Widget", Name: "w1", Object: map[string]any{}}
	deployment := BaselineTaskResource{APIVersion: "apps/v1", Kind: "Deployment", Name: "api", Object: map[string]any{"spec": map[string]any{"replicas": float64(2), "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"resources": map[string]any{"requests": map[string]any{"cpu": "500m", "memory": "256Mi"}}}}}}}}}
	changes := []BaselinePlanChange{{Resource: "Widget/w1", Action: "ADD"}, {Resource: "Deployment/api", Action: "ADD"}}
	impact := AnalyzePlanningImpactWithSchema([]BaselineTaskResource{custom, deployment}, nil, changes, inv, impactSchemaEvidence([]BaselineTaskResource{custom, deployment}, inv), impactRollbackEvidence([]BaselineTaskResource{custom, deployment}, changes, inv))
	if !impact.ApprovalReady || !impact.API[1].CustomResource && !impact.API[0].CustomResource {
		t.Fatalf("crd impact=%+v", impact.API)
	}
	if impact.Capacity.CPURequestDeltaMilli != 1000 || impact.Capacity.MemoryRequestDeltaBytes != 512<<20 || impact.Capacity.PodReplicaDelta != 2 || impact.Capacity.CeilingCheck != "PASS" {
		t.Fatalf("capacity=%+v", impact.Capacity)
	}
	inv.CRDs = nil
	inv.Digest = ClusterInventoryDigest(inv)
	impact = AnalyzePlanningImpactWithSchema([]BaselineTaskResource{custom}, nil, []BaselinePlanChange{{Resource: "Widget/w1", Action: "ADD"}}, inv, impactSchemaEvidence([]BaselineTaskResource{custom}, inv), impactRollbackEvidence([]BaselineTaskResource{custom}, []BaselinePlanChange{{Resource: "Widget/w1", Action: "ADD"}}, inv))
	if impact.ApprovalReady {
		t.Fatalf("missing CRD accepted: %+v", impact)
	}
}

func TestPlanningImpactRequiresStrictSchemaEvidenceAndRejectsSchemaBindingTamper(t *testing.T) {
	inv := impactInventory()
	resources := []BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Name: "x", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap"}}}
	changes := []BaselinePlanChange{{Resource: "ConfigMap/x", Action: "ADD"}}

	missing := AnalyzePlanningImpact(resources, nil, changes, inv)
	if missing.ApprovalReady || missing.API[0].Schema.Status != "NOT_EXECUTED" {
		t.Fatalf("schema-less plan unexpectedly approval ready: %+v", missing)
	}

	evidence := impactSchemaEvidence(resources, inv)
	impact := AnalyzePlanningImpactWithSchema(resources, nil, changes, inv, evidence, impactRollbackEvidence(resources, changes, inv))
	if !impact.ApprovalReady || !PlanningImpactSchemaReady(impact) {
		t.Fatalf("strict schema evidence did not make plan approval ready: %+v", impact)
	}
	if err := ValidatePlanningImpactSemantics(impact, inv, resources, changes); err != nil {
		t.Fatal(err)
	}

	impact.API[0].Schema.SchemaIndexDigest = "sha256:" + strings.Repeat("f", 64)
	impact.Digest = PlanningImpactDigest(impact)
	if err := ValidatePlanningImpactSemantics(impact, inv, resources, changes); err == nil {
		t.Fatal("tampered schema authority digest accepted")
	}
}

func TestCapabilityPreflightBindsRequiredDomainsAndRejectsTamper(t *testing.T) {
	inv := impactInventory()
	resources := []BaselineTaskResource{
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: "test", Name: "deny", Object: map[string]any{}},
	}
	preflight := AnalyzeCapabilityPreflight(resources, inv)
	if preflight.Status != "PASS" || preflight.Method != PlanCapabilityPreflightMethod || preflight.InventoryDigest != inv.Digest {
		t.Fatalf("preflight=%+v", preflight)
	}
	foundNetwork := false
	for _, check := range preflight.Checks {
		if check.Key == "network-policy-enforcement" {
			foundNetwork = true
			if !check.Required || check.Status != "PASS" || check.Authority != "KUBERNETES_DISCOVERY+CNI_INVENTORY" {
				t.Fatalf("network capability=%+v", check)
			}
		}
	}
	if !foundNetwork {
		t.Fatal("network capability check missing")
	}
	if err := ValidateCapabilityPreflightSemantics(preflight, inv, resources); err != nil {
		t.Fatal(err)
	}

	providerResources := []BaselineTaskResource{{APIVersion: "cluster.x-k8s.io/v1beta2", Kind: "Cluster", Namespace: "4so-provider-system", Name: "demo", Object: map[string]any{}}}
	blocked := AnalyzeCapabilityPreflight(providerResources, inv)
	if blocked.Status != "FAIL" {
		t.Fatalf("provider preflight must fail without Cluster API authority: %+v", blocked)
	}
	inv.APIResources = append(inv.APIResources,
		ClusterAPIResourceObservation{APIVersion: "cluster.x-k8s.io/v1beta2", Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "Cluster", Resource: "clusters", Namespaced: true, Verbs: []string{"get", "patch"}},
		ClusterAPIResourceObservation{APIVersion: "cluster.x-k8s.io/v1beta2", Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "ClusterClass", Resource: "clusterclasses", Namespaced: true, Verbs: []string{"get"}},
	)
	inv.Digest = ClusterInventoryDigest(inv)
	ready := AnalyzeCapabilityPreflight(providerResources, inv)
	if ready.Status != "PASS" {
		t.Fatalf("provider capability should pass with discovered v1beta2 API: %+v", ready)
	}

	tampered := ready
	tampered.Checks = append([]PlanCapabilityCheck(nil), ready.Checks...)
	tampered.Checks[0].Detail = "tampered capability claim"
	tampered.Digest = CapabilityPreflightDigest(tampered)
	if err := ValidateCapabilityPreflightSemantics(tampered, inv, providerResources); err == nil {
		t.Fatal("self-redigested capability tamper was accepted")
	}
}

func TestCapabilityPreflightRequiredRuntimeDomains(t *testing.T) {
	inv := impactInventory()
	resources := []BaselineTaskResource{
		{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: "test", Name: "data", Object: map[string]any{}},
		{APIVersion: "snapshot.storage.k8s.io/v1", Kind: "VolumeSnapshot", Namespace: "test", Name: "snap", Object: map[string]any{}},
		{APIVersion: "velero.io/v1", Kind: "Schedule", Namespace: "velero", Name: "backup", Object: map[string]any{}},
		{APIVersion: "monitoring.coreos.com/v1", Kind: "ServiceMonitor", Namespace: "test", Name: "metrics", Object: map[string]any{}},
		{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Namespace: "test", Name: "edge", Object: map[string]any{}},
	}
	blocked := AnalyzeCapabilityPreflight(resources, inv)
	if blocked.Status != "FAIL" {
		t.Fatalf("preflight must fail when required runtime adapters are absent: %+v", blocked)
	}
	failed := map[string]bool{}
	for _, check := range blocked.Checks {
		if check.Required && check.Status == "FAIL" {
			failed[check.Key] = true
		}
	}
	for _, key := range []string{"storage-runtime", "snapshot-runtime", "backup-runtime", "observability-runtime", "gateway-api-runtime"} {
		if !failed[key] {
			t.Fatalf("required missing capability %s was not a blocker: %+v", key, blocked.Checks)
		}
	}

	inv.StorageClasses = []ClusterStorageClass{{Name: "replicated", Provisioner: "csi.example.io", Default: true}}
	inv.Networking.GatewayAPI = true
	inv.Capabilities = append(inv.Capabilities,
		"storage-class-inventory",
		"storage-backup-adapter-auto-discovered",
		"cert.snapshot", "cert.backup", "cert.restore",
		"cert.metrics", "cert.logs", "cert.alerts",
		"gateway-api",
	)
	inv.APIResources = append(inv.APIResources,
		ClusterAPIResourceObservation{APIVersion: "gateway.networking.k8s.io/v1", Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway", Resource: "gateways", Namespaced: true, Verbs: []string{"get", "patch"}},
	)
	inv.Digest = ClusterInventoryDigest(inv)
	ready := AnalyzeCapabilityPreflight(resources, inv)
	if ready.Status != "PASS" {
		t.Fatalf("all required runtime capability domains should pass: %+v", ready)
	}
	for _, check := range ready.Checks {
		if check.Required && check.Status != "PASS" {
			t.Fatalf("required capability did not pass: %+v", check)
		}
	}
}
