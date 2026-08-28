package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const PlanningImpactSchemaVersion = 6

const PlanSchemaValidationMethod = "KUBE_APISERVER_DRY_RUN_STRICT"
const PlanRollbackValidationMethod = "KUBE_ROLLBACK_FEASIBILITY_V1"
const PlanEvidenceCollectionMethod = "BASELINE_EVIDENCE_COLLECTION_V1"
const PlanCapabilityPreflightMethod = "CLUSTER_CAPABILITY_PREFLIGHT_V1"
const PlanEvidencePhasePostApply = "POST_APPLY"
const PlanEvidenceRetentionDays = 90

type apiLifecycleRule struct {
	APIVersion   string
	Kind         string
	DeprecatedIn string
	RemovedIn    string
	Replacement  string
}

// This is intentionally a small, explicit upstream Kubernetes removal table.
// Unknown APIs are not guessed; live discovery remains authoritative for served status.
var apiLifecycleRules = []apiLifecycleRule{
	{"extensions/v1beta1", "Ingress", "1.14", "1.22", "networking.k8s.io/v1"},
	{"networking.k8s.io/v1beta1", "Ingress", "1.19", "1.22", "networking.k8s.io/v1"},
	{"apps/v1beta1", "Deployment", "1.9", "1.16", "apps/v1"},
	{"apps/v1beta1", "StatefulSet", "1.9", "1.16", "apps/v1"},
	{"apps/v1beta2", "Deployment", "1.9", "1.16", "apps/v1"},
	{"apps/v1beta2", "StatefulSet", "1.9", "1.16", "apps/v1"},
	{"apps/v1beta2", "DaemonSet", "1.9", "1.16", "apps/v1"},
	{"apps/v1beta2", "ReplicaSet", "1.9", "1.16", "apps/v1"},
	{"policy/v1beta1", "PodSecurityPolicy", "1.21", "1.25", "Pod Security Admission"},
	{"policy/v1beta1", "PodDisruptionBudget", "1.21", "1.25", "policy/v1"},
	{"autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.22", "1.25", "autoscaling/v2"},
	{"autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "1.26", "autoscaling/v2"},
	{"batch/v1beta1", "CronJob", "1.21", "1.25", "batch/v1"},
	{"apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.16", "1.22", "apiextensions.k8s.io/v1"},
	{"admissionregistration.k8s.io/v1beta1", "MutatingWebhookConfiguration", "1.16", "1.22", "admissionregistration.k8s.io/v1"},
	{"admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration", "1.16", "1.22", "admissionregistration.k8s.io/v1"},
	{"rbac.authorization.k8s.io/v1beta1", "Role", "1.17", "1.22", "rbac.authorization.k8s.io/v1"},
	{"rbac.authorization.k8s.io/v1beta1", "ClusterRole", "1.17", "1.22", "rbac.authorization.k8s.io/v1"},
	{"rbac.authorization.k8s.io/v1beta1", "RoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"},
	{"rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"},
}

func PlanningImpactDigest(v BaselinePlanImpact) string {
	copy := v
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func RollbackFeasibilityDigest(v PlanRollbackFeasibility) string {
	copy := v
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func EvidenceCollectionPlanDigest(v PlanEvidenceCollection) string {
	copy := v
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func CapabilityPreflightDigest(v PlanCapabilityPreflight) string {
	copy := v
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func inventoryHasCapability(inv ClusterInventory, wanted string) bool {
	for _, capability := range inv.Capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func apiResourceHasVerbs(inv ClusterInventory, group, version, kind, resource string, verbs ...string) bool {
	for _, item := range inv.APIResources {
		if item.Group != group || item.Version != version || item.Kind != kind || item.Resource != resource {
			continue
		}
		for _, wanted := range verbs {
			found := false
			for _, verb := range item.Verbs {
				if verb == wanted {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

func planResourceDomains(resources []BaselineTaskResource) map[string]bool {
	out := map[string]bool{}
	for _, resource := range resources {
		group := ""
		if parts := strings.Split(resource.APIVersion, "/"); len(parts) > 1 {
			group = parts[0]
		}
		switch {
		case resource.Kind == "NetworkPolicy":
			out["network"] = true
		case resource.Kind == "PersistentVolumeClaim" || resource.Kind == "StatefulSet" || resource.Kind == "StorageClass":
			out["storage"] = true
		case resource.Kind == "VolumeSnapshot" || resource.Kind == "VolumeSnapshotClass" || resource.Kind == "VolumeSnapshotContent" || group == "snapshot.storage.k8s.io":
			out["storage"] = true
			out["snapshot"] = true
		case group == "velero.io" || resource.Kind == "Backup" || resource.Kind == "Restore" || resource.Kind == "Schedule" || resource.Kind == "BackupStorageLocation":
			out["backup"] = true
		case group == "gateway.networking.k8s.io" || resource.Kind == "Gateway" || resource.Kind == "HTTPRoute" || resource.Kind == "GRPCRoute":
			out["gateway"] = true
		case group == "cluster.x-k8s.io" || resource.Kind == "ClusterClass":
			out["provider"] = true
		case group == "monitoring.coreos.com" || group == "operator.victoriametrics.com" || group == "loki.grafana.com" || resource.Kind == "ServiceMonitor" || resource.Kind == "PodMonitor" || resource.Kind == "VMServiceScrape" || resource.Kind == "VMPodScrape" || resource.Kind == "VMRule":
			out["observability"] = true
		}
	}
	return out
}

func capabilityCheck(key, domain string, required, available bool, authority, impact, detail string, evidence ...string) PlanCapabilityCheck {
	status := "NOT_REQUIRED"
	if available {
		status = "AVAILABLE"
	}
	if required {
		if available {
			status = "PASS"
		} else {
			status = "FAIL"
		}
	}
	return PlanCapabilityCheck{Key: key, Domain: domain, Required: required, Status: status, Authority: authority, Impact: impact, Detail: detail, Evidence: uniqueSortedStrings(evidence)}
}

func AnalyzeCapabilityPreflight(resources []BaselineTaskResource, inv ClusterInventory) PlanCapabilityPreflight {
	domains := planResourceDomains(resources)
	checks := []PlanCapabilityCheck{}

	inventoryReady := strings.HasPrefix(inv.Digest, "sha256:") && inventoryHasCapability(inv, "read-only-inventory") && inv.APIDiscoveryComplete && inv.SchemaDiscoveryComplete
	checks = append(checks, capabilityCheck("inventory-authority", "core", true, inventoryReady, "CLUSTER_INVENTORY_DIGEST", "all plan capability decisions are bound to the same authenticated inventory snapshot", fmt.Sprintf("inventory=%s apiDiscovery=%t schemaDiscovery=%t", inv.Digest, inv.APIDiscoveryComplete, inv.SchemaDiscoveryComplete), inv.Digest, inv.SchemaDiscoveryDigest))

	baselineExecutor := inventoryHasCapability(inv, "controlled-baseline-deployment")
	checks = append(checks, capabilityCheck("baseline-execution", "core", true, baselineExecutor, "PLATFORM_AGENT_CAPABILITY", "the selected Agent must support the controlled baseline execution contract", "controlled-baseline-deployment capability is reported by the connected Agent", "controlled-baseline-deployment"))

	networkRequired := domains["network"]
	networkAPI := apiResourceHasVerbs(inv, "networking.k8s.io", "v1", "NetworkPolicy", "networkpolicies", "get", "patch")
	networkAvailable := strings.TrimSpace(inv.Networking.CNI) != "" && inventoryHasCapability(inv, "cni-inventory") && networkAPI
	checks = append(checks, capabilityCheck("network-policy-enforcement", "network", networkRequired, networkAvailable, "KUBERNETES_DISCOVERY+CNI_INVENTORY", "NetworkPolicy resources require a discovered CNI and served networking.k8s.io/v1 API", fmt.Sprintf("cni=%s networkPolicyAPI=%t", inv.Networking.CNI, networkAPI), "cni:"+inv.Networking.CNI, "api:networking.k8s.io/v1/NetworkPolicy"))

	storageRequired := domains["storage"]
	storageAvailable := len(inv.StorageClasses) > 0 && inventoryHasCapability(inv, "storage-class-inventory")
	storageEvidence := []string{}
	for _, class := range inv.StorageClasses {
		storageEvidence = append(storageEvidence, "storageClass:"+class.Name+"@"+class.Provisioner)
	}
	checks = append(checks, capabilityCheck("storage-runtime", "storage", storageRequired, storageAvailable, "KUBERNETES_STORAGECLASS_INVENTORY", "storage-consuming resources require an admitted StorageClass from the bound inventory", fmt.Sprintf("storageClasses=%d", len(inv.StorageClasses)), storageEvidence...))

	snapshotRequired := domains["snapshot"]
	snapshotAvailable := inventoryHasCapability(inv, "cert.snapshot") && inventoryHasCapability(inv, "storage-backup-adapter-auto-discovered")
	checks = append(checks, capabilityCheck("snapshot-runtime", "snapshot", snapshotRequired, snapshotAvailable, "STORAGE_BACKUP_ADAPTER_DISCOVERY", "snapshot resources require a discovered CSI VolumeSnapshotClass and executable snapshot adapter", "cert.snapshot is published only after matching storage/snapshot adapter discovery", "cert.snapshot", "storage-backup-adapter-auto-discovered"))

	backupRequired := domains["backup"]
	backupAvailable := inventoryHasCapability(inv, "cert.backup") && inventoryHasCapability(inv, "cert.restore") && inventoryHasCapability(inv, "storage-backup-adapter-auto-discovered")
	checks = append(checks, capabilityCheck("backup-runtime", "backup", backupRequired, backupAvailable, "STORAGE_BACKUP_ADAPTER_DISCOVERY", "backup/restore resources require an Available Velero BackupStorageLocation discovered by the Agent", "cert.backup + cert.restore are published only after Velero and storage adapter discovery", "cert.backup", "cert.restore", "storage-backup-adapter-auto-discovered"))

	observabilityRequired := domains["observability"]
	observabilityAvailable := inventoryHasCapability(inv, "cert.metrics") && inventoryHasCapability(inv, "cert.logs") && inventoryHasCapability(inv, "cert.alerts")
	checks = append(checks, capabilityCheck("observability-runtime", "observability", observabilityRequired, observabilityAvailable, "OBSERVABILITY_ADAPTER_DISCOVERY", "observability resources require executable metrics, logs and alerts adapters", "metrics/logs/alerts adapter endpoints are discovered or explicitly configured by the Agent", "cert.metrics", "cert.logs", "cert.alerts"))

	gatewayRequired := domains["gateway"]
	gatewayAvailable := inv.Networking.GatewayAPI && inventoryHasCapability(inv, "gateway-api") && apiResourceHasVerbs(inv, "gateway.networking.k8s.io", "v1", "Gateway", "gateways", "get", "patch")
	checks = append(checks, capabilityCheck("gateway-api-runtime", "gateway", gatewayRequired, gatewayAvailable, "KUBERNETES_DISCOVERY", "Gateway API resources require the v1 API surface on the target cluster", fmt.Sprintf("gatewayApi=%t", inv.Networking.GatewayAPI), "gateway.networking.k8s.io/v1"))

	providerRequired := domains["provider"]
	providerAvailable := apiResourceHasVerbs(inv, "cluster.x-k8s.io", "v1beta2", "Cluster", "clusters", "get", "patch") && apiResourceHasVerbs(inv, "cluster.x-k8s.io", "v1beta2", "ClusterClass", "clusterclasses", "get")
	checks = append(checks, capabilityCheck("provider-runtime", "provider", providerRequired, providerAvailable, "KUBERNETES_DISCOVERY", "provider lifecycle resources require the admitted Cluster API v1beta2 execution surface", fmt.Sprintf("clusterApiV1beta2=%t", providerAvailable), "cluster.x-k8s.io/v1beta2/Cluster", "cluster.x-k8s.io/v1beta2/ClusterClass"))

	probeRequired := storageRequired || snapshotRequired || backupRequired
	probeAvailable := inventoryHasCapability(inv, "runtime-probe-image-digest-pinned")
	checks = append(checks, capabilityCheck("runtime-probe-image", "runtime", probeRequired, probeAvailable, "PLATFORM_AGENT_CONFIGURATION", "executable storage/backup preflight requires the digest-pinned runtime probe image", "Agent reports the probe capability only when its image reference is digest pinned", "runtime-probe-image-digest-pinned"))

	sort.Slice(checks, func(i, j int) bool { return checks[i].Key < checks[j].Key })
	out := PlanCapabilityPreflight{Status: "PASS", Method: PlanCapabilityPreflightMethod, InventoryDigest: inv.Digest, Checks: checks}
	for _, check := range checks {
		if check.Required && check.Status != "PASS" {
			out.Status = "FAIL"
			out.Blockers = append(out.Blockers, fmt.Sprintf("capability preflight failed: %s (%s)", check.Key, check.Detail))
		}
	}
	out.Blockers = uniqueSortedStrings(out.Blockers)
	out.Warnings = uniqueSortedStrings(out.Warnings)
	out.Digest = CapabilityPreflightDigest(out)
	return out
}

func ValidateCapabilityPreflight(v PlanCapabilityPreflight) error {
	if v.Method != PlanCapabilityPreflightMethod || (v.Status != "PASS" && v.Status != "FAIL") || !strings.HasPrefix(v.InventoryDigest, "sha256:") || len(v.Checks) == 0 || !strings.HasPrefix(v.Digest, "sha256:") || v.Digest != CapabilityPreflightDigest(v) {
		return fmt.Errorf("%w: capability preflight authority is incomplete", ErrValidation)
	}
	seen := map[string]bool{}
	for _, check := range v.Checks {
		if strings.TrimSpace(check.Key) == "" || strings.TrimSpace(check.Domain) == "" || strings.TrimSpace(check.Authority) == "" || strings.TrimSpace(check.Impact) == "" || strings.TrimSpace(check.Detail) == "" || seen[check.Key] {
			return fmt.Errorf("%w: invalid capability preflight check %q", ErrValidation, check.Key)
		}
		seen[check.Key] = true
		if check.Required && check.Status != "PASS" && check.Status != "FAIL" {
			return fmt.Errorf("%w: required capability check %s has invalid status", ErrValidation, check.Key)
		}
		if !check.Required && check.Status != "AVAILABLE" && check.Status != "NOT_REQUIRED" {
			return fmt.Errorf("%w: optional capability check %s has invalid status", ErrValidation, check.Key)
		}
	}
	return nil
}

func ValidateCapabilityPreflightSemantics(v PlanCapabilityPreflight, inv ClusterInventory, resources []BaselineTaskResource) error {
	if err := ValidateCapabilityPreflight(v); err != nil {
		return err
	}
	expected := AnalyzeCapabilityPreflight(resources, inv)
	actualRaw, _ := json.Marshal(v)
	expectedRaw, _ := json.Marshal(expected)
	if string(actualRaw) != string(expectedRaw) {
		return fmt.Errorf("%w: capability preflight does not match bound cluster inventory and desired resources", ErrValidation)
	}
	return nil
}

func FinalizeEvidenceCollectionPlan(artifacts []PlanEvidenceArtifact) PlanEvidenceCollection {
	items := append([]PlanEvidenceArtifact(nil), artifacts...)
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	required := 0
	for i := range items {
		if items[i].Required {
			required++
		}
	}
	v := PlanEvidenceCollection{Status: "PASS", Method: PlanEvidenceCollectionMethod, RequiredCount: required, Artifacts: items}
	if len(items) == 0 || required == 0 {
		v.Status = "FAIL"
		v.Blockers = []string{"evidence collection plan has no required artifacts"}
	}
	v.Digest = EvidenceCollectionPlanDigest(v)
	return v
}

func ValidateEvidenceCollectionPlan(v PlanEvidenceCollection) error {
	if v.Status != "PASS" || v.Method != PlanEvidenceCollectionMethod || v.RequiredCount <= 0 || len(v.Artifacts) == 0 {
		return fmt.Errorf("%w: evidence collection plan is incomplete", ErrValidation)
	}
	if !strings.HasPrefix(v.Digest, "sha256:") || v.Digest != EvidenceCollectionPlanDigest(v) {
		return fmt.Errorf("%w: evidence collection plan digest mismatch", ErrValidation)
	}
	seen := map[string]bool{}
	required := 0
	for _, item := range v.Artifacts {
		if strings.TrimSpace(item.Key) == "" || seen[item.Key] || strings.TrimSpace(item.Kind) == "" || strings.TrimSpace(item.Authority) == "" || strings.TrimSpace(item.SourceLocation) == "" || strings.TrimSpace(item.OutputLocation) == "" || item.MediaType != "application/json" || item.Phase != PlanEvidencePhasePostApply || item.RetentionDays < 30 || item.RetentionDays > 3650 {
			return fmt.Errorf("%w: invalid evidence collection artifact %q", ErrValidation, item.Key)
		}
		seen[item.Key] = true
		if item.Required {
			required++
		}
	}
	if required != v.RequiredCount {
		return fmt.Errorf("%w: evidence collection required count mismatch", ErrValidation)
	}
	return nil
}

func ValidateEvidenceCollectionPlanSemantics(v PlanEvidenceCollection, deploymentID string, resources []BaselineTaskResource) error {
	if err := ValidateEvidenceCollectionPlan(v); err != nil {
		return err
	}
	expectedResources := map[string]bool{}
	for _, resource := range resources {
		expectedResources[resource.Kind+"/"+resource.Name] = true
	}
	seenResources := map[string]bool{}
	convergence := 0
	for _, item := range v.Artifacts {
		expectedOutput := "/api/v1/baseline-deployments/" + deploymentID + "/evidence/" + item.Key
		if deploymentID != "" && item.OutputLocation != expectedOutput {
			return fmt.Errorf("%w: evidence output location mismatch for %s", ErrValidation, item.Key)
		}
		if !item.Required || item.RetentionDays != PlanEvidenceRetentionDays {
			return fmt.Errorf("%w: baseline evidence must be required with %d-day retention", ErrValidation, PlanEvidenceRetentionDays)
		}
		switch item.Kind {
		case "KUBE_RESOURCE_READBACK":
			if !expectedResources[item.Resource] || seenResources[item.Resource] || item.Authority != "KUBERNETES_API_SERVER" || !strings.HasPrefix(item.SourceLocation, "kubernetes://kubernetes.default.svc/") {
				return fmt.Errorf("%w: invalid Kubernetes read-back evidence artifact %s", ErrValidation, item.Key)
			}
			seenResources[item.Resource] = true
		case "BASELINE_CONVERGENCE":
			if item.Resource != "" || item.Authority != "PLATFORM_AGENT" || item.SourceLocation != "platform-agent://baseline-convergence" {
				return fmt.Errorf("%w: invalid baseline convergence evidence artifact", ErrValidation)
			}
			convergence++
		default:
			return fmt.Errorf("%w: unsupported evidence artifact kind %s", ErrValidation, item.Kind)
		}
	}
	if len(seenResources) != len(expectedResources) || convergence != 1 || len(v.Artifacts) != len(expectedResources)+1 {
		return fmt.Errorf("%w: evidence collection plan does not cover every managed resource plus convergence", ErrValidation)
	}
	return nil
}

func baselineEvidencePayloadDigest(payload map[string]any) (string, int64) {
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), int64(len(raw))
}

func BaselineEvidenceSetDigest(items []BaselineEvidenceArtifact) string {
	type digestItem struct {
		Key, Kind, Resource, Authority, Digest, MediaType, Location string
		Size                                                        int64
		Required                                                    bool
		RetentionDays                                               int
	}
	values := make([]digestItem, 0, len(items))
	for _, item := range items {
		values = append(values, digestItem{item.Key, item.Kind, item.Resource, item.Authority, item.Digest, item.MediaType, item.Location, item.Size, item.Required, item.RetentionDays})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidateCollectedBaselineEvidence(plan PlanEvidenceCollection, deploymentID string, collected []BaselineEvidenceArtifact) error {
	if err := ValidateEvidenceCollectionPlan(plan); err != nil {
		return err
	}
	planned := map[string]PlanEvidenceArtifact{}
	for _, item := range plan.Artifacts {
		planned[item.Key] = item
	}
	if len(collected) != len(planned) {
		return fmt.Errorf("%w: collected evidence count does not match plan", ErrValidation)
	}
	seen := map[string]bool{}
	for _, item := range collected {
		spec, ok := planned[item.Key]
		if !ok || seen[item.Key] {
			return fmt.Errorf("%w: unexpected or duplicate evidence artifact %s", ErrValidation, item.Key)
		}
		seen[item.Key] = true
		digest, size := baselineEvidencePayloadDigest(item.Payload)
		expectedLocation := spec.OutputLocation
		if deploymentID != "" {
			expectedLocation = strings.ReplaceAll(expectedLocation, "{deploymentId}", deploymentID)
		}
		if item.Kind != spec.Kind || item.Resource != spec.Resource || item.Authority != spec.Authority || item.MediaType != spec.MediaType || item.Location != expectedLocation || item.Required != spec.Required || item.RetentionDays != spec.RetentionDays || item.Digest != digest || item.Size != size || !strings.HasPrefix(item.Digest, "sha256:") {
			return fmt.Errorf("%w: collected evidence does not match plan for %s", ErrValidation, item.Key)
		}
		if deploymentID != "" && item.Location != "/api/v1/baseline-deployments/"+deploymentID+"/evidence/"+item.Key {
			return fmt.Errorf("%w: collected evidence output location mismatch for %s", ErrValidation, item.Key)
		}
	}
	for _, item := range plan.Artifacts {
		if item.Required && !seen[item.Key] {
			return fmt.Errorf("%w: required evidence artifact %s is missing", ErrValidation, item.Key)
		}
	}
	return nil
}

func SealBaselineEvidence(plan PlanEvidenceCollection, deploymentID string, collected []BaselineEvidenceArtifact, now time.Time) ([]BaselineEvidenceArtifact, string, error) {
	if err := ValidateCollectedBaselineEvidence(plan, deploymentID, collected); err != nil {
		return nil, "", err
	}
	out := append([]BaselineEvidenceArtifact(nil), collected...)
	for i := range out {
		t := now.UTC()
		u := t.Add(time.Duration(out[i].RetentionDays) * 24 * time.Hour)
		out[i].CollectedAt = &t
		out[i].RetainUntil = &u
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, BaselineEvidenceSetDigest(out), nil
}

func ValidatePlanningImpact(v BaselinePlanImpact, inventoryDigest string, changes []BaselinePlanChange) error {
	if v.SchemaVersion != PlanningImpactSchemaVersion || strings.TrimSpace(v.InventoryDigest) == "" || v.InventoryDigest != strings.TrimSpace(inventoryDigest) {
		return fmt.Errorf("%w: plan impact inventory/schema mismatch", ErrValidation)
	}
	if err := ValidateBaselineCompatibilityDecisionContract(v.Compatibility); err != nil {
		return err
	}
	if err := ValidateCapabilityPreflight(v.Capability); err != nil {
		return err
	}
	if v.Capability.InventoryDigest != v.InventoryDigest {
		return fmt.Errorf("%w: capability preflight inventory binding mismatch", ErrValidation)
	}
	if !strings.HasPrefix(v.Digest, "sha256:") || v.Digest != PlanningImpactDigest(v) {
		return fmt.Errorf("%w: plan impact digest mismatch", ErrValidation)
	}
	if v.Capacity.CeilingCheck == "" || v.Disruption.Level == "" || v.Disruption.MaintenanceRecommendation == "" {
		return fmt.Errorf("%w: plan impact capacity/disruption assessment is incomplete", ErrValidation)
	}
	if len(changes) > 0 && len(v.API) == 0 {
		return fmt.Errorf("%w: plan impact API analysis is missing", ErrValidation)
	}
	for _, api := range v.API {
		if api.Schema.Status != "PASS" || api.Schema.Method != PlanSchemaValidationMethod || api.Schema.HTTPStatus < 200 || api.Schema.HTTPStatus >= 300 || !strings.HasPrefix(api.Schema.SchemaIndexDigest, "sha256:") {
			return fmt.Errorf("%w: strict schema compatibility evidence is incomplete for %s", ErrValidation, api.Resource)
		}
	}
	if v.Rollback.Method != PlanRollbackValidationMethod || v.Rollback.Status != "PASS" || !strings.HasPrefix(v.Rollback.Digest, "sha256:") || v.Rollback.Digest != RollbackFeasibilityDigest(v.Rollback) {
		return fmt.Errorf("%w: rollback feasibility evidence is incomplete", ErrValidation)
	}
	for _, item := range v.Rollback.Resources {
		if item.Status != "PASS" || !strings.HasPrefix(item.SchemaIndexDigest, "sha256:") {
			return fmt.Errorf("%w: rollback feasibility failed for %s", ErrValidation, item.Resource)
		}
	}
	if err := ValidateEvidenceCollectionPlan(v.Evidence); err != nil {
		return err
	}
	return nil
}

func PlanningImpactSchemaReady(v BaselinePlanImpact) bool {
	if len(v.API) == 0 {
		return false
	}
	for _, api := range v.API {
		if api.Schema.Status != "PASS" || api.Schema.Method != PlanSchemaValidationMethod || api.Schema.HTTPStatus < 200 || api.Schema.HTTPStatus >= 300 || !strings.HasPrefix(api.Schema.SchemaIndexDigest, "sha256:") {
			return false
		}
	}
	return true
}

func ValidatePlanningImpactSemantics(v BaselinePlanImpact, inv ClusterInventory, resources []BaselineTaskResource, changes []BaselinePlanChange) error {
	if err := ValidatePlanningImpact(v, inv.Digest, changes); err != nil {
		return err
	}
	ordered := append([]BaselineTaskResource(nil), resources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Kind+"/"+ordered[i].Name < ordered[j].Kind+"/"+ordered[j].Name })
	if !inv.SchemaDiscoveryComplete || (inv.SchemaDiscoveryVersion != "OPENAPI_V3" && inv.SchemaDiscoveryVersion != "OPENAPI_V2") || !strings.HasPrefix(inv.SchemaDiscoveryDigest, "sha256:") {
		return fmt.Errorf("%w: authoritative OpenAPI schema discovery is incomplete", ErrValidation)
	}
	expectedAPI := make([]PlanAPIImpact, 0, len(ordered))
	for i, r := range ordered {
		expected := analyzeAPIResource(r, inv)
		if i >= len(v.API) {
			return fmt.Errorf("%w: plan impact API analysis is incomplete", ErrValidation)
		}
		schema := v.API[i].Schema
		if schema.Status != "PASS" || schema.Method != PlanSchemaValidationMethod || schema.HTTPStatus < 200 || schema.HTTPStatus >= 300 || schema.SchemaIndexVersion != inv.SchemaDiscoveryVersion || schema.SchemaIndexDigest != inv.SchemaDiscoveryDigest || strings.TrimSpace(schema.FailureDigest) != "" {
			return fmt.Errorf("%w: schema compatibility evidence does not match authority inventory for %s", ErrValidation, expected.Resource)
		}
		expected.Schema = schema
		if len(schema.Warnings) > 0 && expected.Severity == "INFO" {
			expected.Severity = "WARNING"
		}
		expectedAPI = append(expectedAPI, expected)
	}
	actualAPI, _ := json.Marshal(v.API)
	expectedAPIRaw, _ := json.Marshal(expectedAPI)
	if string(actualAPI) != string(expectedAPIRaw) {
		return fmt.Errorf("%w: plan impact API/CRD analysis does not match authority inventory", ErrValidation)
	}
	expectedDisruption := analyzeDisruption(resources, changes)
	actualDisruptionRaw, _ := json.Marshal(v.Disruption)
	expectedDisruptionRaw, _ := json.Marshal(expectedDisruption)
	if string(actualDisruptionRaw) != string(expectedDisruptionRaw) {
		return fmt.Errorf("%w: plan disruption analysis does not match desired changes", ErrValidation)
	}
	if v.Capacity.CPUAllocatableCeilingMilli != inv.Capacity.CPUAllocatableMilli ||
		v.Capacity.MemoryAllocatableCeilingBytes != inv.Capacity.MemoryAllocatableBytes ||
		v.Capacity.PodsAllocatableCeiling != inv.Capacity.PodsAllocatable {
		return fmt.Errorf("%w: plan capacity ceiling does not match cluster inventory", ErrValidation)
	}
	if v.Capacity.CurrentUsageKnown {
		return fmt.Errorf("%w: aggregate current usage is not an authoritative inventory signal", ErrValidation)
	}
	if err := ValidateBaselineCompatibilityDecision(v.Compatibility, inv); err != nil {
		return err
	}
	if err := ValidateCapabilityPreflightSemantics(v.Capability, inv, resources); err != nil {
		return err
	}
	if err := ValidateRollbackFeasibilitySemantics(v.Rollback, inv, resources, changes); err != nil {
		return err
	}
	if err := ValidateEvidenceCollectionPlan(v.Evidence); err != nil {
		return err
	}
	if v.ApprovalReady {
		if v.Compatibility.Status != "PASS" {
			return fmt.Errorf("%w: approval-ready impact has failed compatibility matrix", ErrValidation)
		}
		if v.Capability.Status != "PASS" {
			return fmt.Errorf("%w: approval-ready impact has failed capability preflight", ErrValidation)
		}
		if len(v.Blockers) > 0 || v.Capacity.CeilingCheck == "FAIL" {
			return fmt.Errorf("%w: approval-ready impact contains blockers", ErrValidation)
		}
		for _, api := range v.API {
			if api.Severity == "ERROR" {
				return fmt.Errorf("%w: approval-ready impact contains API/CRD errors", ErrValidation)
			}
		}
	}
	return nil
}

func defaultEvidenceCollectionPlan(resources []BaselineTaskResource) PlanEvidenceCollection {
	ordered := append([]BaselineTaskResource(nil), resources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Kind+"/"+ordered[i].Name < ordered[j].Kind+"/"+ordered[j].Name })
	artifacts := make([]PlanEvidenceArtifact, 0, len(ordered)+1)
	for i, resource := range ordered {
		key := fmt.Sprintf("resource-readback-%02d", i+1)
		artifacts = append(artifacts, PlanEvidenceArtifact{Key: key, Kind: "KUBE_RESOURCE_READBACK", Resource: resource.Kind + "/" + resource.Name, Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/discovery-bound/" + resource.Kind + "/" + resource.Name, OutputLocation: "/api/v1/baseline-deployments/{deploymentId}/evidence/" + key, MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays})
	}
	artifacts = append(artifacts, PlanEvidenceArtifact{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: "/api/v1/baseline-deployments/{deploymentId}/evidence/baseline-convergence", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays})
	return FinalizeEvidenceCollectionPlan(artifacts)
}

func AnalyzePlanningImpact(resources []BaselineTaskResource, current map[string]map[string]any, changes []BaselinePlanChange, inv ClusterInventory) BaselinePlanImpact {
	return AnalyzePlanningImpactWithSchema(resources, current, changes, inv, nil)
}

func AnalyzePlanningImpactWithSchema(resources []BaselineTaskResource, current map[string]map[string]any, changes []BaselinePlanChange, inv ClusterInventory, schemaByResource map[string]PlanSchemaCompatibility, rollbackByResource ...map[string]PlanRollbackResource) BaselinePlanImpact {
	impact := BaselinePlanImpact{SchemaVersion: PlanningImpactSchemaVersion, InventoryDigest: inv.Digest, ApprovalReady: true}
	impact.Compatibility = BaselineCompatibilityDecision(inv)
	if impact.Compatibility.Status != "PASS" {
		impact.ApprovalReady = false
		impact.Blockers = append(impact.Blockers, impact.Compatibility.Blockers...)
	}
	impact.Capability = AnalyzeCapabilityPreflight(resources, inv)
	impact.Evidence = defaultEvidenceCollectionPlan(resources)
	if impact.Capability.Status != "PASS" {
		impact.ApprovalReady = false
		impact.Blockers = append(impact.Blockers, impact.Capability.Blockers...)
	}
	rollbackEvidence := map[string]PlanRollbackResource{}
	if len(rollbackByResource) > 0 && rollbackByResource[0] != nil {
		rollbackEvidence = rollbackByResource[0]
	}
	changeByResource := map[string]BaselinePlanChange{}
	for _, c := range changes {
		changeByResource[c.Resource] = c
	}
	resources = append([]BaselineTaskResource(nil), resources...)
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Kind+"/"+resources[i].Name < resources[j].Kind+"/"+resources[j].Name
	})
	for _, r := range resources {
		key := r.Kind + "/" + r.Name
		apiImpact := analyzeAPIResource(r, inv)
		schema, ok := schemaByResource[key]
		if !ok || schema.Status == "" {
			schema = PlanSchemaCompatibility{Status: "NOT_EXECUTED", Method: PlanSchemaValidationMethod, SchemaIndexVersion: inv.SchemaDiscoveryVersion, SchemaIndexDigest: inv.SchemaDiscoveryDigest}
		}
		schema.Warnings = uniqueSortedStrings(schema.Warnings)
		apiImpact.Schema = schema
		if !inv.SchemaDiscoveryComplete || !strings.HasPrefix(inv.SchemaDiscoveryDigest, "sha256:") {
			apiImpact.Severity = "ERROR"
			apiImpact.Message = fmt.Sprintf("OpenAPI schema discovery is incomplete for %s", key)
		} else if schema.Status != "PASS" || schema.Method != PlanSchemaValidationMethod || schema.HTTPStatus < 200 || schema.HTTPStatus >= 300 || schema.SchemaIndexVersion != inv.SchemaDiscoveryVersion || schema.SchemaIndexDigest != inv.SchemaDiscoveryDigest {
			apiImpact.Severity = "ERROR"
			apiImpact.Message = fmt.Sprintf("strict Kubernetes API schema dry-run failed for %s", key)
		} else if len(schema.Warnings) > 0 && apiImpact.Severity == "INFO" {
			apiImpact.Severity = "WARNING"
		}
		impact.API = append(impact.API, apiImpact)
		if apiImpact.Severity == "ERROR" {
			impact.ApprovalReady = false
			impact.Blockers = append(impact.Blockers, apiImpact.Message)
		} else if apiImpact.Severity == "WARNING" {
			impact.Warnings = append(impact.Warnings, apiImpact.Message)
		}
		for _, warning := range schema.Warnings {
			impact.Warnings = append(impact.Warnings, fmt.Sprintf("%s schema warning: %s", key, warning))
		}
		_ = changeByResource[key]
	}
	impact.Capacity = analyzeCapacity(resources, current, changeByResource, inv)
	if impact.Capacity.CeilingCheck == "FAIL" {
		impact.ApprovalReady = false
		impact.Blockers = append(impact.Blockers, "planned workload request delta exceeds cluster allocatable ceiling")
	}
	impact.Disruption = analyzeDisruption(resources, changes)
	impact.Rollback = analyzeRollbackFeasibility(resources, changes, inv, rollbackEvidence)
	if impact.Rollback.Status != "PASS" {
		impact.ApprovalReady = false
		impact.Blockers = append(impact.Blockers, impact.Rollback.Blockers...)
	}
	impact.Warnings = append(impact.Warnings, impact.Rollback.Warnings...)
	impact.Blockers = uniqueSortedStrings(impact.Blockers)
	impact.Warnings = uniqueSortedStrings(impact.Warnings)
	impact.Digest = PlanningImpactDigest(impact)
	return impact
}

func analyzeRollbackFeasibility(resources []BaselineTaskResource, changes []BaselinePlanChange, inv ClusterInventory, evidence map[string]PlanRollbackResource) PlanRollbackFeasibility {
	out := PlanRollbackFeasibility{Status: "PASS", Method: PlanRollbackValidationMethod}
	changeByResource := map[string]BaselinePlanChange{}
	for _, change := range changes {
		changeByResource[change.Resource] = change
	}
	ordered := append([]BaselineTaskResource(nil), resources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Kind+"/"+ordered[i].Name < ordered[j].Kind+"/"+ordered[j].Name })
	for _, resource := range ordered {
		key := resource.Kind + "/" + resource.Name
		change, changeFound := changeByResource[key]
		if !changeFound {
			change = BaselinePlanChange{Resource: key, Action: "NOOP"}
		}
		item, ok := evidence[key]
		if !ok {
			item = PlanRollbackResource{Resource: key, ChangeAction: change.Action, Strategy: "UNKNOWN", Status: "FAIL", AuthorizationStatus: "NOT_EXECUTED", DryRunStatus: "NOT_EXECUTED", SchemaIndexVersion: inv.SchemaDiscoveryVersion, SchemaIndexDigest: inv.SchemaDiscoveryDigest, FailureDigest: digestString("rollback feasibility not executed")}
		}
		item.Warnings = uniqueSortedStrings(item.Warnings)
		out.Resources = append(out.Resources, item)
		if item.Status != "PASS" {
			out.Status = "FAIL"
			out.Blockers = append(out.Blockers, fmt.Sprintf("rollback feasibility failed for %s", key))
		}
		for _, warning := range item.Warnings {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s rollback warning: %s", key, warning))
		}
	}
	out.Blockers = uniqueSortedStrings(out.Blockers)
	out.Warnings = uniqueSortedStrings(out.Warnings)
	out.Digest = RollbackFeasibilityDigest(out)
	return out
}

func ValidateRollbackFeasibilitySemantics(v PlanRollbackFeasibility, inv ClusterInventory, resources []BaselineTaskResource, changes []BaselinePlanChange) error {
	if v.Method != PlanRollbackValidationMethod || v.Status != "PASS" || v.Digest != RollbackFeasibilityDigest(v) {
		return fmt.Errorf("%w: rollback feasibility authority is invalid", ErrValidation)
	}
	changeByResource := map[string]BaselinePlanChange{}
	resourceByKey := map[string]BaselineTaskResource{}
	for _, change := range changes {
		changeByResource[change.Resource] = change
	}
	for _, resource := range resources {
		resourceByKey[resource.Kind+"/"+resource.Name] = resource
	}
	if len(v.Resources) != len(resources) {
		return fmt.Errorf("%w: rollback feasibility resource count mismatch", ErrValidation)
	}
	for _, item := range v.Resources {
		resource, ok := resourceByKey[item.Resource]
		if !ok {
			return fmt.Errorf("%w: rollback feasibility contains unknown resource %s", ErrValidation, item.Resource)
		}
		change, changeFound := changeByResource[item.Resource]
		if !changeFound {
			change = BaselinePlanChange{Resource: item.Resource, Action: "NOOP"}
		}
		if item.ChangeAction != change.Action || item.Status != "PASS" || item.SchemaIndexVersion != inv.SchemaDiscoveryVersion || item.SchemaIndexDigest != inv.SchemaDiscoveryDigest {
			return fmt.Errorf("%w: rollback feasibility binding mismatch for %s", ErrValidation, item.Resource)
		}
		switch strings.ToUpper(change.Action) {
		case "NOOP":
			if item.Strategy != "NO_ACTION" || item.AuthorizationStatus != "NOT_REQUIRED" || item.DryRunStatus != "NOT_REQUIRED" || strings.TrimSpace(item.ObservedUID) == "" || !strings.HasPrefix(item.ObservedObjectDigest, "sha256:") || len(item.RestoreObject) != 0 || item.RestoreObjectDigest != "" {
				return fmt.Errorf("%w: invalid NOOP rollback evidence for %s", ErrValidation, item.Resource)
			}
		case "ADD":
			if item.Strategy != "DELETE_CREATED_RESOURCE" || item.AuthorizationStatus != "PASS" || item.DryRunStatus != "NOT_APPLICABLE" || item.ObservedUID != "" || item.ObservedObjectDigest != "" || len(item.RestoreObject) != 0 || item.RestoreObjectDigest != "" {
				return fmt.Errorf("%w: invalid ADD rollback evidence for %s", ErrValidation, item.Resource)
			}
		case "UPDATE", "DELETE":
			if strings.EqualFold(resource.Kind, "Secret") {
				return fmt.Errorf("%w: sensitive rollback pre-image cannot be embedded for %s", ErrValidation, item.Resource)
			}
			if item.Strategy != "RESTORE_PREIMAGE" || item.AuthorizationStatus != "PASS" || item.DryRunStatus != "PASS" || item.HTTPStatus < 200 || item.HTTPStatus >= 300 || strings.TrimSpace(item.ObservedUID) == "" || !strings.HasPrefix(item.ObservedObjectDigest, "sha256:") || !strings.HasPrefix(item.RestoreObjectDigest, "sha256:") || item.ObservedObjectDigest != item.RestoreObjectDigest || item.RestoreObjectDigest != RollbackRestoreObjectDigest(item.RestoreObject) {
				return fmt.Errorf("%w: invalid restore rollback evidence for %s", ErrValidation, item.Resource)
			}
			metadata, _ := item.RestoreObject["metadata"].(map[string]any)
			if item.RestoreObject["apiVersion"] != resource.APIVersion || item.RestoreObject["kind"] != resource.Kind || fmt.Sprint(metadata["name"]) != resource.Name || fmt.Sprint(metadata["namespace"]) != resource.Namespace {
				return fmt.Errorf("%w: restore pre-image identity mismatch for %s", ErrValidation, item.Resource)
			}
		default:
			return fmt.Errorf("%w: unsupported rollback change action %q", ErrValidation, change.Action)
		}
		if item.FailureDigest != "" {
			return fmt.Errorf("%w: rollback feasibility carries failure evidence for %s", ErrValidation, item.Resource)
		}
	}
	return nil
}

func RollbackRestoreObjectDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func digestString(v string) string { return RollbackRestoreObjectDigest(v) }

func analyzeAPIResource(r BaselineTaskResource, inv ClusterInventory) PlanAPIImpact {
	out := PlanAPIImpact{Resource: r.Kind + "/" + r.Name, APIVersion: r.APIVersion, Kind: r.Kind, DiscoveryStatus: "UNKNOWN", LifecycleStatus: "CURRENT", Severity: "INFO"}
	if strings.TrimSpace(r.APIVersion) == "" || strings.TrimSpace(r.Kind) == "" {
		out.Severity, out.Message = "ERROR", "desired resource has no apiVersion/kind"
		return out
	}
	served := false
	for _, item := range inv.APIResources {
		if item.APIVersion == r.APIVersion && item.Kind == r.Kind {
			served = true
			break
		}
	}
	if served {
		out.DiscoveryStatus = "SERVED"
	} else if inv.APIDiscoveryComplete {
		out.DiscoveryStatus = "NOT_SERVED"
		out.Severity = "ERROR"
		out.Message = fmt.Sprintf("%s %s is not served by the target cluster", r.APIVersion, r.Kind)
	} else {
		out.DiscoveryStatus = "UNKNOWN"
		out.Severity = "ERROR"
		out.Message = fmt.Sprintf("API discovery is incomplete for %s %s", r.APIVersion, r.Kind)
	}
	if rule, ok := lifecycleRule(r.APIVersion, r.Kind); ok {
		out.DeprecatedIn, out.RemovedIn, out.Replacement = rule.DeprecatedIn, rule.RemovedIn, rule.Replacement
		clusterVersion := parseKubeMinor(inv.KubernetesVersion)
		if clusterVersion.valid && compareMinor(clusterVersion.major, clusterVersion.minor, rule.RemovedIn) >= 0 {
			out.LifecycleStatus = "REMOVED_UPSTREAM"
			out.Severity = "ERROR"
			out.Message = fmt.Sprintf("%s %s was removed upstream in Kubernetes %s; use %s", r.APIVersion, r.Kind, rule.RemovedIn, rule.Replacement)
		} else if clusterVersion.valid && compareMinor(clusterVersion.major, clusterVersion.minor, rule.DeprecatedIn) >= 0 {
			out.LifecycleStatus = "DEPRECATED"
			if out.Severity != "ERROR" {
				out.Severity = "WARNING"
				out.Message = fmt.Sprintf("%s %s is deprecated since Kubernetes %s; use %s", r.APIVersion, r.Kind, rule.DeprecatedIn, rule.Replacement)
			}
		}
	}
	group, version := splitAPIVersion(r.APIVersion)
	if group != "" && !isBuiltinGroup(group) {
		out.CustomResource = true
		crd, found := findCRD(inv.CRDs, group, r.Kind)
		if found {
			out.CRDName = crd.Name
			for _, v := range crd.Versions {
				if v.Name == version && v.Served {
					out.CRDVersionServed = true
					break
				}
			}
			if !out.CRDVersionServed {
				out.Severity = "ERROR"
				out.Message = fmt.Sprintf("CRD %s does not serve version %s", crd.Name, version)
			}
		} else if inv.CRDDiscoveryComplete {
			out.Severity = "ERROR"
			out.Message = fmt.Sprintf("no CRD is installed for %s %s", r.APIVersion, r.Kind)
		} else {
			out.Severity = "ERROR"
			out.Message = fmt.Sprintf("CRD discovery is incomplete for %s %s", r.APIVersion, r.Kind)
		}
	}
	if out.Message == "" {
		out.Message = fmt.Sprintf("%s %s is served and has no known lifecycle blocker", r.APIVersion, r.Kind)
	}
	return out
}

func isBuiltinGroup(group string) bool {
	switch group {
	case "apps", "batch", "autoscaling", "policy", "networking.k8s.io", "rbac.authorization.k8s.io", "storage.k8s.io", "coordination.k8s.io", "discovery.k8s.io", "events.k8s.io", "node.k8s.io", "scheduling.k8s.io", "authentication.k8s.io", "authorization.k8s.io", "admissionregistration.k8s.io", "apiextensions.k8s.io", "certificates.k8s.io", "flowcontrol.apiserver.k8s.io":
		return true
	default:
		return false
	}
}

func findCRD(crds []ClusterCRDObservation, group, kind string) (ClusterCRDObservation, bool) {
	for _, crd := range crds {
		if crd.Group == group && crd.Kind == kind {
			return crd, true
		}
	}
	return ClusterCRDObservation{}, false
}

func splitAPIVersion(apiVersion string) (string, string) {
	parts := strings.Split(strings.TrimSpace(apiVersion), "/")
	if len(parts) == 1 {
		return "", parts[0]
	}
	return parts[0], parts[len(parts)-1]
}

func lifecycleRule(apiVersion, kind string) (apiLifecycleRule, bool) {
	for _, r := range apiLifecycleRules {
		if r.APIVersion == apiVersion && r.Kind == kind {
			return r, true
		}
	}
	return apiLifecycleRule{}, false
}

type kubeMinor struct {
	major, minor int
	valid        bool
}

func parseKubeMinor(v string) kubeMinor {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return kubeMinor{}
	}
	major, err1 := strconv.Atoi(leadingDigits(parts[0]))
	minor, err2 := strconv.Atoi(leadingDigits(parts[1]))
	return kubeMinor{major, minor, err1 == nil && err2 == nil}
}
func leadingDigits(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
func compareMinor(major, minor int, threshold string) int {
	v := parseKubeMinor(threshold)
	if !v.valid {
		return -1
	}
	if major != v.major {
		if major > v.major {
			return 1
		}
		return -1
	}
	if minor > v.minor {
		return 1
	}
	if minor < v.minor {
		return -1
	}
	return 0
}

func analyzeCapacity(resources []BaselineTaskResource, current map[string]map[string]any, changes map[string]BaselinePlanChange, inv ClusterInventory) PlanCapacityEstimate {
	est := PlanCapacityEstimate{
		DemandDeltaKnown:              true,
		CPUAllocatableCeilingMilli:    inv.Capacity.CPUAllocatableMilli,
		MemoryAllocatableCeilingBytes: inv.Capacity.MemoryAllocatableBytes,
		PodsAllocatableCeiling:        inv.Capacity.PodsAllocatable,
		CeilingCheck:                  "NOT_APPLICABLE",
		CurrentUsageKnown:             false,
	}
	for _, r := range resources {
		key := r.Kind + "/" + r.Name
		change := changes[key]
		if r.Kind == "ResourceQuota" {
			est.QuotaImpacts = append(est.QuotaImpacts, PlanQuotaImpact{Resource: key, Action: change.Action, Current: resourceQuotaHard(current[key]), Desired: resourceQuotaHard(r.Object)})
		}
		if !isWorkloadKind(r.Kind) || strings.EqualFold(change.Action, "NOOP") {
			continue
		}
		est.WorkloadResources++
		dCPU, dMem, dPods, desiredKnown := workloadDemand(r.Kind, r.Object, inv)
		cCPU, cMem, cPods, currentKnown := int64(0), int64(0), int64(0), true
		if strings.EqualFold(change.Action, "UPDATE") {
			var ok bool
			cCPU, cMem, cPods, ok = workloadDemand(r.Kind, current[key], inv)
			currentKnown = ok
		} else if strings.EqualFold(change.Action, "DELETE") {
			var ok bool
			cCPU, cMem, cPods, ok = workloadDemand(r.Kind, current[key], inv)
			currentKnown = ok
			dCPU, dMem, dPods = 0, 0, 0
		} else if strings.EqualFold(change.Action, "ADD") {
			cCPU, cMem, cPods = 0, 0, 0
		}
		if !desiredKnown || !currentKnown {
			est.DemandDeltaKnown = false
			est.UnknownReasons = append(est.UnknownReasons, "workload requests/replicas could not be determined for "+key)
			continue
		}
		est.CPURequestDeltaMilli += dCPU - cCPU
		est.MemoryRequestDeltaBytes += dMem - cMem
		est.PodReplicaDelta += dPods - cPods
	}
	sort.Slice(est.QuotaImpacts, func(i, j int) bool { return est.QuotaImpacts[i].Resource < est.QuotaImpacts[j].Resource })
	est.UnknownReasons = uniqueSortedStrings(est.UnknownReasons)
	if est.WorkloadResources > 0 && est.DemandDeltaKnown {
		est.CeilingCheck = "PASS"
		if est.CPURequestDeltaMilli > est.CPUAllocatableCeilingMilli && est.CPUAllocatableCeilingMilli > 0 {
			est.CeilingCheck = "FAIL"
		}
		if est.MemoryRequestDeltaBytes > est.MemoryAllocatableCeilingBytes && est.MemoryAllocatableCeilingBytes > 0 {
			est.CeilingCheck = "FAIL"
		}
		if est.PodReplicaDelta > est.PodsAllocatableCeiling && est.PodsAllocatableCeiling > 0 {
			est.CeilingCheck = "FAIL"
		}
	} else if est.WorkloadResources > 0 {
		est.CeilingCheck = "UNKNOWN"
	}
	return est
}

func resourceQuotaHard(obj map[string]any) map[string]string {
	out := map[string]string{}
	if obj == nil {
		return out
	}
	spec, _ := obj["spec"].(map[string]any)
	hard, _ := spec["hard"].(map[string]any)
	for k, v := range hard {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func isWorkloadKind(kind string) bool {
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func workloadDemand(kind string, obj map[string]any, inv ClusterInventory) (int64, int64, int64, bool) {
	if obj == nil {
		return 0, 0, 0, false
	}
	var podSpec map[string]any
	replicas := int64(1)
	spec, _ := obj["spec"].(map[string]any)
	switch kind {
	case "Pod":
		podSpec = spec
	case "Deployment", "StatefulSet":
		if r, ok := numericInt64(spec["replicas"]); ok {
			replicas = r
		} else if spec["replicas"] == nil {
			replicas = 1
		} else {
			return 0, 0, 0, false
		}
		template, _ := spec["template"].(map[string]any)
		podSpec, _ = template["spec"].(map[string]any)
	case "DaemonSet":
		ready := int64(0)
		for _, n := range inv.Nodes {
			if n.Ready {
				ready++
			}
		}
		if ready == 0 {
			return 0, 0, 0, false
		}
		replicas = ready
		template, _ := spec["template"].(map[string]any)
		podSpec, _ = template["spec"].(map[string]any)
	case "Job":
		if p, ok := numericInt64(spec["parallelism"]); ok {
			replicas = p
		}
		template, _ := spec["template"].(map[string]any)
		podSpec, _ = template["spec"].(map[string]any)
	case "CronJob":
		jobTemplate, _ := spec["jobTemplate"].(map[string]any)
		jobSpec, _ := jobTemplate["spec"].(map[string]any)
		template, _ := jobSpec["template"].(map[string]any)
		podSpec, _ = template["spec"].(map[string]any)
	default:
		return 0, 0, 0, false
	}
	if podSpec == nil {
		return 0, 0, 0, false
	}
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		return 0, 0, 0, false
	}
	var cpu, mem int64
	for _, raw := range containers {
		c, _ := raw.(map[string]any)
		resources, _ := c["resources"].(map[string]any)
		requests, _ := resources["requests"].(map[string]any)
		if requests == nil {
			return 0, 0, 0, false
		}
		cCPU, okCPU := parseCPU(fmt.Sprint(requests["cpu"]))
		cMem, okMem := parseBytes(fmt.Sprint(requests["memory"]))
		if !okCPU || !okMem {
			return 0, 0, 0, false
		}
		cpu += cCPU
		mem += cMem
	}
	return cpu * replicas, mem * replicas, replicas, true
}

func numericInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		return int64(x), x == float64(int64(x))
	case json.Number:
		n, e := x.Int64()
		return n, e == nil
	default:
		n, e := strconv.ParseInt(fmt.Sprint(v), 10, 64)
		return n, e == nil
	}
}
func parseCPU(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "<nil>" {
		return 0, false
	}
	if strings.HasSuffix(v, "m") {
		n, e := strconv.ParseInt(strings.TrimSuffix(v, "m"), 10, 64)
		return n, e == nil
	}
	f, e := strconv.ParseFloat(v, 64)
	return int64(f * 1000), e == nil
}
func parseBytes(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "<nil>" {
		return 0, false
	}
	mult := map[string]float64{"Ki": 1024, "Mi": 1024 * 1024, "Gi": 1024 * 1024 * 1024, "Ti": 1024 * 1024 * 1024 * 1024, "K": 1000, "M": 1000 * 1000, "G": 1000 * 1000 * 1000, "T": 1000 * 1000 * 1000 * 1000}
	for s, m := range mult {
		if strings.HasSuffix(v, s) {
			f, e := strconv.ParseFloat(strings.TrimSuffix(v, s), 64)
			return int64(f * m), e == nil
		}
	}
	f, e := strconv.ParseFloat(v, 64)
	return int64(f), e == nil
}

func analyzeDisruption(resources []BaselineTaskResource, changes []BaselinePlanChange) PlanDisruptionEstimate {
	out := PlanDisruptionEstimate{Level: "NONE", MaintenanceRecommendation: "NOT_REQUIRED"}
	resourceByKey := map[string]BaselineTaskResource{}
	for _, r := range resources {
		resourceByKey[r.Kind+"/"+r.Name] = r
	}
	for _, c := range changes {
		if strings.EqualFold(c.Action, "NOOP") {
			continue
		}
		r := resourceByKey[c.Resource]
		level, maintenance, reason := disruptionFor(r, c.Action)
		if disruptionRank(level) > disruptionRank(out.Level) {
			out.Level = level
		}
		if maintenanceRank(maintenance) > maintenanceRank(out.MaintenanceRecommendation) {
			out.MaintenanceRecommendation = maintenance
		}
		out.Reasons = append(out.Reasons, reason)
		out.AffectedResources = append(out.AffectedResources, c.Resource)
	}
	out.Reasons = uniqueSortedStrings(out.Reasons)
	out.AffectedResources = uniqueSortedStrings(out.AffectedResources)
	return out
}
func disruptionFor(r BaselineTaskResource, action string) (string, string, string) {
	action = strings.ToUpper(strings.TrimSpace(action))
	key := r.Kind + "/" + r.Name
	if action == "DELETE" {
		switch r.Kind {
		case "Namespace", "CustomResourceDefinition", "PersistentVolumeClaim":
			return "HIGH", "REQUIRED", "deleting " + key + " can remove or invalidate dependent runtime state"
		default:
			return "MEDIUM", "RECOMMENDED", "deleting " + key + " removes an existing managed resource"
		}
	}
	switch r.Kind {
	case "NetworkPolicy", "Ingress", "Service", "Gateway", "HTTPRoute":
		return "MEDIUM", "RECOMMENDED", action + " of " + key + " can change live traffic behavior"
	case "CustomResourceDefinition":
		return "HIGH", "REQUIRED", action + " of " + key + " can change validation/storage semantics for custom resources"
	case "Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob":
		return "MEDIUM", "RECOMMENDED", action + " of " + key + " can restart, reschedule or add workload pods"
	case "ResourceQuota", "LimitRange":
		return "LOW", "NOT_REQUIRED", action + " of " + key + " changes admission policy for future workload requests"
	default:
		return "LOW", "NOT_REQUIRED", action + " of " + key + " changes a managed control-plane object without a known pod restart"
	}
}
func disruptionRank(v string) int {
	switch v {
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 1
	default:
		return 0
	}
}
func maintenanceRank(v string) int {
	switch v {
	case "REQUIRED":
		return 3
	case "RECOMMENDED":
		return 2
	case "NOT_REQUIRED":
		return 1
	default:
		return 0
	}
}
func uniqueSortedStrings(in []string) []string {
	m := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			m[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
