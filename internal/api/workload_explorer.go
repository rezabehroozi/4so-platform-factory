package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/resourceexplorer"
)

const workloadResourcePageDefaultLimit = 100
const workloadResourcePageMaxLimit = 200

func (s *Server) clusterWorkloadExplorer(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	project, err := s.requireProjectAccess(r, cluster.ProjectID, organizationRead)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	fresh := controlplane.ClusterInventoryAuthorityFreshAt(cluster, now)
	explorer := inventory.WorkloadExplorer
	if explorer.Authority == "" {
		explorer.Authority = controlplane.WorkloadExplorerAuthorityMethod
	}

	query, err := workloadResourceQuery(r, project.OrganizationID, cluster.ProjectID, cluster.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RESOURCE_EXPLORER_QUERY_INVALID", err.Error())
		return
	}
	resourcePage, err := resourceexplorer.BuildPage(workloadResourceObservations(project.OrganizationID, cluster.ProjectID, cluster.ID, inventory, fresh), query, now, 5*time.Minute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RESOURCE_EXPLORER_QUERY_INVALID", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authority":                  controlplane.WorkloadExplorerAuthorityMethod,
		"clusterId":                  cluster.ID,
		"projectId":                  cluster.ProjectID,
		"inventoryDigest":            inventory.Digest,
		"observedAt":                 inventory.ObservedAt,
		"fresh":                      fresh,
		"stale":                      !fresh,
		"complete":                   explorer.Complete,
		"truncated":                  explorer.Truncated,
		"bounded":                    true,
		"workloadLimit":              controlplane.WorkloadExplorerItemLimit,
		"eventLimit":                 controlplane.WorkloadExplorerEventLimit,
		"workloads":                  explorer.Workloads,
		"services":                   explorer.Services,
		"ingresses":                  explorer.Ingresses,
		"persistentVolumeClaims":     explorer.PVCs,
		"events":                     explorer.Events,
		"resourceExplorerAuthority":  resourceexplorer.BoundedResourceExplorerAuthority,
		"resourcePage":               resourcePage,
		"resourceReadOnly":           true,
		"rawKubernetesMutation":      false,
		"resourceIdentityComplete":   false,
		"resourceEvidenceAuthority":  "clusterInventory.digest",
		"mutationContinuationPolicy": "OWNER_PRODUCT_API_ONLY",
		"personaJourneys":            resourceexplorer.PersonaTaskJourneys(),
	})
}

func workloadResourceQuery(r *http.Request, organizationID, projectID, clusterID string) (resourceexplorer.ResourceQuery, error) {
	values := r.URL.Query()
	limit := workloadResourcePageDefaultLimit
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > workloadResourcePageMaxLimit {
			return resourceexplorer.ResourceQuery{}, &workloadResourceQueryError{message: "limit must be between 1 and 200"}
		}
		limit = parsed
	}
	return resourceexplorer.ResourceQuery{
		OrganizationID: strings.TrimSpace(organizationID),
		ProjectID:      strings.TrimSpace(projectID),
		ClusterID:      strings.TrimSpace(clusterID),
		APIVersion:     strings.TrimSpace(values.Get("apiVersion")),
		Kind:           strings.TrimSpace(values.Get("kind")),
		Namespace:      strings.TrimSpace(values.Get("namespace")),
		Limit:          limit,
		Cursor:         strings.TrimSpace(values.Get("cursor")),
	}, nil
}

type workloadResourceQueryError struct{ message string }

func (e *workloadResourceQueryError) Error() string { return e.message }

// workloadObservedAPIVersion is bounded to the exact Kubernetes list endpoints
// used by the current Agent workload collector. It deliberately does not infer
// versions for arbitrary kinds. UID remains absent until the Agent carries the
// real metadata.uid end-to-end, so these observations stay UNKNOWN rather than
// manufacturing a stable identity.
func workloadObservedAPIVersion(kind string) string {
	switch strings.TrimSpace(kind) {
	case "Deployment", "StatefulSet", "DaemonSet":
		return "apps/v1"
	case "Job":
		return "batch/v1"
	case "Service", "PersistentVolumeClaim":
		return "v1"
	case "Ingress":
		return "networking.k8s.io/v1"
	default:
		return ""
	}
}

func workloadResourceObservations(organizationID, projectID, clusterID string, inventory controlplane.ClusterInventory, fresh bool) []resourceexplorer.ResourceObservation {
	baseSummary := map[string]string{
		"source":                  "clusterInventory.workloadExplorer",
		"inventoryAuthorityFresh": strconv.FormatBool(fresh),
		"inventoryComplete":       strconv.FormatBool(inventory.WorkloadExplorer.Complete),
		"inventoryTruncated":      strconv.FormatBool(inventory.WorkloadExplorer.Truncated),
	}
	makeObservation := func(kind, namespace, name string, summary map[string]string) resourceexplorer.ResourceObservation {
		merged := make(map[string]string, len(baseSummary)+len(summary))
		for key, value := range baseSummary {
			merged[key] = value
		}
		for key, value := range summary {
			merged[key] = value
		}
		return resourceexplorer.ResourceObservation{
			Authority:      resourceexplorer.ResourceObservationAuthority,
			OrganizationID: strings.TrimSpace(organizationID),
			ProjectID:      strings.TrimSpace(projectID),
			ClusterID:      strings.TrimSpace(clusterID),
			Key: resourceexplorer.ResourceKey{
				APIVersion: workloadObservedAPIVersion(kind),
				Kind:       strings.TrimSpace(kind),
				Namespace:  strings.TrimSpace(namespace),
				Name:       strings.TrimSpace(name),
			},
			State:        resourceexplorer.TruthUnknown,
			ObservedAt:   inventory.ObservedAt,
			SourceDigest: inventory.Digest,
			Summary:      merged,
		}
	}

	out := make([]resourceexplorer.ResourceObservation, 0, len(inventory.WorkloadExplorer.Workloads)+len(inventory.WorkloadExplorer.Services)+len(inventory.WorkloadExplorer.Ingresses)+len(inventory.WorkloadExplorer.PVCs))
	for _, workload := range inventory.WorkloadExplorer.Workloads {
		out = append(out, makeObservation(workload.Kind, workload.Namespace, workload.Name, map[string]string{
			"desiredReplicas": strconv.Itoa(workload.DesiredReplicas),
			"readyReplicas":   strconv.Itoa(workload.ReadyReplicas),
			"succeeded":       strconv.Itoa(workload.Succeeded),
			"failed":          strconv.Itoa(workload.Failed),
		}))
	}
	for _, service := range inventory.WorkloadExplorer.Services {
		out = append(out, makeObservation("Service", service.Namespace, service.Name, map[string]string{"type": service.Type}))
	}
	for _, ingress := range inventory.WorkloadExplorer.Ingresses {
		out = append(out, makeObservation("Ingress", ingress.Namespace, ingress.Name, map[string]string{"class": ingress.Class}))
	}
	for _, pvc := range inventory.WorkloadExplorer.PVCs {
		out = append(out, makeObservation("PersistentVolumeClaim", pvc.Namespace, pvc.Name, map[string]string{
			"phase":        pvc.Phase,
			"requested":    pvc.Requested,
			"storageClass": pvc.StorageClass,
		}))
	}
	return out
}
