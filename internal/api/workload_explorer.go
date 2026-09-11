package api

import (
	"net/http"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) clusterWorkloadExplorer(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	fresh := controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC())
	explorer := inventory.WorkloadExplorer
	if explorer.Authority == "" {
		explorer.Authority = controlplane.WorkloadExplorerAuthorityMethod
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":              controlplane.WorkloadExplorerAuthorityMethod,
		"clusterId":              cluster.ID,
		"projectId":              cluster.ProjectID,
		"inventoryDigest":        inventory.Digest,
		"observedAt":             inventory.ObservedAt,
		"fresh":                  fresh,
		"stale":                  !fresh,
		"complete":               explorer.Complete,
		"truncated":              explorer.Truncated,
		"bounded":                true,
		"workloadLimit":          controlplane.WorkloadExplorerItemLimit,
		"eventLimit":             controlplane.WorkloadExplorerEventLimit,
		"workloads":              explorer.Workloads,
		"services":               explorer.Services,
		"ingresses":              explorer.Ingresses,
		"persistentVolumeClaims": explorer.PVCs,
		"events":                 explorer.Events,
	})
}
