package controlplane

import (
	"context"
	"strings"
)

// ListClusterTimelineAuditPage resolves cluster ownership before applying the
// timeline cap. It deliberately avoids Snapshot(), whose cost grows with the
// entire installation rather than the requested cluster.
func (s *MemoryStore) ListClusterTimelineAuditPage(_ context.Context, clusterID string, limit int) ([]AuditEvent, error) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return nil, ErrValidation
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cluster, ok := s.managedClusters[clusterID]
	if !ok {
		return nil, ErrNotFound
	}
	resources := map[string]bool{cluster.ID: true, cluster.ImportID: true}
	operations := map[string]bool{}
	for _, v := range s.operations {
		if v.ProjectID == cluster.ProjectID && (v.TargetRef == "cluster/"+clusterID || v.TargetRef == clusterID) {
			resources[v.ID] = true
			operations[v.ID] = true
		}
	}
	for _, v := range s.steps {
		if operations[v.OperationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.stepTraces {
		if operations[v.OperationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.compensationSteps {
		if operations[v.OperationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.evidence {
		if operations[v.OperationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterInventories {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.agentCertificates {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceProfiles {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceWindows {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceRuns {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
			if v.OperationID != "" {
				resources[v.OperationID] = true
				operations[v.OperationID] = true
			}
		}
	}
	for _, v := range s.baselineDeployments {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeVerifications {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeCertifications {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeClosureCampaigns {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.recoveryCheckpoints {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.tenants {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.providerProfiles {
		if v.ManagementClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.providerClusters {
		if v.ManagementClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.marketplaceRecommendations {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
		}
	}
	for _, v := range s.workspaceBindings {
		if v.ClusterID == clusterID {
			resources[v.ID] = true
			resources[v.WorkspaceID] = true
		}
	}
	for _, v := range s.fleetGroups {
		for _, id := range v.ClusterIDs {
			if id == clusterID {
				resources[v.ID] = true
				break
			}
		}
	}
	for _, v := range s.driftScans {
		for _, target := range v.Targets {
			if target.ClusterID == clusterID {
				resources[v.ID] = true
				break
			}
		}
	}
	for _, v := range s.upgradeCampaigns {
		for _, target := range v.Targets {
			if target.ClusterID == clusterID {
				resources[v.ID] = true
				break
			}
		}
	}
	out := make([]AuditEvent, 0, limit)
	for _, event := range s.audit {
		visible := resources[event.ResourceID]
		if !visible && auditMetadataScope(event.Metadata, "clusterId") == clusterID {
			visible = true
		}
		if visible {
			out = append(out, event)
		}
	}
	auditNewestFirst(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
