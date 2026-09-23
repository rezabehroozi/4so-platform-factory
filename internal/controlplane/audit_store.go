package controlplane

import (
	"context"
	"sort"
	"strings"
)

func auditScopeSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out[value] = true
		}
	}
	return out
}

func auditMetadataScope(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func auditNewestFirst(values []AuditEvent) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].OccurredAt.Equal(values[j].OccurredAt) {
			return values[i].ID > values[j].ID
		}
		return values[i].OccurredAt.After(values[j].OccurredAt)
	})
}

// ListAuditPageByScopes applies tenant authorization before pagination without
// materializing a full control-plane Snapshot. FileStore inherits this method
// from MemoryStore, so its scoped audit read path also avoids cloning unrelated
// tenant state just to build an authorization index.
func (s *MemoryStore) ListAuditPageByScopes(_ context.Context, organizationIDs, projectIDs []string, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	organizations := auditScopeSet(organizationIDs)
	projects := auditScopeSet(projectIDs)
	if len(organizations) == 0 && len(projects) == 0 {
		return []AuditEvent{}, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make(map[string]bool)
	operations := make(map[string]bool)
	clusters := make(map[string]bool)
	events := make(map[string]bool)
	deliveries := make(map[string]bool)
	for id := range organizations {
		resources[id] = true
	}
	for id := range projects {
		resources[id] = true
	}
	for _, v := range s.organizationMemberships {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.oidcGroupMappings {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && v.OrganizationID != "" && organizations[v.OrganizationID]) {
			resources[v.ID] = true
		}
	}
	for _, v := range s.serviceAccounts {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.apiTokens {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.blueprintOverlays {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.revisions {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.blueprintReleases {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.catalogTrustKeys {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.catalogRevisions {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.catalogReleases {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.assignments {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.operations {
		if projects[v.ProjectID] {
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
	for _, v := range s.notificationDestinations {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.notificationRoutes {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && organizations[v.OrganizationID]) {
			resources[v.ID] = true
		}
	}
	for _, v := range s.notificationEvents {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && organizations[v.OrganizationID]) {
			resources[v.ID] = true
			events[v.ID] = true
		}
	}
	for _, v := range s.notificationDeliveries {
		if events[v.EventID] {
			resources[v.ID] = true
			deliveries[v.ID] = true
		}
	}
	for _, v := range s.notificationAttempts {
		if deliveries[v.DeliveryID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterImports {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.managedClusters {
		if projects[v.ProjectID] {
			resources[v.ID] = true
			clusters[v.ID] = true
		}
	}
	for _, v := range s.clusterInventories {
		if clusters[v.ClusterID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceProfiles {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceWindows {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.clusterMaintenanceRuns {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.agentCertificates {
		if clusters[v.ClusterID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.baselineDeployments {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeVerifications {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeCertifications {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.recoveryCheckpoints {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.fleetGroups {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.driftScans {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.upgradeCampaigns {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.entitlements {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.oemProfiles {
		if organizations[v.OrganizationID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.tenants {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.providerProfiles {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.providerClusters {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.marketplaceRecommendations {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}
	for _, v := range s.runtimeClosureCampaigns {
		if projects[v.ProjectID] {
			resources[v.ID] = true
		}
	}

	out := make([]AuditEvent, 0, limit)
	for _, event := range s.audit {
		visible := resources[event.ResourceID]
		if !visible {
			if organizationID := auditMetadataScope(event.Metadata, "organizationId"); organizationID != "" {
				visible = organizations[organizationID]
			}
		}
		if !visible {
			if projectID := auditMetadataScope(event.Metadata, "projectId"); projectID != "" {
				visible = projects[projectID]
			}
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


func (s *MemoryStore) ListAuditPageByResource(_ context.Context, resourceType, resourceID string, limit int) ([]AuditEvent, error) {
	resourceType = strings.TrimSpace(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if resourceType == "" || resourceID == "" {
		return []AuditEvent{}, ErrValidation
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0, limit)
	for _, event := range s.audit {
		if event.ResourceType == resourceType && event.ResourceID == resourceID {
			out = append(out, event)
		}
	}
	auditNewestFirst(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
