package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/fleethealth"
	"platform.4so.io/factory/internal/supportbundle"
	"sort"
	"strings"
	"time"
)

func optionalClusterInventory(store controlplane.Store, ctx context.Context, clusterID string) (controlplane.ClusterInventory, error) {
	inventory, err := store.GetLatestClusterInventory(ctx, clusterID)
	if errors.Is(err, controlplane.ErrNotFound) {
		return controlplane.ClusterInventory{}, nil
	}
	return inventory, err
}

type clusterTimelinePageStore interface {
	ListClusterTimelineAuditPage(context.Context, string, int) ([]controlplane.AuditEvent, error)
}

type supportBundleRequest struct {
	Profile     string `json:"profile"`
	ProjectID   string `json:"projectId,omitempty"`
	ClusterID   string `json:"clusterId,omitempty"`
	OperationID string `json:"operationId,omitempty"`
}

type clusterSupportSnapshot struct {
	Cluster      controlplane.ManagedCluster     `json:"cluster"`
	Inventory    controlplane.ClusterInventory   `json:"inventory"`
	Certificates []controlplane.AgentCertificate `json:"agentCertificates"`
	Health       fleethealth.ClusterHealth       `json:"health"`
	Timeline     []controlplane.AuditEvent       `json:"timeline"`
}

func (s *Server) fleetHealth(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ids := boolSetIDs(allowed)
	if projectID != "" {
		ids, all = []string{projectID}, false
	}
	pager, ok := s.store.(managedClusterPageStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "BOUNDED_FLEET_HEALTH_UNAVAILABLE", "fleet health requires a bounded cluster pager")
		return
	}
	const fleetHealthLimit = 200
	clusters, err := pager.ListManagedClustersPage(r.Context(), ids, all, nil, fleetHealthLimit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("X-4SO-Result-Limit", fmt.Sprint(fleetHealthLimit))
	now := time.Now().UTC()
	rows := make([]fleethealth.ClusterHealth, 0, len(clusters))
	summary := map[string]int{"total": len(clusters), "healthy": 0, "warning": 0, "stale": 0, "critical": 0, "online": 0, "eol": 0}
	for _, cluster := range clusters {
		inventory, err := optionalClusterInventory(s.store, r.Context(), cluster.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		certificates, err := s.store.ListAgentCertificates(r.Context(), cluster.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		health := fleethealth.Evaluate(cluster, inventory, certificates, now)
		rows = append(rows, health)
		if health.Online {
			summary["online"]++
		}
		switch health.Health {
		case "HEALTHY":
			summary["healthy"]++
		case "WARNING":
			summary["warning"]++
		case "STALE":
			summary["stale"]++
		case "CRITICAL":
			summary["critical"]++
		}
		if health.KubernetesSupport.Status == "EOL" {
			summary["eol"]++
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Health != rows[j].Health {
			return healthRank(rows[i].Health) > healthRank(rows[j].Health)
		}
		return rows[i].Name < rows[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"generatedAt": now, "summary": summary, "summaryScope": "returned-clusters", "bounded": true, "resultLimit": fleetHealthLimit, "supportPolicy": fleethealth.SnapshotPolicy(now), "clusters": rows})
}

func healthRank(value string) int {
	switch value {
	case "CRITICAL":
		return 4
	case "STALE":
		return 3
	case "WARNING":
		return 2
	case "HEALTHY":
		return 1
	default:
		return 0
	}
}

func (s *Server) clusterTimeline(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	events, err := s.clusterTimelineEvents(r, cluster)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) clusterTimelineEvents(r *http.Request, cluster controlplane.ManagedCluster) ([]controlplane.AuditEvent, error) {
	pager, ok := s.store.(clusterTimelinePageStore)
	if !ok {
		return nil, fmt.Errorf("%w: cluster timeline requires bounded scoped audit pager", controlplane.ErrPrerequisite)
	}
	return pager.ListClusterTimelineAuditPage(r.Context(), cluster.ID, 200)
}

func (s *Server) supportBundleProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]any{
		{"name": "fleet-diagnostics", "scope": "project", "description": "Fleet health, inventory, operations and scoped audit for one project."},
		{"name": "cluster-diagnostics", "scope": "cluster", "description": "One cluster inventory, certificate health, timeline and related state."},
		{"name": "operation-diagnostics", "scope": "operation", "description": "One durable operation with steps, evidence metadata and scoped audit."},
	})
}

func (s *Server) createSupportBundle(w http.ResponseWriter, r *http.Request) {
	var input supportBundleRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.Profile = strings.TrimSpace(input.Profile)
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	input.OperationID = strings.TrimSpace(input.OperationID)
	now := time.Now().UTC()
	files := map[string]any{"support-policy.json": fleethealth.SnapshotPolicy(now)}
	scope := map[string]any{}
	filename := "4so-support-bundle.zip"

	switch input.Profile {
	case "fleet-diagnostics":
		if input.ProjectID == "" {
			writeError(w, http.StatusUnprocessableEntity, "SUPPORT_SCOPE_REQUIRED", "projectId is required for fleet-diagnostics")
			return
		}
		if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
		project, err := s.store.GetProject(r.Context(), input.ProjectID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		clusterPager, ok := s.store.(managedClusterPageStore)
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "BOUNDED_SUPPORT_BUNDLE_UNAVAILABLE", "fleet support bundles require a bounded cluster pager")
			return
		}
		const fleetBundleClusterLimit = 50
		clusters, err := clusterPager.ListManagedClustersPage(r.Context(), []string{input.ProjectID}, false, nil, fleetBundleClusterLimit+1)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if len(clusters) > fleetBundleClusterLimit {
			writeError(w, http.StatusUnprocessableEntity, "SUPPORT_BUNDLE_SCOPE_TOO_LARGE", "fleet-diagnostics is limited to 50 clusters per synchronous bundle; use cluster-diagnostics for a narrower incident scope")
			return
		}
		details := make([]clusterSupportSnapshot, 0, len(clusters))
		for _, cluster := range clusters {
			inventory, err := optionalClusterInventory(s.store, r.Context(), cluster.ID)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			certificates, err := s.store.ListAgentCertificates(r.Context(), cluster.ID)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			timeline, err := s.clusterTimelineEvents(r, cluster)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			details = append(details, clusterSupportSnapshot{Cluster: cluster, Inventory: inventory, Certificates: certificates, Health: fleethealth.Evaluate(cluster, inventory, certificates, now), Timeline: timeline})
		}
		opPager, ok := s.store.(operationPageStore)
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "BOUNDED_SUPPORT_BUNDLE_UNAVAILABLE", "fleet support bundles require bounded operation paging")
			return
		}
		const fleetBundleOperationLimit = 200
		operations, err := opPager.ListOperationsPage(r.Context(), input.ProjectID, fleetBundleOperationLimit+1)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if len(operations) > fleetBundleOperationLimit {
			writeError(w, http.StatusUnprocessableEntity, "SUPPORT_BUNDLE_SCOPE_TOO_LARGE", "fleet-diagnostics is limited to 200 recent operations per synchronous bundle; narrow the incident scope")
			return
		}
		audit, err := s.projectAuditEvents(r, project)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		files["project.json"] = project
		files["clusters.json"] = details
		files["operations.json"] = operations
		files["audit.json"] = audit
		scope = map[string]any{"projectId": project.ID, "organizationId": project.OrganizationID}
		filename = "4so-fleet-support-" + safeFileName(project.Name) + ".zip"
	case "cluster-diagnostics":
		if input.ClusterID == "" {
			writeError(w, http.StatusUnprocessableEntity, "SUPPORT_SCOPE_REQUIRED", "clusterId is required for cluster-diagnostics")
			return
		}
		cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
		inventory, err := optionalClusterInventory(s.store, r.Context(), cluster.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		certificates, err := s.store.ListAgentCertificates(r.Context(), cluster.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		timeline, err := s.clusterTimelineEvents(r, cluster)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		files["cluster.json"] = clusterSupportSnapshot{Cluster: cluster, Inventory: inventory, Certificates: certificates, Health: fleethealth.Evaluate(cluster, inventory, certificates, now), Timeline: timeline}
		scope = map[string]any{"projectId": cluster.ProjectID, "clusterId": cluster.ID}
		filename = "4so-cluster-support-" + safeFileName(cluster.Name) + ".zip"
	case "operation-diagnostics":
		if input.OperationID == "" {
			writeError(w, http.StatusUnprocessableEntity, "SUPPORT_SCOPE_REQUIRED", "operationId is required for operation-diagnostics")
			return
		}
		operation, err := s.store.GetOperation(r.Context(), input.OperationID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if _, err = s.requireProjectAccess(r, operation.ProjectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
		steps, err := s.store.ListOperationSteps(r.Context(), operation.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		evidence, err := s.store.ListEvidence(r.Context(), operation.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		project, err := s.store.GetProject(r.Context(), operation.ProjectID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		audit, err := s.projectAuditEvents(r, project)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		relatedAudit := make([]controlplane.AuditEvent, 0)
		for _, event := range audit {
			if event.ResourceID == operation.ID || metadataString(event.Metadata, "operationId") == operation.ID {
				relatedAudit = append(relatedAudit, event)
			}
		}
		files["operation.json"] = map[string]any{"operation": operation, "steps": steps, "evidence": evidence, "audit": relatedAudit}
		scope = map[string]any{"projectId": operation.ProjectID, "operationId": operation.ID}
		filename = "4so-operation-support-" + safeFileName(operation.ID) + ".zip"
	default:
		writeError(w, http.StatusUnprocessableEntity, "SUPPORT_PROFILE_INVALID", "profile must be fleet-diagnostics, cluster-diagnostics or operation-diagnostics")
		return
	}

	raw, manifest, err := supportbundle.Build(supportbundle.Input{ProductVersion: s.version, Profile: input.Profile, Scope: scope, GeneratedAt: now, Files: files})
	if err != nil {
		s.logger.Error("support bundle generation failed", "error", err, "profile", input.Profile)
		writeError(w, http.StatusInternalServerError, "SUPPORT_BUNDLE_FAILED", "support bundle could not be safely generated")
		return
	}
	verification, err := supportbundle.Verify(raw)
	if err != nil || !verification.Valid {
		writeError(w, http.StatusInternalServerError, "SUPPORT_BUNDLE_VERIFICATION_FAILED", "support bundle failed local secret-negative verification")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Support-Bundle-Digest", verification.Digest)
	w.Header().Set("X-Support-Bundle-Redactions", fmt.Sprint(manifest.Redactions))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) projectAuditEvents(r *http.Request, project controlplane.Project) ([]controlplane.AuditEvent, error) {
	pager, ok := s.store.(auditScopedPageStore)
	if !ok {
		return nil, fmt.Errorf("%w: project audit diagnostics require bounded scoped audit pager", controlplane.ErrPrerequisite)
	}
	return pager.ListAuditPageByScopes(r.Context(), nil, []string{project.ID}, 1000)
}

func safeFileName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		} else if r == '_' || r == ' ' || r == '.' {
			out.WriteByte('-')
		}
	}
	result := strings.Trim(out.String(), "-")
	if result == "" {
		return "resource"
	}
	if len(result) > 80 {
		result = result[:80]
	}
	return result
}
