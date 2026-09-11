package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"platform.4so.io/factory/internal/controlplane"
	"sort"
	"strings"
	"time"
)

const (
	searchProjectionAuthority  = "SEARCH_PROJECTION_AUTHORITY_V2"
	searchRebuildAuthority     = "SEARCH_PROJECTION_REBUILD_CONTRACT_V1"
	searchClusterSourceLimit   = 200
	searchOperationSourceLimit = 500
	searchEvidenceSourceLimit  = 500
	searchAuditSourceLimit     = 1000
)

type evidenceProjectPageStore interface {
	ListEvidencePageByProject(context.Context, string, int) ([]controlplane.EvidenceMetadata, error)
}

type searchProjectionDocument struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	SourceRef string    `json:"sourceRef"`
	UpdatedAt time.Time `json:"updatedAt"`
	Digest    string    `json:"digest"`
}

func finalizeSearchDocument(v searchProjectionDocument) searchProjectionDocument {
	v.Digest = ""
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	v.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return v
}

func searchDocumentSetDigest(values []searchProjectionDocument) string {
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Server) buildSearchProjectionDocuments(r *http.Request, projectID string) ([]searchProjectionDocument, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("projectId is required")
	}

	// Search is a bounded projection, never a second source of truth. Every
	// production pager scopes in the authority store before LIMIT; unrelated
	// tenant activity therefore cannot evict authorized rows from the page.
	clusterPager, ok := s.store.(managedClusterPageStore)
	if !ok {
		return nil, fmt.Errorf("search projection requires scope-aware managed-cluster paging")
	}
	clusters, err := clusterPager.ListManagedClustersPage(r.Context(), []string{projectID}, false, nil, searchClusterSourceLimit)
	if err != nil {
		return nil, err
	}

	operationPager, ok := s.store.(operationPageStore)
	if !ok {
		return nil, fmt.Errorf("search projection requires scope-aware operation paging")
	}
	operations, err := operationPager.ListOperationsPage(r.Context(), projectID, searchOperationSourceLimit)
	if err != nil {
		return nil, err
	}

	evidencePager, ok := s.store.(evidenceProjectPageStore)
	if !ok {
		return nil, fmt.Errorf("search projection requires scope-aware evidence paging")
	}
	evidence, err := evidencePager.ListEvidencePageByProject(r.Context(), projectID, searchEvidenceSourceLimit)
	if err != nil {
		return nil, err
	}

	auditPager, ok := s.store.(auditScopedPageStore)
	if !ok {
		return nil, fmt.Errorf("search projection requires scope-aware audit paging")
	}
	audit, err := auditPager.ListAuditPageByScopes(r.Context(), nil, []string{projectID}, searchAuditSourceLimit)
	if err != nil {
		return nil, err
	}

	docs := make([]searchProjectionDocument, 0, len(clusters)+len(operations)+len(evidence)+len(audit))
	allowedResources := map[string]bool{projectID: true}
	operationIDs := map[string]bool{}
	for _, cluster := range clusters {
		allowedResources[cluster.ID] = true
		docs = append(docs, finalizeSearchDocument(searchProjectionDocument{ID: "cluster:" + cluster.ID, ProjectID: projectID, Type: "cluster", Title: cluster.DisplayName, Summary: strings.TrimSpace(strings.Join([]string{cluster.Name, cluster.Distribution, cluster.KubernetesVersion, cluster.ConnectionState, strings.Join(cluster.Capabilities, " ")}, " ")), SourceRef: "managedCluster:" + cluster.ID, UpdatedAt: cluster.UpdatedAt}))
	}
	for _, operation := range operations {
		allowedResources[operation.ID] = true
		operationIDs[operation.ID] = true
		docs = append(docs, finalizeSearchDocument(searchProjectionDocument{ID: "operation:" + operation.ID, ProjectID: projectID, Type: "operation", Title: operation.Kind, Summary: strings.TrimSpace(strings.Join([]string{string(operation.State), operation.TargetRef, operation.Risk, operation.LastError}, " ")), SourceRef: "operation:" + operation.ID, UpdatedAt: operation.UpdatedAt}))
	}
	for _, item := range evidence {
		if !operationIDs[item.OperationID] {
			continue
		}
		docs = append(docs, finalizeSearchDocument(searchProjectionDocument{ID: "evidence:" + item.ID, ProjectID: projectID, Type: "evidence", Title: item.Kind, Summary: strings.TrimSpace(strings.Join([]string{item.MediaType, item.Digest, item.Location, item.StepKey}, " ")), SourceRef: "evidence:" + item.ID, UpdatedAt: item.UpdatedAt}))
	}
	for _, item := range audit {
		if !allowedResources[item.ResourceID] {
			continue
		}
		docs = append(docs, finalizeSearchDocument(searchProjectionDocument{ID: "audit:" + item.ID, ProjectID: projectID, Type: "audit", Title: item.Action, Summary: strings.TrimSpace(strings.Join([]string{item.ActorID, item.ResourceType, item.ResourceID, item.RequestID}, " ")), SourceRef: "audit:" + item.ID, UpdatedAt: item.OccurredAt}))
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Type != docs[j].Type {
			return docs[i].Type < docs[j].Type
		}
		return docs[i].ID < docs[j].ID
	})
	return docs, nil
}

func filterSearchProjectionDocuments(docs []searchProjectionDocument, query string, limit int) []searchProjectionDocument {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" || limit < 1 {
		return []searchProjectionDocument{}
	}
	result := make([]searchProjectionDocument, 0)
	for _, doc := range docs {
		haystack := strings.ToLower(doc.Type + " " + doc.Title + " " + doc.Summary + " " + doc.SourceRef)
		if strings.Contains(haystack, query) {
			result = append(result, doc)
			if len(result) >= limit {
				break
			}
		}
	}
	return result
}

func (s *Server) searchProjectionRebuild(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	docs, err := s.buildSearchProjectionDocuments(r, projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authority": searchProjectionAuthority, "rebuildAuthority": searchRebuildAuthority, "projectId": projectID, "backend": "postgresql-bounded", "optionalScaleBackend": "opensearch", "scopeAppliedBeforeLimit": true, "sourceLimits": map[string]int{"clusters": searchClusterSourceLimit, "operations": searchOperationSourceLimit, "evidence": searchEvidenceSourceLimit, "audit": searchAuditSourceLimit}, "documents": docs, "documentCount": len(docs), "digest": searchDocumentSetDigest(docs), "rebuildable": true, "sourceOfTruth": false})
}

func (s *Server) searchProjectionQuery(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query == "" {
		writeError(w, http.StatusBadRequest, "QUERY_REQUIRED", "q is required")
		return
	}
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	docs, err := s.buildSearchProjectionDocuments(r, projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	result := filterSearchProjectionDocuments(docs, query, 100)
	writeJSON(w, http.StatusOK, map[string]any{"authority": searchProjectionAuthority, "backend": "postgresql-bounded", "scopeAppliedBeforeLimit": true, "projectId": projectID, "query": strings.TrimSpace(r.URL.Query().Get("q")), "results": result, "resultCount": len(result), "bounded": true, "limit": 100, "sourceOfTruth": false})
}
