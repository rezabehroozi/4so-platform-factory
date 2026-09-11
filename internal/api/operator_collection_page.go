package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"sort"
	"strconv"
	"strings"
	"time"
)

const operatorCollectionDefaultLimit = 100
const operatorCollectionMaxLimit = 200

const operatorCollectionCursorVersion = 1
const OperatorCollectionCursorAuthority = "OPERATOR_COLLECTION_CURSOR_V1"
const operatorCollectionCursorMaxBytes = 1024

type operatorCollectionCursorEnvelope struct {
	Version   int    `json:"v"`
	UpdatedAt string `json:"updatedAt"`
	ID        string `json:"id"`
}

func encodeOperatorCollectionCursor(cursor controlplane.CollectionCursor) (string, error) {
	id := strings.TrimSpace(cursor.ID)
	if id == "" || len(id) > 256 || cursor.UpdatedAt.IsZero() {
		return "", fmt.Errorf("%w: invalid collection cursor boundary", controlplane.ErrValidation)
	}
	payload, err := json.Marshal(operatorCollectionCursorEnvelope{
		Version:   operatorCollectionCursorVersion,
		UpdatedAt: cursor.UpdatedAt.UTC().Format(time.RFC3339Nano),
		ID:        id,
	})
	if err != nil {
		return "", fmt.Errorf("%w: encode collection cursor", controlplane.ErrValidation)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func operatorCollectionCursor(r *http.Request) (*controlplane.CollectionCursor, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if raw == "" {
		return nil, nil
	}
	if len(raw) > operatorCollectionCursorMaxBytes*2 {
		return nil, fmt.Errorf("%w: cursor is too large", controlplane.ErrValidation)
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(payload) == 0 || len(payload) > operatorCollectionCursorMaxBytes {
		return nil, fmt.Errorf("%w: invalid cursor encoding", controlplane.ErrValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var envelope operatorCollectionCursorEnvelope
	if err = dec.Decode(&envelope); err != nil || dec.More() {
		return nil, fmt.Errorf("%w: invalid cursor payload", controlplane.ErrValidation)
	}
	if envelope.Version != operatorCollectionCursorVersion {
		return nil, fmt.Errorf("%w: unsupported cursor version", controlplane.ErrValidation)
	}
	id := strings.TrimSpace(envelope.ID)
	if id == "" || len(id) > 256 {
		return nil, fmt.Errorf("%w: invalid cursor id", controlplane.ErrValidation)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(envelope.UpdatedAt))
	if err != nil || updatedAt.IsZero() {
		return nil, fmt.Errorf("%w: invalid cursor timestamp", controlplane.ErrValidation)
	}
	return &controlplane.CollectionCursor{UpdatedAt: updatedAt.UTC(), ID: id}, nil
}

func boundedCollectionWindow[T any](items []T, cursor *controlplane.CollectionCursor, limit int, metaOf func(T) controlplane.ResourceMeta) []T {
	out := append([]T(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := metaOf(out[i]), metaOf(out[j])
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return a.ID > b.ID
		}
		return a.UpdatedAt.After(b.UpdatedAt)
	})
	if cursor != nil {
		filtered := out[:0]
		for _, item := range out {
			meta := metaOf(item)
			if meta.UpdatedAt.Before(cursor.UpdatedAt) || (meta.UpdatedAt.Equal(cursor.UpdatedAt) && meta.ID < cursor.ID) {
				filtered = append(filtered, item)
			}
		}
		out = filtered
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func operatorCollectionLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return operatorCollectionDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > operatorCollectionMaxLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", controlplane.ErrValidation, operatorCollectionMaxLimit)
	}
	return n, nil
}

func boundedProjectCollection[T controlplane.CollectionItem](s *Server, w http.ResponseWriter, r *http.Request, projectID string, legacy func() ([]T, error), page func([]string, bool, *controlplane.CollectionCursor, int) ([]T, error), projectOf func(T) string) ([]T, error) {
	metaOf := func(item T) controlplane.ResourceMeta { return item.CollectionMeta() }
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		return nil, err
	}
	ids := boolSetIDs(allowed)
	filterAllowed, filterAll := allowed, all
	if strings.TrimSpace(projectID) != "" {
		projectID = strings.TrimSpace(projectID)
		ids = []string{projectID}
		all = false
		filterAllowed = map[string]bool{projectID: true}
		filterAll = false
	}
	limit, err := operatorCollectionLimit(r)
	if err != nil {
		return nil, err
	}
	cursor, err := operatorCollectionCursor(r)
	if err != nil {
		return nil, err
	}
	fetchLimit := limit + 1
	var values []T
	if page != nil {
		values, err = page(ids, all, cursor, fetchLimit)
	} else {
		values, err = legacy()
		if err == nil {
			values = filterProjectScoped(values, filterAllowed, filterAll, projectOf)
			values = boundedCollectionWindow(values, cursor, fetchLimit, metaOf)
		}
	}
	if err != nil {
		return nil, err
	}
	if values == nil {
		values = []T{}
	}
	// Adapters are required to apply the cursor before LIMIT. Re-sorting the
	// small fetched window here keeps response order deterministic without
	// weakening the adapter-side scope-before-limit contract.
	values = boundedCollectionWindow(values, nil, fetchLimit, metaOf)
	hasMore := len(values) > limit
	if hasMore {
		values = values[:limit]
	}
	w.Header().Set("X-4SO-Pagination-Authority", OperatorCollectionCursorAuthority)
	w.Header().Set("X-4SO-Result-Limit", strconv.Itoa(limit))
	w.Header().Set("X-4SO-Result-Order", "updatedAt:desc,id:desc")
	if hasMore && len(values) > 0 {
		last := metaOf(values[len(values)-1])
		token, encodeErr := encodeOperatorCollectionCursor(controlplane.CollectionCursor{UpdatedAt: last.UpdatedAt, ID: last.ID})
		if encodeErr != nil {
			return nil, encodeErr
		}
		w.Header().Set("X-4SO-Next-Cursor", token)
		next := *r.URL
		query := next.Query()
		query.Set("limit", strconv.Itoa(limit))
		query.Set("cursor", token)
		next.RawQuery = query.Encode()
		w.Header().Set("Link", "<"+next.String()+">; rel=\"next\"")
	}
	return values, nil
}

func writeOperatorCollectionJSON(w http.ResponseWriter, _ *http.Request, status int, value any) {
	writeJSON(w, status, value)
}

type managedClusterPageStore interface {
	ListManagedClustersPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ManagedCluster, error)
}
type clusterImportPageStore interface {
	ListClusterImportsPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ClusterImport, error)
}
type baselineDeploymentPageStore interface {
	ListBaselineDeploymentsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.BaselineDeployment, error)
}
type runtimeVerificationPageStore interface {
	ListRuntimeVerificationsPage(context.Context, []string, bool, string, string, *controlplane.CollectionCursor, int) ([]controlplane.RuntimeVerification, error)
}
type runtimeClosurePageStore interface {
	ListRuntimeClosureCampaignsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.RuntimeClosureCampaign, error)
}
type runtimeCertificationPageStore interface {
	ListRuntimeCertificationsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.RuntimeCertificationRun, error)
}
type providerProfilePageStore interface {
	ListProviderProfilesPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.ProviderProfile, error)
}
type providerClusterPageStore interface {
	ListProviderClustersPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.ProviderCluster, error)
}
type driftScanPageStore interface {
	ListDriftScansPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.DriftScan, error)
}
type tenantPageStore interface {
	ListTenantsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.TenantEnvironment, error)
}
type aiRunPageStore interface {
	ListAIRunsPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.AIRun, error)
}
type blueprintReleasePageStore interface {
	ListBlueprintReleasesPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.BlueprintRelease, error)
}
type platformTemplatePageStore interface {
	ListPlatformTemplatesPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.PlatformTemplate, error)
}
type workspacePageStore interface {
	ListWorkspacesPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.Workspace, error)
}
type recoveryCheckpointPageStore interface {
	ListRecoveryCheckpointsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.RecoveryCheckpoint, error)
}
type fleetGroupPageStore interface {
	ListFleetGroupsPage(context.Context, []string, bool, *controlplane.CollectionCursor, int) ([]controlplane.FleetGroup, error)
}
type upgradeCampaignPageStore interface {
	ListUpgradeCampaignsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.UpgradeCampaign, error)
}
type marketplaceInstallationPageStore interface {
	ListMarketplaceInstallationsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.BaselineDeployment, error)
}
type marketplaceRecommendationPageStore interface {
	ListMarketplaceRecommendationsPage(context.Context, []string, bool, string, *controlplane.CollectionCursor, int) ([]controlplane.MarketplaceRecommendation, error)
}
