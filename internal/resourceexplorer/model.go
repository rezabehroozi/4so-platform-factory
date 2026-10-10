package resourceexplorer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	BoundedResourceExplorerAuthority = "BOUNDED_RESOURCE_EXPLORER_AUTHORITY_V1"
	ResourceObservationAuthority     = "RESOURCE_EXPLORER_OBSERVATION_V1"
	cursorVersion                    = 1
	maxPageLimit                     = 200
	maxCursorBytes                   = 2048
)

type TruthState string

const (
	TruthFresh     TruthState = "FRESH"
	TruthStale     TruthState = "STALE"
	TruthUnknown   TruthState = "UNKNOWN"
	TruthForbidden TruthState = "FORBIDDEN"
)

type ResourceKey struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type ResourceReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type ResourceObservation struct {
	Authority           string              `json:"authority"`
	OrganizationID      string              `json:"organizationId"`
	ProjectID           string              `json:"projectId"`
	ClusterID           string              `json:"clusterId"`
	Key                 ResourceKey         `json:"key"`
	State               TruthState          `json:"state"`
	ObservedAt          time.Time           `json:"observedAt"`
	SourceDigest        string              `json:"sourceDigest"`
	Summary             map[string]string   `json:"summary,omitempty"`
	OwnerReferences     []ResourceReference `json:"ownerReferences,omitempty"`
	RelatedEventDigests []string            `json:"relatedEventDigests,omitempty"`
}

type ResourceQuery struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
	ClusterID      string `json:"clusterId"`
	APIVersion     string `json:"apiVersion,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Limit          int    `json:"limit"`
	Cursor         string `json:"cursor,omitempty"`
}

type ResourceSummary struct {
	Key                 ResourceKey         `json:"key"`
	State               TruthState          `json:"state"`
	ObservedAt          time.Time           `json:"observedAt"`
	SourceDigest        string              `json:"sourceDigest"`
	Summary             map[string]string   `json:"summary,omitempty"`
	OwnerReferences     []ResourceReference `json:"ownerReferences,omitempty"`
	RelatedEventDigests []string            `json:"relatedEventDigests,omitempty"`
}

type ResourcePage struct {
	Authority      string            `json:"authority"`
	OrganizationID string            `json:"organizationId"`
	ProjectID      string            `json:"projectId"`
	ClusterID      string            `json:"clusterId"`
	Items          []ResourceSummary `json:"items"`
	HasMore        bool              `json:"hasMore"`
	NextCursor     string            `json:"nextCursor,omitempty"`
}

type ResourceDetail struct {
	Authority           string              `json:"authority"`
	OrganizationID      string              `json:"organizationId"`
	ProjectID           string              `json:"projectId"`
	ClusterID           string              `json:"clusterId"`
	Key                 ResourceKey         `json:"key"`
	State               TruthState          `json:"state"`
	ObservedAt          time.Time           `json:"observedAt"`
	EvidenceDigest      string              `json:"evidenceDigest"`
	Summary             map[string]string   `json:"summary,omitempty"`
	OwnerReferences     []ResourceReference `json:"ownerReferences,omitempty"`
	RelatedEventDigests []string            `json:"relatedEventDigests,omitempty"`
	ReadOnly            bool                `json:"readOnly"`
	AllowedVerbs        []string            `json:"allowedVerbs,omitempty"`
}

type cursorEnvelope struct {
	Version     int    `json:"v"`
	QueryDigest string `json:"queryDigest"`
	ObservedAt  string `json:"observedAt"`
	SortKey     string `json:"sortKey"`
}

func BuildPage(observations []ResourceObservation, query ResourceQuery, now time.Time, freshness time.Duration) (ResourcePage, error) {
	query = normalizeQuery(query)
	if err := validateQuery(query); err != nil {
		return ResourcePage{}, err
	}
	if now.IsZero() || freshness <= 0 || freshness > 24*time.Hour {
		return ResourcePage{}, errors.New("resource explorer now/freshness is invalid")
	}
	queryDigest := digestQuery(query)
	cursor, err := decodeCursor(query.Cursor)
	if err != nil {
		return ResourcePage{}, err
	}
	if cursor != nil && cursor.QueryDigest != queryDigest {
		return ResourcePage{}, errors.New("resource explorer cursor does not match query scope/filter")
	}
	filtered := make([]ResourceSummary, 0, len(observations))
	for _, observation := range observations {
		if strings.TrimSpace(observation.OrganizationID) != query.OrganizationID || strings.TrimSpace(observation.ProjectID) != query.ProjectID || strings.TrimSpace(observation.ClusterID) != query.ClusterID {
			continue
		}
		if query.APIVersion != "" && strings.TrimSpace(observation.Key.APIVersion) != query.APIVersion {
			continue
		}
		if query.Kind != "" && strings.TrimSpace(observation.Key.Kind) != query.Kind {
			continue
		}
		if query.Namespace != "" && strings.TrimSpace(observation.Key.Namespace) != query.Namespace {
			continue
		}
		item, err := normalizeObservation(observation, now, freshness)
		if err != nil {
			return ResourcePage{}, err
		}
		filtered = append(filtered, item)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].ObservedAt.Equal(filtered[j].ObservedAt) {
			return summarySortKey(filtered[i]) > summarySortKey(filtered[j])
		}
		return filtered[i].ObservedAt.After(filtered[j].ObservedAt)
	})
	if cursor != nil {
		kept := filtered[:0]
		for _, item := range filtered {
			key := summarySortKey(item)
			if item.ObservedAt.Before(cursor.ObservedAt) || (item.ObservedAt.Equal(cursor.ObservedAt) && key < cursor.SortKey) {
				kept = append(kept, item)
			}
		}
		filtered = kept
	}
	hasMore := len(filtered) > query.Limit
	if hasMore {
		filtered = filtered[:query.Limit]
	}
	page := ResourcePage{Authority: BoundedResourceExplorerAuthority, OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, ClusterID: query.ClusterID, Items: filtered, HasMore: hasMore}
	if hasMore && len(filtered) > 0 {
		last := filtered[len(filtered)-1]
		page.NextCursor, err = encodeCursor(cursorEnvelope{Version: cursorVersion, QueryDigest: queryDigest, ObservedAt: last.ObservedAt.UTC().Format(time.RFC3339Nano), SortKey: summarySortKey(last)})
		if err != nil {
			return ResourcePage{}, err
		}
	}
	return page, nil
}

func BuildDetail(observation ResourceObservation, now time.Time, freshness time.Duration) (ResourceDetail, error) {
	if now.IsZero() || freshness <= 0 || freshness > 24*time.Hour {
		return ResourceDetail{}, errors.New("resource explorer now/freshness is invalid")
	}
	item, err := normalizeObservation(observation, now, freshness)
	if err != nil {
		return ResourceDetail{}, err
	}
	return ResourceDetail{
		Authority: BoundedResourceExplorerAuthority,
		OrganizationID: strings.TrimSpace(observation.OrganizationID),
		ProjectID: strings.TrimSpace(observation.ProjectID),
		ClusterID: strings.TrimSpace(observation.ClusterID),
		Key: item.Key,
		State: item.State,
		ObservedAt: item.ObservedAt,
		EvidenceDigest: item.SourceDigest,
		Summary: cloneSummary(item.Summary),
		OwnerReferences: append([]ResourceReference(nil), item.OwnerReferences...),
		RelatedEventDigests: append([]string(nil), item.RelatedEventDigests...),
		ReadOnly: true,
		AllowedVerbs: []string{},
	}, nil
}

func normalizeQuery(query ResourceQuery) ResourceQuery {
	query.OrganizationID = strings.TrimSpace(query.OrganizationID)
	query.ProjectID = strings.TrimSpace(query.ProjectID)
	query.ClusterID = strings.TrimSpace(query.ClusterID)
	query.APIVersion = strings.TrimSpace(query.APIVersion)
	query.Kind = strings.TrimSpace(query.Kind)
	query.Namespace = strings.TrimSpace(query.Namespace)
	query.Cursor = strings.TrimSpace(query.Cursor)
	return query
}

func validateQuery(query ResourceQuery) error {
	if query.OrganizationID == "" || query.ProjectID == "" || query.ClusterID == "" {
		return errors.New("resource explorer organization/project/cluster scope is required")
	}
	if query.Limit < 1 || query.Limit > maxPageLimit {
		return fmt.Errorf("resource explorer limit must be between 1 and %d", maxPageLimit)
	}
	if len(query.APIVersion) > 160 || len(query.Kind) > 160 || len(query.Namespace) > 253 || len(query.OrganizationID) > 256 || len(query.ProjectID) > 256 || len(query.ClusterID) > 256 {
		return errors.New("resource explorer query field exceeds bounded length")
	}
	return nil
}

func normalizeObservation(observation ResourceObservation, now time.Time, freshness time.Duration) (ResourceSummary, error) {
	if observation.Authority != ResourceObservationAuthority {
		return ResourceSummary{}, errors.New("resource observation authority is invalid")
	}
	observation.OrganizationID = strings.TrimSpace(observation.OrganizationID)
	observation.ProjectID = strings.TrimSpace(observation.ProjectID)
	observation.ClusterID = strings.TrimSpace(observation.ClusterID)
	observation.Key.APIVersion = strings.TrimSpace(observation.Key.APIVersion)
	observation.Key.Kind = strings.TrimSpace(observation.Key.Kind)
	observation.Key.Namespace = strings.TrimSpace(observation.Key.Namespace)
	observation.Key.Name = strings.TrimSpace(observation.Key.Name)
	observation.Key.UID = strings.TrimSpace(observation.Key.UID)
	observation.SourceDigest = strings.ToLower(strings.TrimSpace(observation.SourceDigest))
	if !validTruthState(observation.State) {
		return ResourceSummary{}, errors.New("resource observation truth state is invalid")
	}
	requiresUID := observation.State == TruthFresh || observation.State == TruthStale
	if observation.OrganizationID == "" || observation.ProjectID == "" || observation.ClusterID == "" || observation.Key.APIVersion == "" || observation.Key.Kind == "" || observation.Key.Name == "" || (requiresUID && observation.Key.UID == "") || observation.ObservedAt.IsZero() || observation.ObservedAt.After(now) || !validDigest(observation.SourceDigest) {
		return ResourceSummary{}, errors.New("resource observation identity/evidence/time is invalid")
	}
	state := observation.State
	if state == TruthFresh && now.Sub(observation.ObservedAt) > freshness {
		state = TruthStale
	}
	summary, err := sanitizeSummary(observation.Key.Kind, observation.Summary)
	if err != nil {
		return ResourceSummary{}, err
	}
	owners, err := normalizeReferences(observation.OwnerReferences)
	if err != nil {
		return ResourceSummary{}, err
	}
	events, err := normalizeDigests(observation.RelatedEventDigests)
	if err != nil {
		return ResourceSummary{}, err
	}
	return ResourceSummary{Key: observation.Key, State: state, ObservedAt: observation.ObservedAt.UTC(), SourceDigest: observation.SourceDigest, Summary: summary, OwnerReferences: owners, RelatedEventDigests: events}, nil
}

func sanitizeSummary(kind string, input map[string]string) (map[string]string, error) {
	if len(input) > 32 {
		return nil, errors.New("resource explorer summary exceeds bounded field count")
	}
	out := make(map[string]string, len(input))
	secretKind := strings.EqualFold(strings.TrimSpace(kind), "Secret")
	secretAllowed := map[string]bool{"type":true,"immutable":true,"keyCount":true,"status":true}
	for rawKey, rawValue := range input {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		lower := strings.ToLower(key)
		if key == "" || len(key) > 128 || len(value) > 512 {
			return nil, errors.New("resource explorer summary field is invalid or oversized")
		}
		if secretKind && !secretAllowed[key] {
			return nil, errors.New("resource explorer secret summary contains non-redacted field")
		}
		for _, blocked := range []string{"password","token","secret","credential","privatekey","private-key","kubeconfig","stringdata","userdata"} {
			if strings.Contains(lower, blocked) {
				return nil, errors.New("resource explorer summary contains sensitive field name")
			}
		}
		out[key] = value
	}
	return out, nil
}

func normalizeReferences(input []ResourceReference) ([]ResourceReference, error) {
	out := append([]ResourceReference(nil), input...)
	for i := range out {
		out[i].APIVersion = strings.TrimSpace(out[i].APIVersion)
		out[i].Kind = strings.TrimSpace(out[i].Kind)
		out[i].Namespace = strings.TrimSpace(out[i].Namespace)
		out[i].Name = strings.TrimSpace(out[i].Name)
		if out[i].APIVersion == "" || out[i].Kind == "" || out[i].Name == "" {
			return nil, errors.New("resource explorer owner reference is incomplete")
		}
	}
	sort.Slice(out, func(i, j int) bool { return referenceSortKey(out[i]) < referenceSortKey(out[j]) })
	for i := 1; i < len(out); i++ {
		if referenceSortKey(out[i-1]) == referenceSortKey(out[i]) {
			return nil, errors.New("resource explorer owner references contain duplicates")
		}
	}
	return out, nil
}

func normalizeDigests(input []string) ([]string, error) {
	out := make([]string, 0, len(input))
	seen := map[string]bool{}
	for _, raw := range input {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !validDigest(value) || seen[value] {
			return nil, errors.New("resource explorer related event digests are invalid or duplicated")
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validTruthState(state TruthState) bool {
	switch state {
	case TruthFresh, TruthStale, TruthUnknown, TruthForbidden:
		return true
	default:
		return false
	}
}

func digestQuery(query ResourceQuery) string {
	copy := query
	copy.Cursor = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func summarySortKey(item ResourceSummary) string {
	return strings.Join([]string{item.Key.APIVersion,item.Key.Kind,item.Key.Namespace,item.Key.Name,item.Key.UID}, "\x00")
}

func referenceSortKey(item ResourceReference) string {
	return strings.Join([]string{item.APIVersion,item.Kind,item.Namespace,item.Name}, "\x00")
}

func cloneSummary(input map[string]string) map[string]string {
	if input == nil { return nil }
	out := make(map[string]string, len(input))
	for key, value := range input { out[key] = value }
	return out
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") { return false }
	for _, r := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", r) { return false }
	}
	return true
}

func encodeCursor(cursor cursorEnvelope) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil { return "", err }
	if len(raw) > maxCursorBytes { return "", errors.New("resource explorer cursor payload is too large") }
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(raw string) (*struct { QueryDigest string; ObservedAt time.Time; SortKey string }, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" { return nil, nil }
	if len(raw) > maxCursorBytes*2 { return nil, errors.New("resource explorer cursor is too large") }
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(payload) == 0 || len(payload) > maxCursorBytes { return nil, errors.New("resource explorer cursor encoding is invalid") }
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var envelope cursorEnvelope
	if err := dec.Decode(&envelope); err != nil || dec.More() { return nil, errors.New("resource explorer cursor payload is invalid") }
	if envelope.Version != cursorVersion || !validDigest(strings.ToLower(strings.TrimSpace(envelope.QueryDigest))) || strings.TrimSpace(envelope.SortKey) == "" { return nil, errors.New("resource explorer cursor authority is invalid") }
	observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(envelope.ObservedAt))
	if err != nil || observedAt.IsZero() { return nil, errors.New("resource explorer cursor timestamp is invalid") }
	return &struct { QueryDigest string; ObservedAt time.Time; SortKey string }{QueryDigest:strings.ToLower(strings.TrimSpace(envelope.QueryDigest)),ObservedAt:observedAt.UTC(),SortKey:envelope.SortKey}, nil
}
