package api

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/redaction"
)

const mcpRouteParityAuthority = "MCP_ROUTE_PARITY_AUTHORITY_V1"

type mcpRouteParityEntry struct {
	Method              string   `json:"method"`
	Path                string   `json:"path"`
	Family              string   `json:"family"`
	Action              string   `json:"action"`
	Disposition         string   `json:"disposition"`
	ToolName            string   `json:"toolName"`
	Risk                string   `json:"risk"`
	PathParams          []string `json:"pathParams"`
	ConfirmationHeader  string   `json:"confirmationHeader"`
	ConfirmationValue   string   `json:"confirmationValue"`
	ExclusionReason     string   `json:"exclusionReason"`
	DurableJob          bool     `json:"durableJob"`
	IdempotencyRequired bool     `json:"idempotencyRequired"`
}
type mcpRouteParityRegistry struct {
	Authority  string                `json:"authority"`
	Source     string                `json:"source"`
	RouteCount int                   `json:"routeCount"`
	Counts     map[string]int        `json:"counts"`
	Routes     []mcpRouteParityEntry `json:"routes"`
}

//go:embed mcp_route_parity_registry.json
var rawMCPRouteParityRegistry []byte

func loadMCPRouteParityRegistry() mcpRouteParityRegistry {
	var v mcpRouteParityRegistry
	if err := json.Unmarshal(rawMCPRouteParityRegistry, &v); err != nil {
		panic(fmt.Errorf("decode MCP route parity registry: %w", err))
	}
	if v.Authority != mcpRouteParityAuthority || v.RouteCount != len(v.Routes) {
		panic("invalid MCP route parity registry")
	}
	return v
}

func mcpRouteTools() []mcpTool {
	registry := loadMCPRouteParityRegistry()
	out := make([]mcpTool, 0, registry.RouteCount)
	for _, route := range registry.Routes {
		if route.Disposition == "security-excluded" || route.ToolName == "" {
			continue
		}
		props := map[string]any{}
		required := []string{}
		for _, p := range route.PathParams {
			props[p] = map[string]any{"type": "string", "minLength": 1, "maxLength": 500}
			required = append(required, p)
		}
		props["query"] = map[string]any{"type": "object", "additionalProperties": true, "description": "Canonical route query parameters; the fixed route handler remains authoritative."}
		if route.Method != "GET" {
			props["body"] = map[string]any{"type": "object", "additionalProperties": true, "description": "Canonical JSON request body for this fixed action. Unknown/invalid fields remain rejected by the product handler."}
		}
		props["ifMatch"] = map[string]any{"type": "integer", "minimum": 1, "description": "Optional optimistic-concurrency revision translated only to If-Match."}
		if route.ConfirmationHeader != "" {
			props["confirm"] = map[string]any{"type": "boolean", "const": true, "description": "Explicitly confirm this high-impact product action; the server supplies the fixed confirmation phrase."}
			required = append(required, "confirm")
		}
		if route.IdempotencyRequired {
			props["idempotencyKey"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 200}
			required = append(required, "idempotencyKey")
		}
		schema := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			schema["required"] = required
		}
		permission := controlplane.APITokenPermissionMCPRead
		admin := false
		if route.Disposition != "tool-read" {
			permission = controlplane.APITokenPermissionMCPOperate
		}
		if route.Disposition == "tool-admin" {
			admin = true
		}
		out = append(out, mcpTool{Name: route.ToolName, Title: strings.ToUpper(route.Method) + " " + route.Path, Description: "Invoke the fixed product action " + route.Method + " " + route.Path + " through the canonical REST handler. The model cannot choose another route or method.", InputSchema: schema, RequiredPermission: permission, Family: route.Family, Risk: route.Risk, AdministrationOnly: admin})
	}
	return out
}

func mcpRouteByTool(name string) (mcpRouteParityEntry, bool) {
	for _, v := range loadMCPRouteParityRegistry().Routes {
		if v.ToolName == name && v.Disposition != "security-excluded" {
			return v, true
		}
	}
	return mcpRouteParityEntry{}, false
}

func mcpScalarQuery(values url.Values, key string, value any) bool {
	switch v := value.(type) {
	case string:
		values.Add(key, v)
		return true
	case bool:
		values.Add(key, strconv.FormatBool(v))
		return true
	case float64:
		values.Add(key, strconv.FormatFloat(v, 'f', -1, 64))
		return true
	case json.Number:
		values.Add(key, v.String())
		return true
	case []any:
		for _, item := range v {
			if !mcpScalarQuery(values, key, item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func buildMCPRouteRequest(r *http.Request, route mcpRouteParityEntry, args map[string]any, idempotencyKey string) (*http.Request, []byte, error) {
	path := route.Path
	for _, p := range route.PathParams {
		raw, ok := args[p].(string)
		raw = strings.TrimSpace(raw)
		if !ok || raw == "" || len(raw) > 500 {
			return nil, nil, fmt.Errorf("bounded path parameter %s is required", p)
		}
		path = strings.ReplaceAll(path, "{"+p+"}", url.PathEscape(raw))
	}
	values := url.Values{}
	if raw, ok := args["query"]; ok {
		q, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("query must be an object")
		}
		if len(q) > 64 {
			return nil, nil, fmt.Errorf("query has too many fields")
		}
		for key, value := range q {
			if strings.TrimSpace(key) == "" || len(key) > 100 || !mcpScalarQuery(values, key, value) {
				return nil, nil, fmt.Errorf("query field %q is invalid", key)
			}
		}
	}
	var body []byte
	if raw, ok := args["body"]; ok {
		obj, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("body must be an object")
		}
		var err error
		body, err = json.Marshal(obj)
		if err != nil {
			return nil, nil, err
		}
		if len(body) > 1<<20 {
			return nil, nil, fmt.Errorf("body exceeds 1 MiB")
		}
	}
	target := path
	if encoded := values.Encode(); encoded != "" {
		target += "?" + encoded
	}
	sub, err := http.NewRequestWithContext(r.Context(), route.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	sub.Header = r.Header.Clone()
	sub.Header.Del("Mcp-Method")
	sub.Header.Del("Mcp-Name")
	sub.Header.Del("MCP-Protocol-Version")
	sub.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		sub.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if raw, ok := args["ifMatch"]; ok {
		switch v := raw.(type) {
		case float64:
			if v < 1 {
				return nil, nil, fmt.Errorf("ifMatch must be positive")
			}
			sub.Header.Set("If-Match", strconv.FormatInt(int64(v), 10))
		case json.Number:
			sub.Header.Set("If-Match", v.String())
		default:
			return nil, nil, fmt.Errorf("ifMatch must be an integer")
		}
	}
	if route.ConfirmationHeader != "" {
		confirmed, ok := args["confirm"].(bool)
		if !ok || !confirmed {
			return nil, nil, fmt.Errorf("explicit confirmation is required")
		}
		sub.Header.Set(route.ConfirmationHeader, route.ConfirmationValue)
	}
	return sub, body, nil
}

type cappedRecorder struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *cappedRecorder) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *cappedRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *cappedRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n := len(p)
	remaining := (1 << 20) - w.body.Len()
	if remaining > 0 {
		if remaining > n {
			remaining = n
		}
		_, _ = w.body.Write(p[:remaining])
	}
	if n > remaining {
		w.overflow = true
	}
	return n, nil
}

func sanitizedMCPRouteResponse(status int, raw []byte, overflow bool) ([]byte, any) {
	if overflow {
		value := map[string]any{"statusCode": status, "truncated": true, "detail": "canonical response exceeded the 1 MiB MCP capture boundary"}
		out, _ := json.Marshal(value)
		return out, value
	}
	var decoded any
	if len(raw) > 0 && json.Unmarshal(raw, &decoded) == nil {
		clean, _ := redaction.Value(decoded)
		wrapped := map[string]any{"statusCode": status, "result": clean}
		out, _ := json.Marshal(wrapped)
		if len(out) <= 65536 {
			return out, wrapped
		}
		digest := controlplane.OperationRequestPayloadDigest(out)
		small := map[string]any{"statusCode": status, "truncated": true, "responseDigest": digest, "detail": "sanitized response exceeded the 64 KiB durable MCP result boundary"}
		b, _ := json.Marshal(small)
		return b, small
	}
	clean, _ := redaction.String(string(raw))
	wrapped := map[string]any{"statusCode": status, "result": clean}
	out, _ := json.Marshal(wrapped)
	if len(out) > 65536 {
		out = []byte(`{"statusCode":502,"truncated":true}`)
		wrapped = map[string]any{"statusCode": 502, "truncated": true}
	}
	return out, wrapped
}

func extractMCPJobScope(args map[string]any, principalOrg, principalProject string) (string, string) {
	org, project := strings.TrimSpace(principalOrg), strings.TrimSpace(principalProject)
	if v, ok := args["organizationId"].(string); ok && strings.TrimSpace(v) != "" {
		org = strings.TrimSpace(v)
	}
	if v, ok := args["projectId"].(string); ok && strings.TrimSpace(v) != "" {
		project = strings.TrimSpace(v)
	}
	if body, ok := args["body"].(map[string]any); ok {
		if v, ok := body["organizationId"].(string); ok && strings.TrimSpace(v) != "" {
			org = strings.TrimSpace(v)
		}
		if v, ok := body["projectId"].(string); ok && strings.TrimSpace(v) != "" {
			project = strings.TrimSpace(v)
		}
	}
	if q, ok := args["query"].(map[string]any); ok {
		if v, ok := q["organizationId"].(string); ok && strings.TrimSpace(v) != "" {
			org = strings.TrimSpace(v)
		}
		if v, ok := q["projectId"].(string); ok && strings.TrimSpace(v) != "" {
			project = strings.TrimSpace(v)
		}
	}
	return org, project
}

func (s *Server) callMCPRouteTool(ctx context.Context, r *http.Request, route mcpRouteParityEntry, args map[string]any) (map[string]any, error) {
	principal, ok := requestPrincipal(r)
	if !ok {
		return nil, fmt.Errorf("authenticated principal is required")
	}
	key := ""
	if route.IdempotencyRequired {
		raw, ok := args["idempotencyKey"].(string)
		key = strings.TrimSpace(raw)
		if !ok || key == "" || len(key) > 200 {
			return nil, fmt.Errorf("idempotencyKey is required for AI mutation")
		}
	}
	sub, _, err := buildMCPRouteRequest(r, route, args, key)
	if err != nil {
		return nil, err
	}
	rawArgs, _ := json.Marshal(args)
	digest := controlplane.MCPControlRequestDigest(route.ToolName, rawArgs)
	org, project := extractMCPJobScope(args, principal.OrganizationID, principal.ProjectID)
	var jobStore controlplane.MCPControlJobStore
	if js, ok := s.store.(controlplane.MCPControlJobStore); ok {
		jobStore = js
	}
	var job controlplane.MCPControlJob
	if route.DurableJob {
		if jobStore == nil {
			return nil, fmt.Errorf("durable MCP control job store is unavailable")
		}
		var replay bool
		job, replay, err = jobStore.CreateMCPControlJob(ctx, controlplane.MCPControlJob{ToolName: route.ToolName, Family: route.Family, Action: route.Action, Method: route.Method, Route: route.Path, Risk: route.Risk, ActorID: principal.Subject, Authentication: principal.Authentication, OAuthClientID: principal.AuthorizedClientID, DelegationProfile: principal.DelegationAccessProfile, OrganizationID: org, ProjectID: project, RequestID: r.Header.Get("X-Request-ID"), IdempotencyKey: key, RequestDigest: digest, LeaseOwner: r.Header.Get("X-Request-ID")}, 2*time.Minute, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("create durable MCP control job: %w", err)
		}
		if replay {
			switch job.State {
			case controlplane.MCPControlJobSucceeded, controlplane.MCPControlJobFailed:
				var stored map[string]any
				_ = json.Unmarshal(job.Response, &stored)
				stored["controlJob"] = job
				stored["replay"] = true
				return stored, nil
			case controlplane.MCPControlJobRecoveryRequired:
				return nil, fmt.Errorf("control job %s requires operator recovery because the previous mutation outcome is indeterminate", job.ID)
			default:
				return nil, fmt.Errorf("control job %s is still running; retry will not dispatch the mutation again", job.ID)
			}
		}
	}
	rec := &cappedRecorder{}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && route.DurableJob && jobStore != nil {
				_, _ = jobStore.MarkMCPControlJobRecoveryRequired(ctx, job.ID, job.Revision, principal.Subject)
				err = fmt.Errorf("canonical handler panicked; control job moved to recovery-required")
			}
		}()
		s.mux.ServeHTTP(rec, sub)
	}()
	if err != nil {
		return nil, err
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	sealed, value := sanitizedMCPRouteResponse(status, rec.body.Bytes(), rec.overflow)
	if route.DurableJob {
		completed, e := jobStore.CompleteMCPControlJob(ctx, job.ID, job.Revision, job.FenceToken, status, sealed, principal.Subject)
		if e != nil {
			return nil, fmt.Errorf("complete durable MCP control job %s revision=%d fence=%d: %w", job.ID, job.Revision, job.FenceToken, e)
		}
		valueMap, _ := value.(map[string]any)
		if valueMap == nil {
			valueMap = map[string]any{"statusCode": status, "result": value}
		}
		valueMap["controlJob"] = completed
		valueMap["replay"] = false
		valueMap["authority"] = controlplane.MCPDurableControlJobAuthority
		return valueMap, nil
	}
	valueMap, _ := value.(map[string]any)
	if valueMap == nil {
		valueMap = map[string]any{"statusCode": status, "result": value}
	}
	valueMap["authority"] = mcpRouteParityAuthority
	return valueMap, nil
}

func mustJSON(v any) string { raw, _ := json.Marshal(v); return string(raw) }

func publicMCPControlJob(v controlplane.MCPControlJob) controlplane.MCPControlJob {
	v.Response = nil
	return v
}

func (s *Server) aiCapabilities(w http.ResponseWriter, r *http.Request) {
	registry := loadMCPRouteParityRegistry()
	mutations := registry.Counts["tool-operate"] + registry.Counts["tool-admin"]
	writeJSON(w, http.StatusOK, map[string]any{"authority": mcpRouteParityAuthority, "routeCount": registry.RouteCount, "routeDispositionCoveragePercent": 100, "counts": registry.Counts, "aiCallableRoutes": registry.RouteCount - registry.Counts["security-excluded"], "durableMutationAuthority": controlplane.MCPDurableControlJobAuthority, "durableMutationRoutes": mutations, "durableMutationCoveragePercent": 100, "idempotencyRequired": true, "terminalReplay": true, "expiredInFlightPolicy": "RECOVERY_REQUIRED_NO_AUTOMATIC_REDISPATCH", "arbitraryRouteAllowed": false, "rawCredentialAccess": false, "canDecidePass": false, "canDecidePhysicalPass": false, "persianWritingAuthority": "PERSIAN_WRITING_GATE_V1", "persianWritingUpstream": "ali2000hos/persian-writing@1.3.5", "persianWritingRegister": "formal-but-human"})
}

func (s *Server) aiPersianWriting(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":     "PERSIAN_WRITING_INTEGRATION_V1",
		"gateAuthority": "PERSIAN_WRITING_GATE_V1",
		"upstream": map[string]any{
			"repository": "https://github.com/ali2000hos/persian-writing",
			"version":    "1.3.5",
			"commit":     "118c2167f30cafe18df13c0ba85f98f50dad1894",
			"tree":       "9fd2300bfee50ac7cc666a2e8cbffc47a71e8857",
		},
		"runtimeNetworkDependency": false,
		"register":                 "formal-but-human",
		"scope":                    "user-facing Persian product copy and RTL mechanics",
		"rules": []string{
			"use Persian Yeh/Kaf and NFC Unicode",
			"use ZWNJ for Persian morphology",
			"use Persian punctuation and digits in Persian prose while preserving machine identifiers",
			"avoid bureaucratic and AI-sounding filler",
			"preserve established technical product/protocol nouns when they improve comprehension",
			"translate explanatory grammar, verbs and adjectives into natural Persian",
		},
		"rawLexiconExposed":       false,
		"fontAssetsRedistributed": false,
		"canRewriteRuntimeState":  false,
	})
}
func (s *Server) accessibleMCPControlJobs(r *http.Request, js controlplane.MCPControlJobStore, limit int) ([]controlplane.MCPControlJob, error) {
	projects, allProjects, err := s.accessibleProjectSet(r)
	if err != nil {
		return nil, err
	}
	organizations, allOrganizations, err := s.resourceOrganizationSet(r)
	if err != nil {
		return nil, err
	}
	if allProjects && allOrganizations {
		return js.ListMCPControlJobs(r.Context(), "", "", limit)
	}
	byID := map[string]controlplane.MCPControlJob{}
	for projectID := range projects {
		rows, e := js.ListMCPControlJobs(r.Context(), "", projectID, limit)
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			byID[row.ID] = row
		}
	}
	for organizationID := range organizations {
		rows, e := js.ListMCPControlJobs(r.Context(), organizationID, "", limit)
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			// Organization-scoped listing includes project jobs too. Keep those only
			// when the principal can also read the project, otherwise a direct
			// project isolation boundary would be widened by the parent org query.
			if row.ProjectID != "" && !allProjects && !projects[row.ProjectID] {
				continue
			}
			byID[row.ID] = row
		}
	}
	out := make([]controlplane.MCPControlJob, 0, len(byID))
	for _, row := range byID {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Server) listAIControlJobs(w http.ResponseWriter, r *http.Request) {
	js, ok := s.store.(controlplane.MCPControlJobStore)
	if !ok {
		writeError(w, 503, "MCP_CONTROL_JOB_STORE_UNAVAILABLE", "durable MCP control job store is unavailable")
		return
	}
	principal, _ := requestPrincipal(r)
	org, project := principal.OrganizationID, principal.ProjectID
	if q := strings.TrimSpace(r.URL.Query().Get("organizationId")); q != "" {
		org = q
	}
	if q := strings.TrimSpace(r.URL.Query().Get("projectId")); q != "" {
		project = q
	}
	if org != "" {
		if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
			writeError(w, 403, "ORGANIZATION_ACCESS_DENIED", "organization read access is required")
			return
		}
	}
	if project != "" {
		if _, err := s.requireProjectAccess(r, project, organizationRead); err != nil {
			writeError(w, 403, "PROJECT_ACCESS_DENIED", "project read access is required")
			return
		}
	}
	var items []controlplane.MCPControlJob
	var err error
	if org != "" || project != "" {
		items, err = js.ListMCPControlJobs(r.Context(), org, project, 100)
	} else {
		items, err = s.accessibleMCPControlJobs(r, js, 100)
	}
	if err != nil {
		writeError(w, 500, "MCP_CONTROL_JOB_LIST_FAILED", err.Error())
		return
	}
	for i := range items {
		items[i] = publicMCPControlJob(items[i])
	}
	writeJSON(w, 200, map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "items": items, "limit": 100})
}
func (s *Server) getAIControlJob(w http.ResponseWriter, r *http.Request) {
	js, ok := s.store.(controlplane.MCPControlJobStore)
	if !ok {
		writeError(w, 503, "MCP_CONTROL_JOB_STORE_UNAVAILABLE", "durable MCP control job store is unavailable")
		return
	}
	v, err := js.GetMCPControlJob(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "MCP_CONTROL_JOB_NOT_FOUND", "control job was not found")
		return
	}
	if v.ProjectID != "" {
		if _, err := s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
			writeError(w, 403, "PROJECT_ACCESS_DENIED", "project read access is required")
			return
		}
	} else if v.OrganizationID != "" {
		if err := s.requireOrganizationAccess(r, v.OrganizationID, organizationRead); err != nil {
			writeError(w, 403, "ORGANIZATION_ACCESS_DENIED", "organization read access is required")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "job": publicMCPControlJob(v)})
}

func (s *Server) resolveAIControlJobRecovery(w http.ResponseWriter, r *http.Request) {
	js, ok := s.store.(controlplane.MCPControlJobStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "MCP_CONTROL_JOB_STORE_UNAVAILABLE", "durable MCP control job store is unavailable")
		return
	}
	if !requestHasRole(r, "platform-admin") {
		writeError(w, http.StatusForbidden, "MCP_RECOVERY_OPERATOR_REQUIRED", "recovery resolution requires an authenticated platform-admin operator")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "REVISION_REQUIRED", err.Error())
		return
	}
	var req struct {
		Resolution     controlplane.MCPControlJobRecoveryResolution `json:"resolution"`
		ReadbackDigest string                                       `json:"readbackDigest"`
		EvidenceDigest string                                       `json:"evidenceDigest"`
	}
	if err = decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := js.ResolveMCPControlJobRecovery(r.Context(), r.PathValue("id"), expected, req.Resolution, req.ReadbackDigest, req.EvidenceDigest, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", v.Revision))
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":             controlplane.MCPControlJobRecoveryAuthority,
		"automaticRedispatch":   false,
		"authoritativeReadback": true,
		"job":                   publicMCPControlJob(v),
	})
}

var _ io.Writer = (*cappedRecorder)(nil)
