package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/labmodel"
	"platform.4so.io/factory/internal/targetmodel"
)

const mcpProtocolVersion = "2026-07-28"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Meta    map[string]any  `json:"_meta,omitempty"`
	Params  struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
		Meta      map[string]any `json:"_meta,omitempty"`
	} `json:"params"`
}

type mcpTool struct {
	Name               string         `json:"name"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	InputSchema        map[string]any `json:"inputSchema"`
	RequiredPermission string         `json:"requiredPermission"`
}

func mcpTools() []mcpTool {
	empty := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}}
	idInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	return []mcpTool{
		{Name: "lab_guide", Title: "Lab certification guide", Description: "Read the canonical server tiers, deterministic test matrix, AI failure-only policy and MCP contract.", InputSchema: empty, RequiredPermission: "mcp.read"},
		{Name: "target_architecture_model", Title: "Target architecture model", Description: "Read the canonical target-distribution architecture and large-phase program roadmap.", InputSchema: empty, RequiredPermission: "mcp.read"},
		{Name: "ai_runtime_policy", Title: "AI runtime policy", Description: "Read provider-neutral AI budgets, redaction requirements and authority boundaries without exposing credentials.", InputSchema: empty, RequiredPermission: "mcp.read"},
		{Name: "cluster_summary", Title: "Managed cluster summary", Description: "Read authoritative project-scoped cluster identity, health and inventory freshness metadata.", InputSchema: idInput, RequiredPermission: "mcp.read"},
		{Name: "operation_status", Title: "Durable operation status", Description: "Read authoritative project-scoped operation state, retry and recovery metadata.", InputSchema: idInput, RequiredPermission: "mcp.read"},
		{Name: "ai_run", Title: "AI advisory run", Description: "Read a durable project-scoped advisory AI run and its digests/usage without raw prompts or credentials.", InputSchema: idInput, RequiredPermission: "mcp.read"},
	}
}

func mcpExactIDArgument(arguments map[string]any) (string, bool) {
	if len(arguments) != 1 {
		return "", false
	}
	raw, ok := arguments["id"].(string)
	id := strings.TrimSpace(raw)
	return id, ok && id != "" && len(id) <= 200
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, status, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if err := s.requireCapabilityAuthorization(r, "mcp.read", true); err != nil {
		if errors.Is(err, errCapabilityAccessDenied) {
			writeMCPError(w, nil, http.StatusForbidden, -32001, "mcp.read capability permission is required")
		} else {
			writeMCPError(w, nil, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
		}
		return
	}
	if strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")) != mcpProtocolVersion {
		writeMCPError(w, nil, http.StatusBadRequest, -32600, "MCP-Protocol-Version must be 2026-07-28")
		return
	}
	var req mcpRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeMCPError(w, nil, http.StatusBadRequest, -32700, "invalid JSON-RPC request")
		return
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32600, "invalid JSON-RPC request")
		return
	}
	headerMethod := strings.TrimSpace(r.Header.Get("Mcp-Method"))
	if headerMethod == "" || headerMethod != req.Method {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32600, "Mcp-Method header must match the JSON-RPC method")
		return
	}
	if req.Method == "tools/call" {
		headerName := strings.TrimSpace(r.Header.Get("Mcp-Name"))
		if headerName == "" || headerName != strings.TrimSpace(req.Params.Name) {
			writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "Mcp-Name header must match params.name")
			return
		}
	}

	switch req.Method {
	case "server/discover":
		writeMCPResult(w, req.ID, map[string]any{
			"supportedVersions": []string{mcpProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"instructions":      "Read-only 4SO Platform Factory lab and target-architecture authority. Test PASS and Physical PASS are never decided by MCP or AI.",
			"ttlMs":             60000,
			"cacheScope":        "private",
			"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{
				"name": "4so-platform-factory", "version": s.version,
			}},
		})
	case "tools/list":
		writeMCPResult(w, req.ID, map[string]any{"tools": mcpTools(), "ttlMs": 60000, "cacheScope": "private"})
	case "tools/call":
		var value any
		switch strings.TrimSpace(req.Params.Name) {
		case "lab_guide":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "lab_guide accepts no arguments")
				return
			}
			value = labmodel.Model()
		case "target_architecture_model":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "target_architecture_model accepts no arguments")
				return
			}
			value = targetmodel.ArchitectureModel()
		case "ai_runtime_policy":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "ai_runtime_policy accepts no arguments")
				return
			}
			if s.aiRuntime == nil {
				value = map[string]any{"enabled": false, "provider": "none", "redactionRequired": true, "advisoryOnly": true, "canDecidePass": false, "canDecidePhysicalPass": false}
			} else {
				value = s.aiRuntime.Policy()
			}
		case "cluster_summary":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "cluster_summary requires exactly one id argument")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = map[string]any{"id": cluster.ID, "projectId": cluster.ProjectID, "revision": cluster.Revision, "name": cluster.Name, "distribution": cluster.Distribution, "kubernetesVersion": cluster.KubernetesVersion, "agentVersion": cluster.AgentVersion, "connectionState": cluster.ConnectionState, "lastSeenAt": cluster.LastSeenAt, "inventoryObservedAt": cluster.InventoryObservedAt, "inventoryDigest": cluster.InventoryDigest, "capabilities": cluster.Capabilities}
		case "operation_status":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "operation_status requires exactly one id argument")
				return
			}
			op, err := s.store.GetOperation(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "operation not found")
				return
			}
			if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = map[string]any{"id": op.ID, "projectId": op.ProjectID, "revision": op.Revision, "kind": op.Kind, "targetRef": op.TargetRef, "desiredRevision": op.DesiredRevision, "state": op.State, "risk": op.Risk, "class": op.Class, "attempt": op.Attempt, "retryExhausted": op.RetryExhausted, "lastFailureClass": op.LastFailureClass, "lastError": op.LastError, "recoveryEvidenceDigest": op.RecoveryEvidenceDigest, "updatedAt": op.UpdatedAt}
		case "ai_run":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "ai_run requires exactly one id argument")
				return
			}
			run, err := s.store.GetAIRun(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "AI run not found")
				return
			}
			if _, err = s.requireProjectAccess(r, run.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = run
		default:
			writeMCPError(w, req.ID, http.StatusNotFound, -32602, fmt.Sprintf("unknown tool %q", req.Params.Name))
			return
		}
		raw, err := json.Marshal(value)
		if err != nil {
			writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "encode tool result")
			return
		}
		writeMCPResult(w, req.ID, map[string]any{
			"content":           []map[string]string{{"type": "text", "text": string(raw)}},
			"structuredContent": value,
			"isError":           false,
		})
	default:
		writeMCPError(w, req.ID, http.StatusNotFound, -32601, "method not found")
	}
}
