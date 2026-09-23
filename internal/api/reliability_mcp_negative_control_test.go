package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestReliabilityMCPReadOperateBoundaryAndProjectFence(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-mcp", DisplayName: "Reliability MCP"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	operator := auth.Principal{Subject: "rel-agent", Roles: []string{"platform-admin"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: project.ID}
	readOnly := operator
	readOnly.Permissions = []string{"read", "mcp.read"}
	blocked := callGeneratedMCPTool(t, srv, readOnly, 1, "api_post_reliability_incidents", map[string]any{"idempotencyKey": "blocked", "body": map[string]any{"projectId": project.ID, "service": "platform-api", "severity": "CRITICAL"}})
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("read-only MCP mutated reliability: %d %s", blocked.Code, blocked.Body.String())
	}

	created := callGeneratedMCPTool(t, srv, operator, 2, "api_post_reliability_incidents", map[string]any{"idempotencyKey": "create-once", "body": map[string]any{"projectId": project.ID, "service": "platform-api", "severity": "CRITICAL"}})
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), controlplane.MCPDurableControlJobAuthority) {
		t.Fatalf("reliability mutation did not use durable control job: %d %s", created.Code, created.Body.String())
	}
	incidents, err := store.ListIncidents(ctx, project.ID, "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incident mutation not authoritative: %+v %v", incidents, err)
	}

	registry := loadMCPRouteParityRegistry()
	seen := 0
	for _, route := range registry.Routes {
		if route.Family != "reliability" {
			continue
		}
		seen++
		want := "tool-read"
		if route.Method != http.MethodGet {
			want = "tool-operate"
		}
		if route.Disposition != want || route.ToolName == "" {
			t.Fatalf("unexpected reliability MCP classification: %+v", route)
		}
		if strings.Contains(strings.ToLower(route.ToolName+route.Action), "evidence") {
			t.Fatalf("raw evidence surfaced through reliability MCP tool: %+v", route)
		}
	}
	if seen != 10 {
		t.Fatalf("reliability MCP route count=%d want=10", seen)
	}
}
