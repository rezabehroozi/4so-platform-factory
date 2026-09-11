package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func operationExecutorTestRequest(t *testing.T, h http.Handler, principal auth.Principal, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
	r.Header.Set("X-Actor-ID", principal.Subject)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOperationExecutionPlaneRejectsHumanPrincipalAndBindsWorkerIdentity(t *testing.T) {
	store := controlplane.NewMemoryStore()
	s := New("test", nil, slog.Default(), store)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "exec-org", DisplayName: "Execution Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{
		ProjectID: project.ID, Kind: "authority.test", TargetRef: "cluster/test",
		DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "medium", Class: controlplane.OperationClassMutating,
	}, "exec-authority", "requester", "req-1")
	if err != nil {
		t.Fatal(err)
	}

	human := auth.Principal{Subject: "human-operator", Authentication: "oidc", Roles: []string{"platform-operator"}, ProjectRoles: map[string]string{project.ID: "project-operator"}, Expires: time.Now().Add(time.Hour).Unix()}
	w := operationExecutorTestRequest(t, s.Handler(), human, http.MethodPost, "/api/v1/operations/"+op.ID+"/transition", `{"state":"PLANNING"}`, map[string]string{"If-Match": fmt.Sprintf("\"%d\"", op.Revision)})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "OPERATION_EXECUTOR_REQUIRED") {
		t.Fatalf("human raw transition status=%d body=%s", w.Code, w.Body.String())
	}
	current, _ := store.GetOperation(ctx, op.ID)
	if current.State != controlplane.OperationDraft || current.Revision != op.Revision {
		t.Fatalf("human changed operation: %+v", current)
	}

	admin := auth.Principal{Subject: "human-admin", Authentication: "oidc", Roles: []string{"platform-admin"}, Expires: time.Now().Add(time.Hour).Unix()}
	w = operationExecutorTestRequest(t, s.Handler(), admin, http.MethodPost, "/api/v1/operations/"+op.ID+"/claim", `{"workerId":"fake-worker","leaseSeconds":60}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "OPERATION_EXECUTOR_REQUIRED") {
		t.Fatalf("human admin claim status=%d body=%s", w.Code, w.Body.String())
	}

	executor := auth.Principal{
		Subject: "operation-worker-prod", Authentication: "api-token", Roles: []string{"platform-operator"},
		Permissions:    []string{controlplane.APITokenPermissionRead, controlplane.APITokenPermissionOperate, controlplane.APITokenPermissionOperationExecute},
		OrganizationID: org.ID, ProjectID: project.ID, Expires: time.Now().Add(time.Hour).Unix(),
	}
	w = operationExecutorTestRequest(t, s.Handler(), executor, http.MethodPost, "/api/v1/operations/"+op.ID+"/transition", `{"state":"PLANNING"}`, map[string]string{"If-Match": fmt.Sprintf("\"%d\"", op.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("executor transition status=%d body=%s", w.Code, w.Body.String())
	}
	current, _ = store.GetOperation(ctx, op.ID)
	if current.State != controlplane.OperationPlanning {
		t.Fatalf("state=%s", current.State)
	}
	current, err = store.TransitionOperation(ctx, current.ID, current.Revision, controlplane.OperationQueued, "", "internal-planner")
	if err != nil {
		t.Fatal(err)
	}

	// The generic transition endpoint must never bypass lease/fence-aware
	// execution authority. QUEUED -> RUNNING requires claim + attempt/start.
	w = operationExecutorTestRequest(t, s.Handler(), executor, http.MethodPost, "/api/v1/operations/"+op.ID+"/transition", `{"state":"RUNNING"}`, map[string]string{"If-Match": fmt.Sprintf("\"%d\"", current.Revision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "PREREQUISITE_NOT_SATISFIED") {
		t.Fatalf("raw execution transition bypass status=%d body=%s", w.Code, w.Body.String())
	}

	w = operationExecutorTestRequest(t, s.Handler(), executor, http.MethodPost, "/api/v1/operations/"+op.ID+"/claim", `{"workerId":"spoofed-worker","leaseSeconds":60}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "WORKER_IDENTITY_MISMATCH") {
		t.Fatalf("spoofed worker status=%d body=%s", w.Code, w.Body.String())
	}
	w = operationExecutorTestRequest(t, s.Handler(), executor, http.MethodPost, "/api/v1/operations/"+op.ID+"/claim", `{"leaseSeconds":60}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("executor claim status=%d body=%s", w.Code, w.Body.String())
	}
	claimed, _ := store.GetOperation(ctx, op.ID)
	if claimed.LeaseOwner != executor.Subject || claimed.FenceToken <= 0 {
		t.Fatalf("claim did not bind authenticated identity: %+v", claimed)
	}

	// A live executor can renew its exact fenced lease; a human still cannot.
	w = operationExecutorTestRequest(t, s.Handler(), executor, http.MethodPost, "/api/v1/operations/"+op.ID+"/lease/renew", fmt.Sprintf(`{"fenceToken":%d,"leaseSeconds":120}`, claimed.FenceToken), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%s", w.Code, w.Body.String())
	}
	w = operationExecutorTestRequest(t, s.Handler(), human, http.MethodPost, "/api/v1/operations/"+op.ID+"/lease/renew", fmt.Sprintf(`{"workerId":"%s","fenceToken":%d}`, executor.Subject, claimed.FenceToken), nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("human renew status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestOperationExecutePermissionIsOperatorOnly(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "perm-org", DisplayName: "Perm Org"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	viewer, _ := store.CreateServiceAccount(ctx, controlplane.ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "viewer", DisplayName: "Viewer", ProductRole: "platform-viewer"}, "admin")
	_, err := store.CreateAPIToken(ctx, controlplane.APIToken{ServiceAccountID: viewer.ID, TokenPrefix: "4so_x", TokenDigest: "sha256:" + strings.Repeat("1", 64), Permissions: []string{controlplane.APITokenPermissionOperationExecute}, ExpiresAt: time.Now().Add(time.Hour), IdempotencyKey: "viewer-exec"}, "admin")
	if err == nil {
		t.Fatal("viewer service account received operation.execute")
	}
	operator, _ := store.CreateServiceAccount(ctx, controlplane.ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "worker", DisplayName: "Worker", ProductRole: "platform-operator"}, "admin")
	token, err := store.CreateAPIToken(ctx, controlplane.APIToken{ServiceAccountID: operator.ID, TokenPrefix: "4so_y", TokenDigest: "sha256:" + strings.Repeat("2", 64), Permissions: []string{controlplane.APITokenPermissionOperationExecute}, ExpiresAt: time.Now().Add(time.Hour), IdempotencyKey: "operator-exec"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range token.Permissions {
		if p == controlplane.APITokenPermissionOperationExecute {
			found = true
		}
	}
	if !found {
		t.Fatalf("permissions=%v", token.Permissions)
	}
}
