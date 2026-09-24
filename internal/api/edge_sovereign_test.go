package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/edgeauthority"
)

func edgeAssessmentProject(t *testing.T, s *Server) controlplane.Project {
	t.Helper()
	org, err := s.store.CreateOrganization(context.Background(), controlplane.Organization{Name: "edge-org", DisplayName: "Edge Org"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := s.store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "edge", DisplayName: "Edge"}, "owner")
	if err != nil { t.Fatal(err) }
	return project
}

func edgeDigest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func edgePOST(t *testing.T, s *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor-ID", "edge-reviewer")
	req.Header.Set("X-Actor-Role", "platform-viewer")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestEdgeBootAttestationAssessmentDoesNotClaimPhysicalPass(t *testing.T) {
	s := testServer(t)
	project := edgeAssessmentProject(t, s)
	claim := edgeauthority.BootClaim{
		Authority: edgeauthority.BootAttestationAuthority,
		SiteID: "site-a", NodeID: "node-a", ObservedAt: time.Now().UTC(),
		TPMPresent: true, SecureBootEnabled: true, MeasuredBootPresent: true,
		DiskEncryptionVerified: true, QuoteVerified: true, NonceBound: true, PCRPolicyMatched: true,
		QuoteDigest: edgeDigest("1"), EventLogDigest: edgeDigest("2"), EvidenceDigest: edgeDigest("3"),
	}
	w := edgePOST(t, s, "/api/v1/edge/boot-attestations/assess", map[string]any{"projectId": project.ID, "claim": claim})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"ATTESTED"`) || !strings.Contains(w.Body.String(), `"physicalCertification":"NOT_RUN"`) {
		t.Fatalf("assessment=%d body=%s", w.Code, w.Body.String())
	}
	claim.NonceBound = false
	w = edgePOST(t, s, "/api/v1/edge/boot-attestations/assess", map[string]any{"projectId": project.ID, "claim": claim})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"REJECTED"`) {
		t.Fatalf("unsafe claim=%d body=%s", w.Code, w.Body.String())
	}
}

func TestEdgeLocalAIProfileAdmissionRejectsExternalAuthority(t *testing.T) {
	s := testServer(t)
	project := edgeAssessmentProject(t, s)
	profile := edgeauthority.LocalAIProfile{
		Authority: edgeauthority.LocalAIProfileAuthority, Mode: "disconnected", Runtime: "local-vllm",
		ModelDigest: edgeDigest("4"), RuntimeImageDigest: edgeDigest("5"),
		MaxPromptBytes: 256 * 1024, MaxOutputBytes: 256 * 1024,
	}
	w := edgePOST(t, s, "/api/v1/edge/local-ai/profiles/validate", map[string]any{"projectId": project.ID, "profile": profile})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"admitted":true`) || !strings.Contains(w.Body.String(), `"runtimeStarted":false`) {
		t.Fatalf("valid profile=%d body=%s", w.Code, w.Body.String())
	}
	profile.ExternalProvider = true
	w = edgePOST(t, s, "/api/v1/edge/local-ai/profiles/validate", map[string]any{"projectId": project.ID, "profile": profile})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("external profile=%d body=%s", w.Code, w.Body.String())
	}
}

func TestEdgeLocalAuthorityCompileAdmitAndReconnectAreSideEffectFree(t *testing.T) {
	s := testServer(t)
	project := edgeAssessmentProject(t, s)
	now := time.Now().UTC()
	compile := edgePOST(t, s, "/api/v1/edge/local-authority/policies/compile", map[string]any{
		"projectId": project.ID,
		"siteId": "site-a",
		"revision": 7,
		"desiredStateDigest": edgeDigest("a"),
		"allowedActions": []string{"OBSERVE", "COLLECT_DIAGNOSTICS"},
		"maxOfflineSeconds": 7200,
		"maxQueuedEvidenceItems": 100,
		"validUntil": now.Add(time.Hour),
	})
	if compile.Code != http.StatusOK || !strings.Contains(compile.Body.String(), `"authority":"EDGE_LOCAL_AUTHORITY_V1"`) || !strings.Contains(compile.Body.String(), `"mutationExecuted":false`) {
		t.Fatalf("compile=%d body=%s", compile.Code, compile.Body.String())
	}
	var compiled struct{ Policy edgeauthority.LocalPolicy `json:"policy"` }
	if err := json.Unmarshal(compile.Body.Bytes(), &compiled); err != nil { t.Fatal(err) }

	request := edgeauthority.MutationRequest{
		SiteID: compiled.Policy.SiteID, ProjectID: project.ID, Action: edgeauthority.ActionObserve,
		TargetRef: "site:site-a", BaseRevision: compiled.Policy.Revision,
		BaseDesiredDigest: compiled.Policy.DesiredStateDigest, PolicyDigest: compiled.Policy.PolicyDigest,
		IdempotencyKey: "edge-op-1", RequestDigest: edgeDigest("b"),
	}
	admit := edgePOST(t, s, "/api/v1/edge/local-authority/mutations/admit", map[string]any{
		"projectId": project.ID, "policy": compiled.Policy, "request": request,
		"disconnectedSince": now.Add(-time.Minute),
	})
	if admit.Code != http.StatusOK || !strings.Contains(admit.Body.String(), `"admitted":true`) || !strings.Contains(admit.Body.String(), `"requiresDurableOperationForExecution":true`) || !strings.Contains(admit.Body.String(), `"mutationExecuted":false`) {
		t.Fatalf("admit=%d body=%s", admit.Code, admit.Body.String())
	}

	reconnect := edgePOST(t, s, "/api/v1/edge/local-authority/reconnect/resolve", map[string]any{
		"projectId": project.ID, "request": request, "centralRevision": 8, "centralDesiredStateDigest": edgeDigest("c"),
	})
	if reconnect.Code != http.StatusOK || !strings.Contains(reconnect.Body.String(), `"state":"REVIEW_REQUIRED"`) || !strings.Contains(reconnect.Body.String(), `"automaticApply":false`) || !strings.Contains(reconnect.Body.String(), `"mutationExecuted":false`) {
		t.Fatalf("reconnect=%d body=%s", reconnect.Code, reconnect.Body.String())
	}
}

func TestEdgeLocalAuthorityRejectsCrossProjectAdmission(t *testing.T) {
	s := testServer(t)
	project := edgeAssessmentProject(t, s)
	now := time.Now().UTC()
	policy, err := edgeauthority.CanonicalPolicy("site-a", project.ID, edgeDigest("d"), 3, []edgeauthority.Action{edgeauthority.ActionObserve}, time.Hour, 10, now.Add(time.Hour))
	if err != nil { t.Fatal(err) }
	request := edgeauthority.MutationRequest{SiteID:"site-a", ProjectID:"prj_foreign", Action:edgeauthority.ActionObserve, TargetRef:"site:site-a", BaseRevision:3, BaseDesiredDigest:edgeDigest("d"), PolicyDigest:policy.PolicyDigest, IdempotencyKey:"edge-op-x", RequestDigest:edgeDigest("e")}
	w := edgePOST(t, s, "/api/v1/edge/local-authority/mutations/admit", map[string]any{"projectId":project.ID,"policy":policy,"request":request,"disconnectedSince":now.Add(-time.Minute)})
	if w.Code != http.StatusForbidden { t.Fatalf("cross-project admission=%d body=%s",w.Code,w.Body.String()) }
}
