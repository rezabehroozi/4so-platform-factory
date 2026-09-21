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
