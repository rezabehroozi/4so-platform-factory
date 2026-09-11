package compliance

import "testing"

func TestEvaluateFindsSecurityBaselineViolations(t *testing.T) {
	input := []map[string]any{
		{"kind": "ClusterRoleBinding", "metadata": map[string]any{"name": "danger"}, "roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}},
		{"kind": "Deployment", "metadata": map[string]any{"namespace": "prod", "name": "api"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"hostNetwork": true, "containers": []any{map[string]any{"name": "api", "image": "example/api:latest", "securityContext": map[string]any{"privileged": true}}}}}}},
	}
	got := Evaluate(input)
	if got.Authority != BaselineAuthority || got.Objects != 2 || len(got.Findings) != 4 {
		t.Fatalf("unexpected result: %#v", got)
	}
	seen := map[string]bool{}
	for _, f := range got.Findings {
		seen[f.RuleID] = true
		if len(f.Fingerprint) != 64 {
			t.Fatalf("bad fingerprint: %#v", f)
		}
	}
	for _, rule := range []string{"RBAC_CLUSTER_ADMIN_BINDING", "WORKLOAD_HOST_NAMESPACE", "WORKLOAD_PRIVILEGED_CONTAINER", "IMAGE_MUTABLE_LATEST_TAG"} {
		if !seen[rule] {
			t.Fatalf("missing %s: %#v", rule, got.Findings)
		}
	}
}

func TestEvaluateAcceptsHardenedWorkload(t *testing.T) {
	input := []byte(`{"kind":"Deployment","metadata":{"namespace":"prod","name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","securityContext":{"privileged":false}}]}}}}`)
	got, err := EvaluateJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Objects != 1 || len(got.Findings) != 0 {
		t.Fatalf("unexpected findings: %#v", got)
	}
}

func TestEvaluateRejectsInvalidInput(t *testing.T) {
	if _, err := EvaluateJSON([]byte(`{"kind":"List","items":"bad"}`)); err == nil {
		t.Fatal("expected invalid List.items failure")
	}
}

func TestEvaluateOrdersSeverityCriticalHighMedium(t *testing.T) {
	input := []map[string]any{
		{"kind": "ClusterRoleBinding", "metadata": map[string]any{"name": "danger"}, "roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}},
		{"kind": "Pod", "metadata": map[string]any{"namespace": "prod", "name": "api"}, "spec": map[string]any{"hostNetwork": true, "containers": []any{map[string]any{"name": "api", "image": "example/api:1.2.3"}}}},
	}
	got := Evaluate(input)
	if len(got.Findings) != 3 {
		t.Fatalf("unexpected finding count: %#v", got.Findings)
	}
	if got.Findings[0].Severity != SeverityCritical || got.Findings[1].Severity != SeverityHigh || got.Findings[2].Severity != SeverityMedium {
		t.Fatalf("severity order is not CRITICAL > HIGH > MEDIUM: %#v", got.Findings)
	}
}

func TestEvaluateIncludesEphemeralContainersAndRequiresDigestPins(t *testing.T) {
	input := []map[string]any{{
		"kind": "Pod", "metadata": map[string]any{"namespace": "prod", "name": "debuggable"},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			"ephemeralContainers": []any{map[string]any{"name": "debug", "image": "busybox:1.36", "securityContext": map[string]any{"privileged": true}}}},
	}}
	got := Evaluate(input)
	seen := map[string]bool{}
	for _, f := range got.Findings {
		seen[f.RuleID] = true
	}
	if !seen["WORKLOAD_PRIVILEGED_CONTAINER"] || !seen["IMAGE_NOT_DIGEST_PINNED"] {
		t.Fatalf("ephemeral-container violations were not detected: %#v", got.Findings)
	}
}
