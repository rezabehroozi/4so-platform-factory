package bootstrap

import (
	"context"
	"io"
	"strings"
	"testing"
)

type clusterHTTPCaptureSystem struct {
	*SimulatedSystem
	args  []string
	input string
}

func (s *clusterHTTPCaptureSystem) OutputInput(_ context.Context, _ string, args []string, _ map[string]string, input io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	s.args = append([]string(nil), args...)
	s.input = string(raw)
	return []byte(`{"status":"ok"}`), nil
}

func TestClusterHTTPKeepsBootstrapCredentialOutOfPodSpecAndKubectlArguments(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	bundle, _, err := LoadBundle(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	system := &clusterHTTPCaptureSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	secret := "bootstrap-secret-must-never-enter-kubectl-argv"
	payload := []byte(`{"name":"bootstrap"}`)
	out, err := runner.clusterHTTP(context.Background(), bundle, "POST", "http://platform-api:8080/api/v1/organizations", payload, map[string]string{
		"Content-Type":               "application/json",
		"X-Actor-ID":                 "bootstrap-installer",
		"X-Platform-Bootstrap-Token": secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"status":"ok"}` {
		t.Fatalf("unexpected response %q", string(out))
	}
	joined := strings.Join(system.args, " ")
	if strings.Contains(joined, secret) || strings.Contains(system.input, secret) {
		t.Fatal("bootstrap credential leaked into kubectl arguments or stdin")
	}
	for _, required := range []string{
		`"automountServiceAccountToken":false`,
		`"activeDeadlineSeconds":120`,
		`"terminationGracePeriodSeconds":0`,
		`"name":"platform-internal-services"`,
		`"key":"bootstrap-token"`,
		`"allowPrivilegeEscalation":false`,
		`"readOnlyRootFilesystem":true`,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("secure bootstrap probe is missing %s: %s", required, joined)
		}
	}
	if strings.Contains(joined, string(payload)) || strings.Contains(joined, "bootstrap-installer") || strings.Contains(joined, "http://platform-api:8080/api/v1/organizations") {
		t.Fatalf("dynamic bootstrap request data leaked into PodSpec/argv: %s", joined)
	}
	for _, required := range []string{"POST\n", "http://platform-api:8080/api/v1/organizations\n", "bootstrap-installer\n", "application/json\n", string(payload)} {
		if !strings.Contains(system.input, required) {
			t.Fatalf("bootstrap request stdin is missing %q: %q", required, system.input)
		}
	}
}

func TestSanitizeBootstrapCredentialManifestCoversHACompactEnv(t *testing.T) {
	raw := []byte(`apiVersion: v1
kind: Secret
metadata: {name: platform-internal-services, namespace: platform-system}
type: Opaque
data:
  session-secret: c2Vzc2lvbg==
  bootstrap-token: Ym9vdHN0cmFw
  catalog-signing-key: c2lnbmluZw==
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: platform-api, namespace: platform-system}
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: bootstrap-token}}
            - {name: PLATFORM_FACTORY_LISTEN, value: "0.0.0.0:8080"}
`)
	clean, err := sanitizeBootstrapCredentialManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clean), "bootstrap-token") || strings.Contains(string(clean), "PLATFORM_FACTORY_BOOTSTRAP_TOKEN") {
		t.Fatalf("HA foundation manifest still contains bootstrap credential:\n%s", clean)
	}
	if !strings.Contains(string(clean), "catalog-signing-key") || !strings.Contains(string(clean), "PLATFORM_FACTORY_LISTEN") {
		t.Fatalf("sanitization removed unrelated desired state:\n%s", clean)
	}
}

func TestRevokeBootstrapCredentialFailsBeforeLiveMutationWhenDesiredStateIsUnavailable(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-api", secretUID: "uid-secret", deploymentRV: "10", secretRV: "11", envPresent: true, secretPresent: true}
	runner := &Runner{stateDir: t.TempDir(), system: system}
	err := runner.revokeBootstrapCredential(context.Background(), "install-run-missing-authority")
	if err == nil || !strings.Contains(err.Error(), "authoritative foundation manifest") {
		t.Fatalf("expected durable desired-state failure before live revocation, got %v", err)
	}
	for _, command := range system.Commands {
		if strings.Contains(command, " patch deployment/") || strings.Contains(command, " patch secret/") {
			t.Fatalf("live bootstrap credential was mutated before durable desired-state revocation: %s", command)
		}
	}
}
