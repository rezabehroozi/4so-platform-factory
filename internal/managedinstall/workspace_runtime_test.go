package managedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExecutableFixture(t *testing.T, dir, name, body string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

func prepareWorkspaceFixture(t *testing.T, root string, req Request) string {
	t.Helper()
	workspace, digest, err := workspacePath(root, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "auth"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(workspace, "auth"), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := WorkspaceDescriptor{
		Authority:          WorkspaceDescriptorAuthority,
		RequestDigest:      digest,
		OrganizationID:     req.OrganizationID,
		ProjectID:          req.ProjectID,
		ClusterName:        req.ClusterName,
		TargetVersion:      req.TargetVersion,
		ReleasePayloadSHA:  artifactDigest(req, "release-payload"),
		FCOSSHA:            artifactDigest(req, "fcos"),
		AgentISOSHA:        artifactDigest(req, "agent-iso"),
		PreparedBy:         "workspace-preparer",
		PreparationVersion: "v1",
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(workspace, "workspace.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "auth", "kubeconfig"), []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestWorkspaceRuntimeExecutesExactBinariesAndVerifiesOKDHealth(t *testing.T) {
	workspaceRoot := filepath.Join(t.TempDir(), "workspaces")
	workRoot := filepath.Join(t.TempDir(), "runtime")
	binRoot := filepath.Join(t.TempDir(), "bin")
	for _, dir := range []string{workspaceRoot, workRoot, binRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	req := testRequest()
	prepareWorkspaceFixture(t, workspaceRoot, req)
	installPath, installSHA := writeExecutableFixture(t, binRoot, "openshift-install", `#!/bin/sh
if [ -n "$KUBECONFIG" ]; then echo leaked-kubeconfig >&2; exit 41; fi
exit 0
`)
	ocPath, ocSHA := writeExecutableFixture(t, binRoot, "oc", `#!/bin/sh
case "$*" in
  *"get clusterversion version"*) echo '{"status":{"desired":{"version":"4.19.0"},"conditions":[{"type":"Available","status":"True"},{"type":"Failing","status":"False"},{"type":"Progressing","status":"False"}]}}' ;;
  *"get nodes"*) echo '{"items":[{"metadata":{"name":"cp-1"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp-2"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp-3"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *"get clusteroperators"*) echo '{"items":[{"metadata":{"name":"network"},"status":{"conditions":[{"type":"Available","status":"True"},{"type":"Degraded","status":"False"},{"type":"Progressing","status":"False"}]}},{"metadata":{"name":"storage"},"status":{"conditions":[{"type":"Available","status":"True"},{"type":"Degraded","status":"False"},{"type":"Progressing","status":"False"}]}}]}' ;;
  *"apply -f -"*) cat >/dev/null ;;
  *) echo unexpected-oc-args "$*" >&2; exit 42 ;;
esac
`)
	runtime := &WorkspaceRuntime{Config: WorkspaceRuntimeConfig{WorkspaceRoot: workspaceRoot, WorkRoot: workRoot, OpenShiftInstall: installPath, OpenShiftInstallSHA: installSHA, OC: ocPath, OCSHA: ocSHA, InstallTimeout: time.Minute, CommandTimeout: time.Minute}}
	if err := runtime.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", "/tmp/parent-must-not-leak")
	result, err := runtime.InstallConnectedOKD(context.Background(), req, "op-1@1788933600")
	if err != nil {
		t.Fatal(err)
	}
	if result["healthVerified"] != true || result["clusterVersion"] != "4.19.0" || result["workspaceDigestBound"] != true {
		t.Fatalf("unexpected result %#v", result)
	}
	apply, err := runtime.ApplyRegistrationManifest(context.Background(), req, "op-1@1788933600", "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n")
	if err != nil {
		t.Fatal(err)
	}
	if apply["applied"] != true || !strings.HasPrefix(apply["manifestDigest"].(string), "sha256:") {
		t.Fatalf("unexpected apply result %#v", apply)
	}
}

func TestWorkspaceRuntimeRejectsDescriptorArtifactDrift(t *testing.T) {
	workspaceRoot := filepath.Join(t.TempDir(), "workspaces")
	workRoot := filepath.Join(t.TempDir(), "runtime")
	binRoot := filepath.Join(t.TempDir(), "bin")
	for _, dir := range []string{workspaceRoot, workRoot, binRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(dir, 0o700)
	}
	req := testRequest()
	workspace := prepareWorkspaceFixture(t, workspaceRoot, req)
	var doc WorkspaceDescriptor
	raw, _ := os.ReadFile(filepath.Join(workspace, "workspace.json"))
	_ = json.Unmarshal(raw, &doc)
	doc.AgentISOSHA = "sha256:" + strings.Repeat("b", 64)
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(workspace, "workspace.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	installPath, installSHA := writeExecutableFixture(t, binRoot, "openshift-install", "#!/bin/sh\nexit 0\n")
	ocPath, ocSHA := writeExecutableFixture(t, binRoot, "oc", "#!/bin/sh\nexit 0\n")
	runtime := &WorkspaceRuntime{Config: WorkspaceRuntimeConfig{WorkspaceRoot: workspaceRoot, WorkRoot: workRoot, OpenShiftInstall: installPath, OpenShiftInstallSHA: installSHA, OC: ocPath, OCSHA: ocSHA}}
	if _, err := runtime.InstallConnectedOKD(context.Background(), req, "op-2@1788933600"); err == nil {
		t.Fatal("workspace artifact drift was accepted")
	}
}

func TestWorkspaceRuntimeDisconnectedMirrorIsExactOfflineAndRequiredBeforeInstall(t *testing.T) {
	workspaceRoot := filepath.Join(t.TempDir(), "workspaces")
	workRoot := filepath.Join(t.TempDir(), "runtime")
	binRoot := filepath.Join(t.TempDir(), "bin")
	for _, dir := range []string{workspaceRoot, workRoot, binRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	archivePayload := []byte("sealed-mirror-archive-payload\n")
	archiveSum := sha256.Sum256(archivePayload)
	inventory := disconnectedMirrorInventory{Authority: DisconnectedMirrorInventoryAuthority, Files: []disconnectedMirrorInventoryFile{{Path: "segment-000001.tar", SHA256: "sha256:" + hex.EncodeToString(archiveSum[:])}}}
	inventoryRaw, _ := json.Marshal(inventory)
	inventorySum := sha256.Sum256(inventoryRaw)
	iscRaw := []byte("apiVersion: mirror.openshift.io/v2alpha1\nkind: ImageSetConfiguration\nmirror:\n  platform:\n    graph: true\n")
	iscSum := sha256.Sum256(iscRaw)

	req := testRequest()
	req.Connectivity = "disconnected"
	req.Disconnected = &DisconnectedConfig{
		MirrorRegistry:              "registry.internal.test/okd",
		ImageSetConfigurationSHA256: "sha256:" + hex.EncodeToString(iscSum[:]),
		MirrorInventorySHA256:       "sha256:" + hex.EncodeToString(inventorySum[:]),
	}
	workspace := prepareWorkspaceFixture(t, workspaceRoot, req)
	disc := filepath.Join(workspace, "disconnected")
	archive := filepath.Join(disc, "archive")
	for _, dir := range []string{disc, archive} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(disc, "imageset-config.yaml"), iscRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disc, "mirror-inventory.json"), inventoryRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "segment-000001.tar"), archivePayload, 0o600); err != nil {
		t.Fatal(err)
	}

	installPath, installSHA := writeExecutableFixture(t, binRoot, "openshift-install", "#!/bin/sh\nexit 0\n")
	ocPath, ocSHA := writeExecutableFixture(t, binRoot, "oc", `#!/bin/sh
case "$*" in
  *"get clusterversion version"*) echo '{"status":{"desired":{"version":"4.19.0"},"conditions":[{"type":"Available","status":"True"},{"type":"Failing","status":"False"},{"type":"Progressing","status":"False"}]}}' ;;
  *"get nodes"*) echo '{"items":[{"metadata":{"name":"cp-1"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp-2"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"cp-3"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *"get clusteroperators"*) echo '{"items":[{"metadata":{"name":"network"},"status":{"conditions":[{"type":"Available","status":"True"},{"type":"Degraded","status":"False"},{"type":"Progressing","status":"False"}]}}]}' ;;
  *) exit 42 ;;
esac
`)
	mirrorPath, mirrorSHA := writeExecutableFixture(t, binRoot, "oc-mirror", `#!/bin/sh
if [ -n "$HTTP_PROXY$HTTPS_PROXY$ALL_PROXY" ]; then echo proxy-leaked >&2; exit 51; fi
case "$*" in
  *"--from file://"*"docker://registry.internal.test/okd"*"--v2"*"--dest-tls-verify=true"*) exit 0 ;;
  *) echo bad-args "$*" >&2; exit 52 ;;
esac
`)
	runtime := &WorkspaceRuntime{Config: WorkspaceRuntimeConfig{
		WorkspaceRoot: workspaceRoot, WorkRoot: workRoot,
		OpenShiftInstall: installPath, OpenShiftInstallSHA: installSHA,
		OC: ocPath, OCSHA: ocSHA,
		OCMirror: mirrorPath, OCMirrorSHA: mirrorSHA,
		DisconnectedMirrorRegistry: "registry.internal.test/okd",
		InstallTimeout:             time.Minute, CommandTimeout: time.Minute,
	}}
	if err := runtime.ValidateDisconnected(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", "http://must-not-leak.invalid:9999")
	t.Setenv("HTTPS_PROXY", "http://must-not-leak.invalid:9999")
	if _, err := runtime.InstallDisconnectedOKD(context.Background(), req, "disc-op@1788933600"); err == nil || !strings.Contains(err.Error(), "mirror checkpoint") {
		t.Fatalf("disconnected install ran without mirror checkpoint: %v", err)
	}
	prepared, err := runtime.PrepareDisconnectedMirror(context.Background(), req, "disc-op@1788933600")
	if err != nil {
		t.Fatal(err)
	}
	if prepared["networkSourceRequired"] != false || prepared["ocMirrorV2"] != true || prepared["archiveFileCount"] != 1 {
		t.Fatalf("unexpected disconnected mirror evidence %#v", prepared)
	}
	result, err := runtime.InstallDisconnectedOKD(context.Background(), req, "disc-op@1788933600")
	if err != nil {
		t.Fatal(err)
	}
	if result["healthVerified"] != true || result["connectivity"] != "disconnected" || result["publicRegistryRequired"] != false {
		t.Fatalf("unexpected disconnected install result %#v", result)
	}

	// Exact inventory coverage is fail-closed: an unsealed file invalidates a retry.
	if err := os.WriteFile(filepath.Join(archive, "unsealed.tar"), []byte("drift"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.PrepareDisconnectedMirror(context.Background(), req, "disc-op-2@1788933600"); err == nil || !strings.Contains(err.Error(), "unsealed file") {
		t.Fatalf("unsealed archive drift was accepted: %v", err)
	}
}
