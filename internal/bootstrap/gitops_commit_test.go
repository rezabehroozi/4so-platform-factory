package bootstrap

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type gitOpsVerifySystem struct {
	*SimulatedSystem
	commit string
	digest string
}

func (s *gitOpsVerifySystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "jsonpath={.status.sync.status}"):
		return []byte("Synced"), nil
	case strings.Contains(joined, "jsonpath={.status.health.status}"):
		return []byte("Healthy"), nil
	case strings.Contains(joined, "jsonpath={.status.sync.revision}"):
		return []byte(s.commit), nil
	case strings.Contains(joined, "jsonpath={.data.revisionDigest}"):
		return []byte(s.digest), nil
	default:
		return nil, fmt.Errorf("unexpected output command %s %v", name, args)
	}
}

// Keep explicit interface coverage here because GitOps verification runs through
// the same System boundary as the real bootstrap runner.
func (s *gitOpsVerifySystem) RunInput(ctx context.Context, name string, args []string, env map[string]string, input io.Reader) error {
	return s.SimulatedSystem.RunInput(ctx, name, args, env, input)
}

func TestNormalizeGitOpsManifestNamespace(t *testing.T) {
	raw := []byte("metadata:\n  labels:\n    app.kubernetes.io/part-of: argocd\nsubjects:\n- kind: ServiceAccount\n  name: argocd-server\n  namespace: argocd\n")
	got, err := normalizeGitOpsManifestNamespace(raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Contains(text, "namespace: argocd") || !strings.Contains(text, "namespace: platform-gitops") {
		t.Fatalf("namespace was not normalized:\n%s", text)
	}
	if !strings.Contains(text, "app.kubernetes.io/part-of: argocd") || !strings.Contains(text, "name: argocd-server") {
		t.Fatalf("non-namespace Argo identity was rewritten:\n%s", text)
	}
	if _, err = normalizeGitOpsManifestNamespace([]byte("  \n")); err == nil {
		t.Fatal("empty Argo CD manifest was accepted")
	}
}

func TestGitOpsManifestSelectionIsProfileAware(t *testing.T) {
	var bundle BundleManifest
	bundle.Spec.Workloads.GitOpsManifest = Artifact{Path: "artifacts/argocd-standard.yaml", SHA256: "sha256:" + strings.Repeat("a", 64)}
	bundle.Spec.Workloads.GitOpsHAManifest = Artifact{Path: "artifacts/argocd-ha.yaml", SHA256: "sha256:" + strings.Repeat("b", 64)}

	single := Run{}
	single.Request.ProfileID = "evaluation-single-node"
	got, err := gitOpsManifestForRun(single, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != bundle.Spec.Workloads.GitOpsManifest.Path {
		t.Fatalf("single-node selected %q, want standard manifest", got.Path)
	}

	ha := Run{}
	ha.Request.ProfileID = "production-standard-ha"
	got, err = gitOpsManifestForRun(ha, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != bundle.Spec.Workloads.GitOpsHAManifest.Path {
		t.Fatalf("HA selected %q, want HA manifest", got.Path)
	}

	bundle.Spec.Workloads.GitOpsHAManifest = Artifact{}
	if _, err = gitOpsManifestForRun(ha, bundle); err == nil || !strings.Contains(err.Error(), "requires a digest-locked GitOps HA") {
		t.Fatalf("production HA accepted a bundle without HA GitOps authority: %v", err)
	}
}

func TestVerifyGitOpsHandoverRequiresExactPublishedCommit(t *testing.T) {
	desiredCommit := strings.Repeat("a", 40)
	if err := validateObservedGitOpsCommit(desiredCommit, strings.Repeat("c", 40)); err == nil || !strings.Contains(err.Error(), "observed commit") {
		t.Fatalf("expected immutable commit mismatch, got %v", err)
	}
	if err := validateObservedGitOpsCommit("abcdef1", "abcdef1"); err == nil {
		t.Fatal("abbreviated desired commit was accepted")
	}
}

func TestVerifyGitOpsHandoverPersistsObservedCommit(t *testing.T) {
	root := t.TempDir()
	desiredCommit := strings.Repeat("a", 40)
	digest := "sha256:" + strings.Repeat("b", 64)
	system := &gitOpsVerifySystem{SimulatedSystem: &SimulatedSystem{Root: root}, commit: desiredCommit, digest: digest}
	runner := &Runner{system: system, simulation: false, now: func() time.Time { return time.Unix(1, 0).UTC() }}
	if err := runner.writeGitOpsStatus(GitOpsHandoverStatus{State: "REVISION_PUBLISHED", CommitSHA: desiredCommit, RevisionDigest: digest}); err != nil {
		t.Fatal(err)
	}
	if err := runner.verifyGitOpsHandover(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := runner.GitOpsStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "RECONCILED" || status.ObservedCommitSHA != desiredCommit || status.ObservedDigest != digest {
		t.Fatalf("status=%+v", status)
	}
}


type legacyGitOpsMigrationSystem struct {
	*SimulatedSystem
	namespaceJSON []byte
	applicationJSON []byte
	deletedApplication bool
	deletedNamespace bool
}

func (s *legacyGitOpsMigrationSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	joined := strings.Join(args, " ")
	s.Commands = append(s.Commands, name+" "+joined)
	switch {
	case strings.Contains(joined, "get namespace/argocd"):
		return s.namespaceJSON, nil
	case strings.Contains(joined, "get application/platform-appliance"):
		return s.applicationJSON, nil
	default:
		return nil, fmt.Errorf("unexpected output command %s %v", name, args)
	}
}

func (s *legacyGitOpsMigrationSystem) Run(_ context.Context, name string, args []string, _ map[string]string) error {
	joined := strings.Join(args, " ")
	s.Commands = append(s.Commands, name+" "+joined)
	if strings.Contains(joined, "-n argocd delete application/platform-appliance") {
		s.deletedApplication = true
	}
	if strings.Contains(joined, "delete namespace/argocd") {
		s.deletedNamespace = true
	}
	return nil
}

func legacyNamespaceJSON(uid string, owned bool) []byte {
	annotation := ""
	if owned {
		annotation = `,"annotations":{"platform.4so.io/bootstrap-owner":"4so-platform-installer"}`
	}
	return []byte(fmt.Sprintf(`{"metadata":{"uid":"%s"%s}}`, uid, annotation))
}

func legacyApplicationJSON(uid, project, repo string) []byte {
	return []byte(fmt.Sprintf(`{"metadata":{"uid":"%s"},"spec":{"project":"%s","source":{"repoURL":"%s"}}}`, uid, project, repo))
}

func TestCanonicalGitOpsNamespaceCarriesOwnershipAuthority(t *testing.T) {
	manifest := string(gitOpsNamespaceManifest())
	for _, required := range []string{
		"name: platform-gitops",
		"platform.4so.io/bootstrap-owner: \"4so-platform-installer\"",
		"platform.4so.io/gitops-namespace-role: \"canonical\"",
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("canonical GitOps namespace is missing %q:\n%s", required, manifest)
		}
	}
}

func TestLegacyGitOpsForeignApplicationIsUntouched(t *testing.T) {
	root := t.TempDir()
	system := &legacyGitOpsMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		namespaceJSON: legacyNamespaceJSON("legacy-ns-1", false),
		applicationJSON: legacyApplicationJSON("foreign-app-1", "default", "https://example.invalid/foreign.git"),
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Unix(100, 0).UTC() }}
	if err := runner.deactivateLegacyGitOpsApplication(context.Background()); err != nil { t.Fatal(err) }
	if system.deletedApplication || system.deletedNamespace {
		t.Fatalf("foreign legacy Argo authority was mutated: commands=%v", system.Commands)
	}
	status, err := runner.GitOpsLegacyMigrationStatus()
	if err != nil || status == nil || status.State != "FOREIGN_OR_UNUSED_UNTOUCHED" {
		t.Fatalf("foreign namespace status=%#v err=%v", status, err)
	}
}

func TestLegacyGitOpsProductApplicationDeactivatesWithoutDeletingUnownedNamespace(t *testing.T) {
	root := t.TempDir()
	repo := "http://platform-forgejo.platform-system.svc.cluster.local:3000/platform/desired-state.git"
	system := &legacyGitOpsMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		namespaceJSON: legacyNamespaceJSON("legacy-ns-2", false),
		applicationJSON: legacyApplicationJSON("legacy-app-2", "platform", repo),
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Unix(101, 0).UTC() }}
	if err := runner.deactivateLegacyGitOpsApplication(context.Background()); err != nil { t.Fatal(err) }
	if !system.deletedApplication || system.deletedNamespace {
		t.Fatalf("product Application deactivation boundary is wrong: commands=%v", system.Commands)
	}
	if err := runner.cleanupOwnedLegacyGitOpsNamespace(context.Background()); err != nil { t.Fatal(err) }
	if system.deletedNamespace {
		t.Fatal("unowned legacy namespace was deleted")
	}
	status, err := runner.GitOpsLegacyMigrationStatus()
	if err != nil || status == nil || status.State != "PRODUCT_APPLICATION_DEACTIVATED_REVIEW_REQUIRED" {
		t.Fatalf("review-required status=%#v err=%v", status, err)
	}
}

func TestLegacyGitOpsOwnedNamespaceDeletesOnlyAfterProductApplicationDeactivation(t *testing.T) {
	root := t.TempDir()
	repo := "http://platform-forgejo.platform-system.svc.cluster.local:3000/platform/desired-state.git"
	system := &legacyGitOpsMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		namespaceJSON: legacyNamespaceJSON("legacy-ns-3", true),
		applicationJSON: legacyApplicationJSON("legacy-app-3", "platform", repo),
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Unix(102, 0).UTC() }}
	if err := runner.deactivateLegacyGitOpsApplication(context.Background()); err != nil { t.Fatal(err) }
	if !system.deletedApplication || system.deletedNamespace {
		t.Fatalf("legacy product Application was not isolated before namespace cleanup: %v", system.Commands)
	}
	if err := runner.cleanupOwnedLegacyGitOpsNamespace(context.Background()); err != nil { t.Fatal(err) }
	if !system.deletedNamespace {
		t.Fatalf("explicitly product-owned legacy namespace was not deleted: %v", system.Commands)
	}
	status, err := runner.GitOpsLegacyMigrationStatus()
	if err != nil || status == nil || status.State != "OWNED_LEGACY_NAMESPACE_REMOVED" {
		t.Fatalf("cleanup status=%#v err=%v", status, err)
	}
}
