package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"platform.4so.io/factory/internal/gitops"
)

const (
	gitOpsPrivateKeyPath        = "/var/lib/4so-platform-installer/secrets/gitops-signing-key"
	gitOpsStatusPath            = "/var/lib/4so-platform-installer/gitops-handover.json"
	gitOpsManifestPath          = "/var/lib/4so-platform-installer/bundle/gitops/argocd-install.yaml"
	gitOpsRuntimeManifestPath   = "/var/lib/4so-platform-installer/bundle/gitops/argocd-install.platform-gitops.yaml"
	gitOpsNamespaceManifestPath = "/var/lib/4so-platform-installer/bundle/gitops/platform-gitops-namespace.yaml"
	catalogSigningKeyPath       = "/var/lib/4so-platform-installer/secrets/catalog-signing-key"
)

type GitOpsHandoverStatus struct {
	State                  string    `json:"state"`
	RevisionID             string    `json:"revisionId,omitempty"`
	RevisionDigest         string    `json:"revisionDigest,omitempty"`
	CommitSHA              string    `json:"commitSha,omitempty"`
	Repository             string    `json:"repository,omitempty"`
	Application            string    `json:"application,omitempty"`
	SyncStatus             string    `json:"syncStatus,omitempty"`
	HealthStatus           string    `json:"healthStatus,omitempty"`
	ObservedDigest         string    `json:"observedDigest,omitempty"`
	ObservedCommitSHA      string    `json:"observedCommitSha,omitempty"`
	OwnershipScope         string    `json:"ownershipScope,omitempty"`
	FullFoundationHandover bool      `json:"fullFoundationHandover"`
	UpdatedAt              time.Time `json:"updatedAt"`
	Error                  string    `json:"error,omitempty"`
}

func (r *Runner) GitOpsStatus() (GitOpsHandoverStatus, error) {
	var status GitOpsHandoverStatus
	raw, err := r.readFile(gitOpsStatusPath)
	if err != nil {
		return status, err
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		return status, err
	}
	return status, nil
}

func (r *Runner) ensureCatalogSigningKey() error {
	if r.system.Exists(catalogSigningKeyPath) {
		return nil
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := privateKey.Seed()
	return r.system.WriteFile(catalogSigningKeyPath, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600)
}

func (r *Runner) ensureGitOpsSigningKey() error {
	if r.system.Exists(gitOpsPrivateKeyPath) {
		return nil
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return r.system.WriteFile(gitOpsPrivateKeyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600)
}

func (r *Runner) loadGitOpsSigningKey() (ed25519.PrivateKey, error) {
	raw, err := r.readSecret(gitOpsPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decode GitOps signing key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func normalizeGitOpsManifestNamespace(raw []byte) ([]byte, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("Argo CD install manifest is empty")
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "namespace: argocd" {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "namespace: platform-gitops"
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (r *Runner) deployGitOpsController(ctx context.Context, bundle BundleManifest) error {
	source, err := safeBundlePath(r.bundleDir, bundle.Spec.Workloads.GitOpsManifest.Path)
	if err != nil {
		return err
	}
	if err = r.system.CopyFile(source, gitOpsManifestPath, 0o600); err != nil {
		return err
	}
	raw, err := r.readFile(gitOpsManifestPath)
	if err != nil {
		return err
	}
	runtimeManifest, err := normalizeGitOpsManifestNamespace(raw)
	if err != nil {
		return err
	}
	if err = r.system.WriteFile(gitOpsRuntimeManifestPath, runtimeManifest, 0o600); err != nil {
		return err
	}
	namespaceManifest := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: platform-gitops\n")
	if err = r.system.WriteFile(gitOpsNamespaceManifestPath, namespaceManifest, 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "apply", "--server-side", "--force-conflicts", "-f", gitOpsNamespaceManifestPath}, nil); err != nil {
		return fmt.Errorf("create platform-gitops namespace: %w", err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "apply", "--server-side", "--force-conflicts", "-f", gitOpsRuntimeManifestPath}, nil); err != nil {
		return fmt.Errorf("apply Argo CD controller manifest: %w", err)
	}
	if err = waitUntil(ctx, 2*time.Second, 5*time.Minute, func() error {
		return r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "get", "configmap", "argocd-cmd-params-cm"}, nil)
	}); err != nil {
		return fmt.Errorf("wait for Argo CD command parameters: %w", err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "patch", "configmap", "argocd-cmd-params-cm", "--type=merge", "-p", `{"data":{"server.insecure":"true"}}`}, nil); err != nil {
		return fmt.Errorf("configure Argo CD internal HTTP endpoint: %w", err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "rollout", "restart", "deployment/argocd-server"}, nil); err != nil {
		return fmt.Errorf("restart Argo CD server after internal HTTP configuration: %w", err)
	}
	checks := [][]string{{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "rollout", "status", "deployment/argocd-server", "--timeout=10m"}, {"--kubeconfig", kubeconfig, "-n", "platform-gitops", "rollout", "status", "deployment/argocd-repo-server", "--timeout=10m"}, {"--kubeconfig", kubeconfig, "-n", "platform-gitops", "rollout", "status", "statefulset/argocd-application-controller", "--timeout=10m"}}
	for _, args := range checks {
		if err = r.system.Run(ctx, kubectl, args, nil); err != nil {
			return err
		}
	}
	if err = r.ensureGitOpsObserverToken(ctx); err != nil {
		return fmt.Errorf("bootstrap Argo CD observer authority: %w", err)
	}
	return nil
}
func (r *Runner) initialSignedRevision(run Run) (gitops.Revision, string, string, error) {
	privateKey, err := r.loadGitOpsSigningKey()
	if err != nil {
		return gitops.Revision{}, "", "", err
	}
	zone := strings.TrimSpace(run.Request.Network.DNSZone)
	revision, err := gitops.Build(gitops.RevisionInput{
		ProductVersion: r.version,
		SpecDigest:     run.SpecDigest,
		BundleDigest:   run.BundleDigest,
		PublicEndpoint: run.Request.Network.PublicEndpoint,
		GitEndpoint:    "https://git." + zone,
		Registry:       "https://registry." + zone,
		Identity:       "https://auth." + zone,
	}, privateKey)
	if err != nil {
		return gitops.Revision{}, "", "", err
	}
	organization := strings.TrimSpace(run.Request.Services.Git.Organization)
	repository := strings.TrimSpace(run.Request.Services.Git.Repository)
	if organization == "" {
		organization = "platform"
	}
	if repository == "" {
		repository = "desired-state"
	}
	return revision, organization, repository, nil
}

func (r *Runner) persistPublishedRevision(run Run, revision gitops.Revision, organization, repository, commitSHA string) error {
	if !gitops.IsFullCommitSHA(strings.TrimSpace(commitSHA)) {
		return fmt.Errorf("revision publish did not return a full immutable commit SHA")
	}
	status := GitOpsHandoverStatus{
		State: "REVISION_PUBLISHED", RevisionID: revision.ID, RevisionDigest: revision.Digest,
		CommitSHA: commitSHA, Repository: organization + "/" + repository,
		Application: "platform-appliance", OwnershipScope: "platform-configuration",
		FullFoundationHandover: false, UpdatedAt: r.now().UTC(),
	}
	if err := r.writeGitOpsStatus(status); err != nil {
		return err
	}
	forgejoPassword, err := r.readSecret("/var/lib/4so-platform-installer/secrets/forgejo-admin-password")
	if err != nil {
		return err
	}
	manifest := gitOpsApplicationManifest(run, organization, repository, revision.ID, commitSHA, forgejoPassword)
	return r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-gitops-application.yaml", []byte(manifest), 0o600)
}

func (r *Runner) publishSignedRevision(ctx context.Context, run Run, bundle BundleManifest) error {
	revision, organization, repository, err := r.initialSignedRevision(run)
	if err != nil {
		return err
	}
	files := make(map[string]string, len(revision.Files))
	for path, content := range revision.Files {
		files[path] = string(content)
	}
	payload, _ := json.Marshal(map[string]any{
		"organization": organization,
		"repository":   repository,
		"revisionId":   revision.ID,
		"digest":       revision.Digest,
		"files":        files,
	})
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return err
	}
	response, err := r.clusterHTTP(ctx, bundle, "POST", "http://platform-api:8080/api/v1/system-services/git/revisions", payload, map[string]string{
		"Content-Type":               "application/json",
		"X-Actor-ID":                 "bootstrap-installer",
		"X-Platform-Bootstrap-Token": bootstrapToken,
	})
	if err != nil {
		return err
	}
	var result struct {
		CommitSHA string `json:"commitSha"`
	}
	if !r.simulation {
		if err = json.Unmarshal(response, &result); err != nil {
			return fmt.Errorf("decode revision publish response: %w", err)
		}
	} else {
		result.CommitSHA = strings.Repeat("a", 40)
	}
	return r.persistPublishedRevision(run, revision, organization, repository, result.CommitSHA)
}

func (r *Runner) reconcileInterruptedPublishedRevision(ctx context.Context, run Run) (bool, error) {
	revision, organization, repository, err := r.initialSignedRevision(run)
	if err != nil {
		return false, err
	}
	if status, statusErr := r.GitOpsStatus(); statusErr == nil {
		if status.RevisionID == revision.ID && status.RevisionDigest == revision.Digest && status.Repository == organization+"/"+repository && gitops.IsFullCommitSHA(strings.TrimSpace(status.CommitSHA)) {
			return true, nil
		}
	}
	if r.simulation {
		return false, nil
	}
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return false, err
	}
	bundle, _, err := LoadBundle(r.bundleDir)
	if err != nil {
		return false, err
	}
	endpoint := "http://platform-api:8080/api/v1/system-services/git/revisions?organization=" + url.QueryEscape(organization) + "&repository=" + url.QueryEscape(repository)
	raw, err := r.clusterHTTP(ctx, bundle, "GET", endpoint, nil, map[string]string{
		"X-Actor-ID":                 "bootstrap-installer",
		"X-Platform-Bootstrap-Token": bootstrapToken,
	})
	if err != nil {
		return false, fmt.Errorf("query durable Git revision authority: %w", err)
	}
	var revisions []struct {
		Organization string `json:"organization"`
		Repository   string `json:"repository"`
		RevisionID   string `json:"revisionId"`
		Digest       string `json:"digest"`
		CommitSHA    string `json:"commitSha"`
	}
	if err = json.Unmarshal(raw, &revisions); err != nil {
		return false, fmt.Errorf("decode durable Git revision authority: %w", err)
	}
	for _, recorded := range revisions {
		if recorded.Organization != organization || recorded.Repository != repository || recorded.RevisionID != revision.ID || recorded.Digest != revision.Digest {
			continue
		}
		if !gitops.IsFullCommitSHA(strings.TrimSpace(recorded.CommitSHA)) {
			return false, fmt.Errorf("durable Git authority recorded revision %s without a full immutable commit SHA", revision.ID)
		}
		if err = r.persistPublishedRevision(run, revision, organization, repository, recorded.CommitSHA); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (r *Runner) verifyGitOpsHandover(ctx context.Context) error {
	status, err := r.GitOpsStatus()
	if err != nil {
		return err
	}
	if r.simulation {
		status.State = "RECONCILED"
		status.SyncStatus = "Synced"
		status.HealthStatus = "Healthy"
		status.ObservedDigest = status.RevisionDigest
		status.ObservedCommitSHA = status.CommitSHA
		status.UpdatedAt = r.now().UTC()
		return r.writeGitOpsStatus(status)
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	var observed string
	var observedCommit string
	err = waitUntil(ctx, 3*time.Second, 10*time.Minute, func() error {
		syncRaw, probeErr := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "get", "application", "platform-appliance", "-o", "jsonpath={.status.sync.status}"}, nil)
		if probeErr != nil || strings.TrimSpace(string(syncRaw)) != "Synced" {
			return fmt.Errorf("Argo CD application is not Synced")
		}
		healthRaw, probeErr := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "get", "application", "platform-appliance", "-o", "jsonpath={.status.health.status}"}, nil)
		if probeErr != nil || strings.TrimSpace(string(healthRaw)) != "Healthy" {
			return fmt.Errorf("Argo CD application is not Healthy")
		}
		revisionRaw, probeErr := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-gitops", "get", "application", "platform-appliance", "-o", "jsonpath={.status.sync.revision}"}, nil)
		if probeErr != nil {
			return probeErr
		}
		observedCommit = strings.TrimSpace(string(revisionRaw))
		if probeErr = validateObservedGitOpsCommit(status.CommitSHA, observedCommit); probeErr != nil {
			return probeErr
		}
		digestRaw, probeErr := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "get", "configmap", "platform-gitops-revision", "-o", "jsonpath={.data.revisionDigest}"}, nil)
		if probeErr != nil {
			return probeErr
		}
		observed = strings.TrimSpace(string(digestRaw))
		if observed != status.RevisionDigest {
			return fmt.Errorf("observed revision digest %s does not equal desired %s", observed, status.RevisionDigest)
		}
		return nil
	})
	if err != nil {
		status.State = "FAILED"
		status.Error = err.Error()
		status.UpdatedAt = r.now().UTC()
		if persistErr := r.writeGitOpsStatus(status); persistErr != nil {
			return fmt.Errorf("%w; persist failed GitOps status: %v", err, persistErr)
		}
		return err
	}
	status.State = "RECONCILED"
	status.SyncStatus = "Synced"
	status.HealthStatus = "Healthy"
	status.ObservedDigest = observed
	status.ObservedCommitSHA = observedCommit
	status.UpdatedAt = r.now().UTC()
	return r.writeGitOpsStatus(status)
}

func validateObservedGitOpsCommit(desired, observed string) error {
	desired = strings.TrimSpace(desired)
	observed = strings.TrimSpace(observed)
	if !gitops.IsFullCommitSHA(desired) {
		return fmt.Errorf("desired GitOps commit is not a full immutable Git SHA")
	}
	if observed != desired {
		return fmt.Errorf("Argo CD observed commit %s does not equal desired %s", observed, desired)
	}
	return nil
}

func (r *Runner) writeGitOpsStatus(status GitOpsHandoverStatus) error {
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return r.system.WriteFile(gitOpsStatusPath, append(raw, '\n'), 0o600)
}

func gitOpsApplicationManifest(run Run, organization, repository, revisionID, commitSHA, forgejoPassword string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: platform-internal-git
  namespace: platform-gitops
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: http://platform-forgejo.platform-system.svc.cluster.local:3000/%s/%s.git
  username: platform-admin
  password: %s
---
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: platform
  namespace: platform-gitops
spec:
  sourceRepos:
    - http://platform-forgejo.platform-system.svc.cluster.local:3000/%s/%s.git
  destinations:
    - namespace: platform-system
      server: https://kubernetes.default.svc
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: ""
      kind: ConfigMap
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: platform-appliance
  namespace: platform-gitops
  annotations:
    platform.4so.io/revision: %q
    platform.4so.io/commit-sha: %q
spec:
  project: platform
  source:
    repoURL: http://platform-forgejo.platform-system.svc.cluster.local:3000/%s/%s.git
    targetRevision: main
    path: clusters/appliance
  destination:
    server: https://kubernetes.default.svc
    namespace: platform-system
  syncPolicy:
    automated:
      prune: false
      selfHeal: true
    syncOptions:
      - CreateNamespace=false
`, organization, repository, yamlScalar(forgejoPassword), organization, repository, revisionID, commitSHA, organization, repository)
}
