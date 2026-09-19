package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	gitOpsLegacyMigrationAuthority = "GITOPS_LEGACY_NAMESPACE_MIGRATION_V1"
	gitOpsLegacyMigrationPath      = "/var/lib/4so-platform-installer/gitops-legacy-migration.json"
	gitOpsNamespaceOwnerAnnotation = "platform.4so.io/bootstrap-owner"
	gitOpsNamespaceRoleAnnotation  = "platform.4so.io/gitops-namespace-role"
	gitOpsInstallerOwner           = "4so-platform-installer"
)

type GitOpsLegacyMigrationStatus struct {
	Authority      string    `json:"authority"`
	State          string    `json:"state"`
	Namespace      string    `json:"namespace,omitempty"`
	NamespaceUID   string    `json:"namespaceUid,omitempty"`
	ApplicationUID string    `json:"applicationUid,omitempty"`
	RepositoryURL  string    `json:"repositoryUrl,omitempty"`
	NamespaceOwned bool      `json:"namespaceOwned"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type legacyNamespaceEnvelope struct {
	Metadata struct {
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

type legacyApplicationEnvelope struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Project string `json:"project"`
		Source struct {
			RepoURL string `json:"repoURL"`
		} `json:"source"`
	} `json:"spec"`
}

func productLegacyGitOpsRepository(raw string) bool {
	raw = strings.TrimSpace(raw)
	const prefix = "http://platform-forgejo.platform-system.svc.cluster.local:3000/"
	return strings.HasPrefix(raw, prefix) && strings.HasSuffix(raw, ".git") && len(raw) > len(prefix)+len(".git")
}

func (r *Runner) writeLegacyGitOpsMigrationStatus(status GitOpsLegacyMigrationStatus) error {
	status.Authority = gitOpsLegacyMigrationAuthority
	status.UpdatedAt = r.now().UTC()
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return r.system.WriteFile(gitOpsLegacyMigrationPath, append(raw, '\n'), 0o600)
}

func (r *Runner) GitOpsLegacyMigrationStatus() (*GitOpsLegacyMigrationStatus, error) {
	raw, err := r.readFile(gitOpsLegacyMigrationPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var status GitOpsLegacyMigrationStatus
	if err = json.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("decode legacy GitOps migration status: %w", err)
	}
	if status.Authority != gitOpsLegacyMigrationAuthority || strings.TrimSpace(status.State) == "" {
		return nil, errors.New("legacy GitOps migration authority is invalid")
	}
	return &status, nil
}

func (r *Runner) legacyGitOpsNamespace(ctx context.Context) (*legacyNamespaceEnvelope, error) {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	raw, err := r.system.Output(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "get", "namespace/argocd", "--ignore-not-found", "-o", "json",
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy Argo CD namespace: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var namespace legacyNamespaceEnvelope
	if err = json.Unmarshal(raw, &namespace); err != nil {
		return nil, fmt.Errorf("decode legacy Argo CD namespace: %w", err)
	}
	if strings.TrimSpace(namespace.Metadata.UID) == "" {
		return nil, errors.New("legacy Argo CD namespace has no immutable UID")
	}
	return &namespace, nil
}

func (r *Runner) legacyGitOpsApplication(ctx context.Context) (*legacyApplicationEnvelope, error) {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	raw, err := r.system.Output(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "argocd", "get", "application/platform-appliance", "--ignore-not-found", "-o", "json",
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy platform GitOps Application: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var app legacyApplicationEnvelope
	if err = json.Unmarshal(raw, &app); err != nil {
		return nil, fmt.Errorf("decode legacy platform GitOps Application: %w", err)
	}
	if strings.TrimSpace(app.Metadata.UID) == "" {
		return nil, errors.New("legacy platform GitOps Application has no immutable UID")
	}
	return &app, nil
}

func (r *Runner) deactivateLegacyGitOpsApplication(ctx context.Context) error {
	if r.simulation {
		return nil
	}
	namespace, err := r.legacyGitOpsNamespace(ctx)
	if err != nil || namespace == nil {
		return err
	}
	app, err := r.legacyGitOpsApplication(ctx)
	if err != nil {
		return err
	}
	ownedNamespace := namespace.Metadata.Annotations[gitOpsNamespaceOwnerAnnotation] == gitOpsInstallerOwner
	if app == nil || app.Spec.Project != "platform" || !productLegacyGitOpsRepository(app.Spec.Source.RepoURL) {
		return r.writeLegacyGitOpsMigrationStatus(GitOpsLegacyMigrationStatus{
			State: "FOREIGN_OR_UNUSED_UNTOUCHED", Namespace: "argocd", NamespaceUID: namespace.Metadata.UID, NamespaceOwned: ownedNamespace,
		})
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	if err = r.system.Run(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "argocd", "delete", "application/platform-appliance", "--wait=true",
	}, nil); err != nil {
		return fmt.Errorf("deactivate product-owned legacy GitOps Application before canonical publication: %w", err)
	}
	return r.writeLegacyGitOpsMigrationStatus(GitOpsLegacyMigrationStatus{
		State: "PRODUCT_APPLICATION_DEACTIVATED", Namespace: "argocd", NamespaceUID: namespace.Metadata.UID,
		ApplicationUID: app.Metadata.UID, RepositoryURL: strings.TrimSpace(app.Spec.Source.RepoURL), NamespaceOwned: ownedNamespace,
	})
}

func (r *Runner) cleanupOwnedLegacyGitOpsNamespace(ctx context.Context) error {
	status, err := r.GitOpsLegacyMigrationStatus()
	if err != nil || status == nil || status.State != "PRODUCT_APPLICATION_DEACTIVATED" {
		return err
	}
	if !status.NamespaceOwned {
		status.State = "PRODUCT_APPLICATION_DEACTIVATED_REVIEW_REQUIRED"
		return r.writeLegacyGitOpsMigrationStatus(*status)
	}
	namespace, err := r.legacyGitOpsNamespace(ctx)
	if err != nil {
		return err
	}
	if namespace == nil {
		status.State = "OWNED_LEGACY_NAMESPACE_ABSENT"
		return r.writeLegacyGitOpsMigrationStatus(*status)
	}
	if namespace.Metadata.UID != status.NamespaceUID || namespace.Metadata.Annotations[gitOpsNamespaceOwnerAnnotation] != gitOpsInstallerOwner {
		return errors.New("legacy Argo CD namespace identity changed after migration admission; refusing deletion")
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	if err = r.system.Run(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "delete", "namespace/argocd", "--wait=true",
	}, nil); err != nil {
		return fmt.Errorf("remove product-owned legacy Argo CD namespace: %w", err)
	}
	status.State = "OWNED_LEGACY_NAMESPACE_REMOVED"
	return r.writeLegacyGitOpsMigrationStatus(*status)
}
