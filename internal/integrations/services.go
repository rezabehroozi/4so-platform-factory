package integrations

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/gitops"
	"platform.4so.io/factory/internal/imagebundle"
)

type GitConnection struct {
	ProviderID   string `json:"providerId"`
	ProviderName string `json:"providerName"`
	BaseURL      string `json:"baseUrl"`
	CredentialID string `json:"credentialId"`
	Username     string `json:"username"`
	SecretRef    string `json:"secretRef"`
}

type Config struct {
	GitConnectionResolver      func(context.Context) (GitConnection, error)
	ZotURL                     string
	KeycloakURL                string
	ArgoCDURL                  string
	ArgoCDToken                string
	RepositoryBootstrapEnabled bool
}

type ServiceStatus struct {
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Configured    bool   `json:"configured"`
	Healthy       bool   `json:"healthy"`
	Version       string `json:"version,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	Error         string `json:"error,omitempty"`
	CredentialID  string `json:"credentialId,omitempty"`
	CredentialRef string `json:"credentialRef,omitempty"`
}

type RepositoryRequest struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Private      bool   `json:"private"`
}

type RevisionRequest struct {
	Organization string            `json:"organization"`
	Repository   string            `json:"repository"`
	RevisionID   string            `json:"revisionId"`
	Digest       string            `json:"digest"`
	DeliveryMode string            `json:"deliveryMode,omitempty"`
	Files        map[string]string `json:"files"`
}

type RevisionResult struct {
	Organization         string `json:"organization"`
	Repository           string `json:"repository"`
	RevisionID           string `json:"revisionId"`
	Digest               string `json:"digest"`
	CommitSHA            string `json:"commitSha"`
	ChangedFiles         int    `json:"changedFiles"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
}

type GitOpsApplicationObservation struct {
	Application  string `json:"application"`
	SyncStatus   string `json:"syncStatus"`
	HealthStatus string `json:"healthStatus"`
	Revision     string `json:"revision"`
}

type GitRevisionSnapshot struct {
	Organization         string   `json:"organization"`
	Repository           string   `json:"repository"`
	Branch               string   `json:"branch"`
	RevisionID           string   `json:"revisionId"`
	Digest               string   `json:"digest"`
	CommitSHA            string   `json:"commitSha"`
	PublicKeyFingerprint string   `json:"publicKeyFingerprint"`
	Trusted              bool     `json:"trusted"`
	ChangedFiles         []string `json:"changedFiles,omitempty"`
}

type revisionDescriptor struct {
	Metadata struct {
		ID string `json:"id"`
	} `json:"metadata"`
	Spec      gitops.RevisionInput `json:"spec"`
	Integrity struct {
		Digest               string `json:"digest"`
		Signature            string `json:"signature"`
		PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	} `json:"integrity"`
}

type RepositoryResult struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	HTMLURL      string `json:"htmlUrl,omitempty"`
	CloneURL     string `json:"cloneUrl,omitempty"`
	Created      bool   `json:"created"`
	Seeded       bool   `json:"seeded"`
}

type Client struct {
	config Config
	http   *http.Client
}

func New(config Config) *Client {
	config.ZotURL = strings.TrimRight(strings.TrimSpace(config.ZotURL), "/")
	config.KeycloakURL = strings.TrimRight(strings.TrimSpace(config.KeycloakURL), "/")
	config.ArgoCDURL = strings.TrimRight(strings.TrimSpace(config.ArgoCDURL), "/")
	config.ArgoCDToken = strings.TrimSpace(config.ArgoCDToken)
	return &Client{config: config, http: &http.Client{Timeout: 8 * time.Second}}
}

func (c *Client) Configured() bool {
	return c != nil && (c.config.GitConnectionResolver != nil || c.config.ZotURL != "" || c.config.KeycloakURL != "" || c.config.ArgoCDURL != "")
}

func (c *Client) RepositoryBootstrapEnabled() bool {
	return c != nil && c.config.RepositoryBootstrapEnabled
}

func (c *Client) Status(ctx context.Context) []ServiceStatus {
	if c == nil {
		return []ServiceStatus{
			{Name: "git", Provider: "forgejo", Configured: false},
			{Name: "registry", Provider: "zot", Configured: false},
			{Name: "identity", Provider: "keycloak", Configured: false},
			{Name: "gitops", Provider: "argocd", Configured: false},
		}
	}
	return []ServiceStatus{c.forgejoStatus(ctx), c.zotStatus(ctx), c.keycloakStatus(ctx), c.argocdStatus(ctx)}
}

func forgejoSupportsAtomicMultiFile(version string) bool {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return major > 1 || (major == 1 && minor >= 20)
}

func (c *Client) forgejoStatus(ctx context.Context) ServiceStatus {
	result := ServiceStatus{Name: "git", Provider: "forgejo", Configured: c != nil && c.config.GitConnectionResolver != nil}
	if !result.Configured {
		return result
	}
	conn, err := c.gitConnection(ctx)
	if err != nil {
		result.Configured = false
		result.Error = err.Error()
		return result
	}
	result.Endpoint, result.CredentialID, result.CredentialRef = conn.BaseURL, conn.CredentialID, conn.SecretRef
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, conn.BaseURL+"/api/v1/version", nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := c.http.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		return result
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Version = payload.Version
	if !forgejoSupportsAtomicMultiFile(payload.Version) {
		result.Error = fmt.Sprintf("Forgejo %q does not provide the atomic multi-file repository API required by managed Git publication (minimum compatible version: 1.20)", payload.Version)
		return result
	}
	result.Healthy = true
	return result
}

func (c *Client) zotStatus(ctx context.Context) ServiceStatus {
	result := ServiceStatus{Name: "registry", Provider: "zot", Configured: c.config.ZotURL != "", Endpoint: c.config.ZotURL}
	if !result.Configured {
		return result
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.ZotURL+"/v2/", nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := c.http.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		return result
	}
	result.Healthy = true
	result.Version = response.Header.Get("Docker-Distribution-Api-Version")
	return result
}

func (c *Client) keycloakStatus(ctx context.Context) ServiceStatus {
	result := ServiceStatus{Name: "identity", Provider: "keycloak", Configured: c.config.KeycloakURL != "", Endpoint: c.config.KeycloakURL}
	if !result.Configured {
		return result
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.KeycloakURL+"/realms/platform/.well-known/openid-configuration", nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := c.http.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		return result
	}
	var payload struct {
		Issuer string `json:"issuer"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || strings.TrimSpace(payload.Issuer) == "" {
		if err == nil {
			err = errors.New("issuer missing")
		}
		result.Error = err.Error()
		return result
	}
	result.Healthy = true
	result.Version = "oidc"
	return result
}

func (c *Client) argocdStatus(ctx context.Context) ServiceStatus {
	result := ServiceStatus{Name: "gitops", Provider: "argocd", Configured: c.config.ArgoCDURL != "", Endpoint: c.config.ArgoCDURL}
	if !result.Configured {
		return result
	}
	if c.config.ArgoCDToken == "" {
		result.Error = "Argo CD observation token is not configured"
		return result
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.ArgoCDURL+"/healthz", nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := c.http.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		return result
	}
	result.Healthy = true
	result.Version = "managed"
	return result
}

func (c *Client) ObserveGitOpsApplication(ctx context.Context, application string) (GitOpsApplicationObservation, error) {
	if c == nil || strings.TrimSpace(c.config.ArgoCDURL) == "" {
		return GitOpsApplicationObservation{}, errors.New("managed Argo CD integration is not configured")
	}
	application = strings.TrimSpace(application)
	if application == "" || !safeName(application) {
		return GitOpsApplicationObservation{}, errors.New("application name is required")
	}
	if c.config.ArgoCDToken == "" {
		return GitOpsApplicationObservation{}, errors.New("managed Argo CD observation token is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.ArgoCDURL+"/api/v1/applications/"+url.PathEscape(application), nil)
	if err != nil {
		return GitOpsApplicationObservation{}, err
	}
	request.Header.Set("Authorization", "Bearer "+c.config.ArgoCDToken)
	response, err := c.http.Do(request)
	if err != nil {
		return GitOpsApplicationObservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return GitOpsApplicationObservation{}, fmt.Errorf("Argo CD application observation returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			} `json:"sync"`
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
		} `json:"status"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return GitOpsApplicationObservation{}, err
	}
	result := GitOpsApplicationObservation{Application: strings.TrimSpace(payload.Metadata.Name), SyncStatus: strings.TrimSpace(payload.Status.Sync.Status), HealthStatus: strings.TrimSpace(payload.Status.Health.Status), Revision: strings.TrimSpace(payload.Status.Sync.Revision)}
	if result.Application == "" {
		result.Application = application
	}
	if result.SyncStatus == "" || result.HealthStatus == "" || result.Revision == "" {
		return GitOpsApplicationObservation{}, errors.New("Argo CD application status is incomplete")
	}
	return result, nil
}

func (c *Client) EnsureRepository(ctx context.Context, input RepositoryRequest) (RepositoryResult, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return RepositoryResult{}, errors.New("managed Forgejo integration is not configured")
	}
	input.Organization = strings.TrimSpace(input.Organization)
	input.Name = strings.TrimSpace(input.Name)
	if input.Organization == "" || input.Name == "" {
		return RepositoryResult{}, errors.New("organization and repository name are required")
	}
	if !safeName(input.Organization) || !safeName(input.Name) {
		return RepositoryResult{}, errors.New("organization and repository names may contain only letters, numbers, dot, dash and underscore")
	}
	if err := c.ensureOrganization(ctx, input.Organization); err != nil {
		return RepositoryResult{}, err
	}
	result, found, err := c.getRepository(ctx, input.Organization, input.Name)
	if err != nil {
		return RepositoryResult{}, err
	}
	if found {
		return result, nil
	}
	body := map[string]any{"name": input.Name, "description": input.Description, "private": input.Private, "auto_init": false, "default_branch": "main"}
	var created forgejoRepository
	if err = c.forgejoJSON(ctx, http.MethodPost, "/api/v1/orgs/"+url.PathEscape(input.Organization)+"/repos", body, &created, http.StatusCreated); err != nil {
		return RepositoryResult{}, err
	}
	result = repositoryResult(created)
	result.Created = true
	seeded, seedErr := c.seedRepository(ctx, input.Organization, input.Name)
	if seedErr != nil {
		return result, seedErr
	}
	result.Seeded = seeded
	return result, nil
}

func (c *Client) ensureOrganization(ctx context.Context, name string) error {
	var organization map[string]any
	err := c.forgejoJSON(ctx, http.MethodGet, "/api/v1/orgs/"+url.PathEscape(name), nil, &organization, http.StatusOK)
	if err == nil {
		return nil
	}
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusNotFound {
		return err
	}
	payload := map[string]any{"username": name, "full_name": "4SO Platform Factory", "visibility": "private", "repo_admin_change_team_access": true}
	return c.forgejoJSON(ctx, http.MethodPost, "/api/v1/orgs", payload, &organization, http.StatusCreated)
}

type forgejoRepository struct {
	Name     string `json:"name"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func repositoryResult(value forgejoRepository) RepositoryResult {
	return RepositoryResult{Organization: value.Owner.Login, Name: value.Name, HTMLURL: value.HTMLURL, CloneURL: value.CloneURL}
}

func (c *Client) getRepository(ctx context.Context, organization, name string) (RepositoryResult, bool, error) {
	var repository forgejoRepository
	err := c.forgejoJSON(ctx, http.MethodGet, "/api/v1/repos/"+url.PathEscape(organization)+"/"+url.PathEscape(name), nil, &repository, http.StatusOK)
	if err == nil {
		return repositoryResult(repository), true, nil
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.Status == http.StatusNotFound {
		return RepositoryResult{}, false, nil
	}
	return RepositoryResult{}, false, err
}

const managedRepositorySeedReadme = "# Managed Platform Desired State\n\nThis repository is generated and managed by 4SO Platform Factory.\n"

func (c *Client) seedRepository(ctx context.Context, organization, repository string) (bool, error) {
	content := map[string]any{
		"message":    "Initialize managed platform desired state",
		"content":    base64.StdEncoding.EncodeToString([]byte(managedRepositorySeedReadme)),
		"branch":     "main",
		"new_branch": "main",
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents/README.md"
	var response map[string]any
	err := c.forgejoJSON(ctx, http.MethodPost, endpoint, content, &response, http.StatusCreated)
	if err == nil {
		return true, nil
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.Status == http.StatusConflict {
		return false, nil
	}
	return false, err
}

func (c *Client) BootstrapRepositoryBaseCommit(ctx context.Context, organization, repository string) (string, error) {
	organization = strings.TrimSpace(organization)
	repository = strings.TrimSpace(repository)
	if !safeName(organization) || !safeName(repository) {
		return "", errors.New("organization and repository are required")
	}
	commit, err := c.branchCommit(ctx, organization, repository, "main")
	if err != nil {
		return "", err
	}
	var entries []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents?ref=main"
	if err = c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &entries, http.StatusOK); err != nil {
		return "", err
	}
	if len(entries) != 1 || entries[0].Path != "README.md" || (entries[0].Type != "" && entries[0].Type != "file") {
		return "", errors.New("existing repository is not the exact product-managed bootstrap seed")
	}
	raw, err := c.repositoryFile(ctx, organization, repository, "README.md", "main")
	if err != nil {
		return "", err
	}
	if string(raw) != managedRepositorySeedReadme {
		return "", errors.New("existing repository bootstrap README does not match the product-managed seed")
	}
	return commit, nil
}

func (c *Client) requireForgejoAtomicPublicationCapability(ctx context.Context) error {
	status := c.forgejoStatus(ctx)
	if status.Healthy {
		return nil
	}
	if status.Error == "" {
		status.Error = "managed Forgejo capability is not healthy"
	}
	return fmt.Errorf("managed Forgejo publication capability: %s", status.Error)
}

func (c *Client) PublishRevision(ctx context.Context, input RevisionRequest) (RevisionResult, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return RevisionResult{}, errors.New("managed Forgejo integration is not configured")
	}
	input.Organization = strings.TrimSpace(input.Organization)
	input.Repository = strings.TrimSpace(input.Repository)
	if _, _, err := validateRevisionRequest(input); err != nil {
		return RevisionResult{}, err
	}
	if err := c.requireForgejoAtomicPublicationCapability(ctx); err != nil {
		return RevisionResult{}, err
	}
	if _, err := c.EnsureRepository(ctx, RepositoryRequest{Organization: input.Organization, Name: input.Repository, Description: "Managed platform desired state", Private: true}); err != nil {
		return RevisionResult{}, err
	}
	base, err := c.branchCommit(ctx, input.Organization, input.Repository, "main")
	if err != nil {
		return RevisionResult{}, err
	}
	return c.PublishRevisionFromBase(ctx, input, base)
}

// PublishRevisionFromBase performs direct delivery as a staged atomic commit and
// compare-and-swap of the managed branch. The caller must supply the exact
// durable/live base authority it planned against.
func (c *Client) PublishRevisionFromBase(ctx context.Context, input RevisionRequest, expectedBaseCommit string) (RevisionResult, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return RevisionResult{}, errors.New("managed Forgejo integration is not configured")
	}
	descriptor, paths, err := validateRevisionRequest(input)
	if err != nil {
		return RevisionResult{}, err
	}
	expectedBaseCommit = strings.TrimSpace(expectedBaseCommit)
	if !gitops.IsFullCommitSHA(expectedBaseCommit) {
		return RevisionResult{}, errors.New("full immutable base commit is required for direct Git delivery")
	}
	if err = c.requireForgejoAtomicPublicationCapability(ctx); err != nil {
		return RevisionResult{}, err
	}
	files := make(map[string][]byte, len(paths))
	for _, filePath := range paths {
		files[filePath] = []byte(input.Files[filePath])
	}
	changed, commitSHA, err := c.commitManagedFilesWithBranchCAS(ctx, input.Organization, input.Repository, "main", expectedBaseCommit, directStageBranch(input.RevisionID), files, "Publish "+input.RevisionID+" ("+input.Digest+")")
	if err != nil {
		return RevisionResult{}, err
	}
	snapshot, err := c.InspectGitRevision(ctx, input.Organization, input.Repository, "main", expectedBaseCommit, descriptor.Integrity.PublicKeyFingerprint)
	if err != nil {
		return RevisionResult{}, err
	}
	if !snapshot.Trusted || snapshot.CommitSHA != commitSHA || snapshot.RevisionID != input.RevisionID || snapshot.Digest != input.Digest || snapshot.PublicKeyFingerprint != descriptor.Integrity.PublicKeyFingerprint {
		return RevisionResult{}, errors.New("direct Git delivery result does not match the exact signed revision intent")
	}
	if err := validateManagedRevisionChangedFiles(snapshot.ChangedFiles); err != nil {
		return RevisionResult{}, err
	}
	if err := c.ValidateManagedRepositoryTree(ctx, input.Organization, input.Repository, commitSHA); err != nil {
		return RevisionResult{}, err
	}
	return RevisionResult{Organization: input.Organization, Repository: input.Repository, RevisionID: input.RevisionID, Digest: input.Digest, CommitSHA: commitSHA, ChangedFiles: changed, PublicKeyFingerprint: descriptor.Integrity.PublicKeyFingerprint}, nil
}

func (c *Client) changeRepositoryFilesAtomic(ctx context.Context, organization, repository, branch string, files map[string][]byte, message string) (int, string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	paths := make([]string, 0, len(files))
	for filePath := range files {
		clean := strings.TrimPrefix(path.Clean("/"+filePath), "/")
		if clean == "" || strings.Contains(clean, "..") {
			return 0, "", fmt.Errorf("unsafe repository path %q", filePath)
		}
		paths = append(paths, clean)
	}
	sort.Strings(paths)
	operations := make([]map[string]any, 0, len(paths))
	for _, filePath := range paths {
		var existing struct {
			SHA     string `json:"sha"`
			Content string `json:"content"`
		}
		endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents/" + strings.Join(escapePathSegments(filePath), "/")
		err := c.forgejoJSON(ctx, http.MethodGet, endpoint+"?ref="+url.QueryEscape(branch), nil, &existing, http.StatusOK)
		encoded := base64.StdEncoding.EncodeToString(files[filePath])
		if err == nil {
			current, decodeErr := base64.StdEncoding.DecodeString(strings.ReplaceAll(existing.Content, "\n", ""))
			if decodeErr == nil && bytes.Equal(current, files[filePath]) {
				continue
			}
			if strings.TrimSpace(existing.SHA) == "" {
				return 0, "", fmt.Errorf("Forgejo content response for %s did not include file sha", filePath)
			}
			operations = append(operations, map[string]any{"operation": "update", "path": filePath, "content": encoded, "sha": existing.SHA})
			continue
		}
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || statusErr.Status != http.StatusNotFound {
			return 0, "", err
		}
		operations = append(operations, map[string]any{"operation": "create", "path": filePath, "content": encoded})
	}
	if len(operations) == 0 {
		commit, err := c.branchCommit(ctx, organization, repository, branch)
		return 0, commit, err
	}
	payload := map[string]any{"branch": branch, "message": message, "files": operations}
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents"
	if err := c.forgejoJSON(ctx, http.MethodPost, endpoint, payload, &out, http.StatusCreated); err != nil {
		return 0, "", err
	}
	commit := strings.TrimSpace(out.Commit.SHA)
	if !gitops.IsFullCommitSHA(commit) {
		return 0, "", fmt.Errorf("Forgejo multi-file response did not include a full immutable commit id: %q", commit)
	}
	return len(operations), commit, nil
}

func (c *Client) putRepositoryFile(ctx context.Context, organization, repository, filePath string, content []byte, message string) (bool, error) {
	return c.putRepositoryFileOnBranch(ctx, organization, repository, "main", filePath, content, message)
}

func (c *Client) putRepositoryFileOnBranch(ctx context.Context, organization, repository, branch, filePath string, content []byte, message string) (bool, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents/" + strings.Join(escapePathSegments(filePath), "/")
	var existing struct {
		SHA     string `json:"sha"`
		Content string `json:"content"`
	}
	err := c.forgejoJSON(ctx, http.MethodGet, endpoint+"?ref="+url.QueryEscape(branch), nil, &existing, http.StatusOK)
	encoded := base64.StdEncoding.EncodeToString(content)
	if err == nil {
		current, decodeErr := base64.StdEncoding.DecodeString(strings.ReplaceAll(existing.Content, "\n", ""))
		if decodeErr == nil && bytes.Equal(current, content) {
			return false, nil
		}
		input := map[string]any{"message": message, "content": encoded, "branch": branch, "sha": existing.SHA}
		var output map[string]any
		return true, c.forgejoJSON(ctx, http.MethodPut, endpoint, input, &output, http.StatusOK)
	}
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusNotFound {
		return false, err
	}
	input := map[string]any{"message": message, "content": encoded, "branch": branch}
	var output map[string]any
	return true, c.forgejoJSON(ctx, http.MethodPost, endpoint, input, &output, http.StatusCreated)
}

func (c *Client) branchCommit(ctx context.Context, organization, repository, branch string) (string, error) {
	var payload struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/branches/" + url.PathEscape(branch)
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &payload, http.StatusOK); err != nil {
		return "", err
	}
	commit := strings.TrimSpace(payload.Commit.ID)
	if commit == "" {
		return "", errors.New("Forgejo branch response did not include commit id")
	}
	if !gitops.IsFullCommitSHA(commit) {
		return "", fmt.Errorf("Forgejo branch response did not include a full immutable commit id: %q", commit)
	}
	return commit, nil
}

func (c *Client) InspectGitRevision(ctx context.Context, organization, repository, branch, baseCommitSHA, expectedFingerprint string) (GitRevisionSnapshot, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return GitRevisionSnapshot{}, errors.New("Forgejo-compatible Git integration is not configured")
	}
	organization = strings.TrimSpace(organization)
	repository = strings.TrimSpace(repository)
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	if !safeName(organization) || !safeName(repository) || !safeName(branch) {
		return GitRevisionSnapshot{}, errors.New("organization, repository and branch contain unsupported characters")
	}
	commit, err := c.branchCommit(ctx, organization, repository, branch)
	if err != nil {
		return GitRevisionSnapshot{}, err
	}
	files := map[string]string{}
	for _, filePath := range []string{".platform/revision.json", ".platform/revision.sig", ".platform/public-key.pem"} {
		content, e := c.repositoryFile(ctx, organization, repository, filePath, branch)
		if e != nil {
			return GitRevisionSnapshot{}, e
		}
		files[filePath] = string(content)
	}
	descriptor, verifyErr := verifyRevisionFiles(files, expectedFingerprint)
	changed := []string{}
	if strings.TrimSpace(baseCommitSHA) != "" && baseCommitSHA != commit {
		changed, err = c.compareFiles(ctx, organization, repository, baseCommitSHA, commit)
		if err != nil {
			return GitRevisionSnapshot{}, fmt.Errorf("compare Git revisions %s...%s: %w", baseCommitSHA, commit, err)
		}
	}
	return GitRevisionSnapshot{Organization: strings.ToLower(organization), Repository: strings.ToLower(repository), Branch: branch, RevisionID: descriptor.Metadata.ID, Digest: descriptor.Integrity.Digest, CommitSHA: commit, PublicKeyFingerprint: descriptor.Integrity.PublicKeyFingerprint, Trusted: verifyErr == nil, ChangedFiles: changed}, nil
}

func verifyRevisionFiles(files map[string]string, expectedFingerprint string) (revisionDescriptor, error) {
	var descriptor revisionDescriptor
	raw := []byte(files[".platform/revision.json"])
	if len(raw) == 0 {
		return descriptor, errors.New(".platform/revision.json is missing")
	}
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return descriptor, err
	}
	canonical, err := json.Marshal(descriptor.Spec)
	if err != nil {
		return descriptor, err
	}
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if descriptor.Integrity.Digest != digest {
		return descriptor, errors.New("revision descriptor digest mismatch")
	}
	expectedID := "revision-" + hex.EncodeToString(sum[:8])
	if strings.TrimSpace(descriptor.Metadata.ID) != expectedID {
		return descriptor, errors.New("revision descriptor id is not deterministically bound to the signed spec")
	}
	block, _ := pem.Decode([]byte(files[".platform/public-key.pem"]))
	if block == nil || len(block.Bytes) != ed25519.PublicKeySize {
		return descriptor, errors.New("revision public key is invalid")
	}
	pub := ed25519.PublicKey(block.Bytes)
	fpSum := sha256.Sum256(pub)
	fingerprint := "sha256:" + hex.EncodeToString(fpSum[:])
	if descriptor.Integrity.PublicKeyFingerprint != fingerprint {
		return descriptor, errors.New("revision public key fingerprint mismatch")
	}
	if strings.TrimSpace(expectedFingerprint) != "" && fingerprint != strings.TrimSpace(expectedFingerprint) {
		return descriptor, errors.New("revision signing fingerprint differs from platform-published base")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(descriptor.Integrity.Signature))
	if err != nil || !ed25519.Verify(pub, sum[:], sig) {
		return descriptor, errors.New("revision signature verification failed")
	}
	sigFile := strings.TrimSpace(files[".platform/revision.sig"])
	if sigFile == "" {
		return descriptor, errors.New("revision signature file is missing")
	}
	if sigFile != strings.TrimSpace(descriptor.Integrity.Signature) {
		return descriptor, errors.New("revision signature file does not match descriptor")
	}
	return descriptor, nil
}

func (c *Client) repositoryFile(ctx context.Context, organization, repository, filePath, ref string) ([]byte, error) {
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents/" + strings.Join(escapePathSegments(filePath), "/") + "?ref=" + url.QueryEscape(ref)
	var payload struct {
		Content string `json:"content"`
	}
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &payload, http.StatusOK); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
}

func (c *Client) compareFiles(ctx context.Context, organization, repository, base, head string) ([]string, error) {
	var payload struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/compare/" + url.PathEscape(base) + "..." + url.PathEscape(head)
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &payload, http.StatusOK); err != nil {
		return nil, err
	}
	out := []string{}
	seen := map[string]bool{}
	for _, f := range payload.Files {
		v := strings.TrimSpace(f.Filename)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

func escapePathSegments(value string) []string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return parts
}

type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("Forgejo API returned HTTP %d: %s", e.Status, e.Body)
}

func ResolveSecretReference(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(ref, "env://"):
		name := strings.Trim(strings.TrimPrefix(ref, "env://"), "/")
		if name == "" {
			return "", errors.New("env secret reference is missing a variable name")
		}
		value, ok := os.LookupEnv(name)
		if !ok || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("secret reference %s is unavailable", ref)
		}
		return value, nil
	case strings.HasPrefix(ref, "file:///"):
		pathName := strings.TrimPrefix(ref, "file://")
		raw, err := os.ReadFile(pathName)
		if err != nil {
			return "", fmt.Errorf("resolve secret reference %s: %w", ref, err)
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return "", fmt.Errorf("secret reference %s is empty", ref)
		}
		return value, nil
	default:
		return "", errors.New("git credential secretRef must use env:// or file://")
	}
}

func (c *Client) gitConnection(ctx context.Context) (GitConnection, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return GitConnection{}, errors.New("Git provider authority is not configured")
	}
	conn, err := c.config.GitConnectionResolver(ctx)
	if err != nil {
		return GitConnection{}, fmt.Errorf("resolve Git provider authority: %w", err)
	}
	conn.BaseURL = strings.TrimRight(strings.TrimSpace(conn.BaseURL), "/")
	if conn.BaseURL == "" || conn.CredentialID == "" || strings.TrimSpace(conn.Username) == "" || strings.TrimSpace(conn.SecretRef) == "" {
		return GitConnection{}, errors.New("Git provider authority is incomplete")
	}
	return conn, nil
}

func (c *Client) forgejoJSON(ctx context.Context, method, endpoint string, input any, output any, expected int) error {
	conn, err := c.gitConnection(ctx)
	if err != nil {
		return err
	}
	secret, err := ResolveSecretReference(conn.SecretRef)
	if err != nil {
		return err
	}
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, conn.BaseURL+path.Clean("/"+endpoint), body)
	if err != nil {
		return err
	}
	request.SetBasicAuth(conn.Username, secret)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != expected {
		return &httpStatusError{Status: response.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if output != nil && len(raw) > 0 {
		if err = json.Unmarshal(raw, output); err != nil {
			return err
		}
	}
	return nil
}

func safeName(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return value != ""
}

type ImageMirrorStatus struct {
	SourceReference string `json:"sourceReference"`
	MirrorReference string `json:"mirrorReference,omitempty"`
	Available       bool   `json:"available"`
	Error           string `json:"error,omitempty"`
}

func (c *Client) RegistryConfigured() bool {
	return c != nil && strings.TrimSpace(c.config.ZotURL) != ""
}

func (c *Client) MirrorReference(sourceReference string) (string, error) {
	if c == nil || strings.TrimSpace(c.config.ZotURL) == "" {
		return "", errors.New("managed zot integration is not configured")
	}
	client, err := imagebundle.NewRegistryClient(c.config.ZotURL)
	if err != nil {
		return "", err
	}
	return client.MirrorReference(sourceReference)
}

func (c *Client) CheckMirroredImage(ctx context.Context, sourceReference string) ImageMirrorStatus {
	status := ImageMirrorStatus{SourceReference: strings.TrimSpace(sourceReference)}
	if c == nil || strings.TrimSpace(c.config.ZotURL) == "" {
		status.Error = "managed zot integration is not configured"
		return status
	}
	client, err := imagebundle.NewRegistryClient(c.config.ZotURL)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	result, err := client.Verify(ctx, status.SourceReference)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.MirrorReference = result.MirrorReference
	status.Available = result.Verified
	if !result.Verified {
		status.Error = "digest is not present in the managed registry mirror"
	}
	return status
}
