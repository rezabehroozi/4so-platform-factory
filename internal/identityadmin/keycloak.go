package identityadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const workerActor = "system-identity-admin-worker"

// KeycloakClient is the only component allowed to turn an approved
// IdentityAdminJob into Keycloak Admin API calls. Credentials are loaded from
// a server-side file for each token acquisition and are never stored in product
// authority, audit payloads, MCP responses, or durable job state.
type KeycloakClient struct {
	BaseURL      string
	Realm        string
	AdminRealm   string
	AdminUser    string
	PasswordFile string
	HTTPClient   *http.Client
}

type identityProviderRepresentation struct {
	Alias          string            `json:"alias"`
	DisplayName    string            `json:"displayName,omitempty"`
	InternalID     string            `json:"internalId,omitempty"`
	ProviderID     string            `json:"providerId"`
	Enabled        bool              `json:"enabled"`
	OrganizationID string            `json:"organizationId,omitempty"`
	HideOnLogin    *bool             `json:"hideOnLogin,omitempty"`
	TrustEmail     *bool             `json:"trustEmail,omitempty"`
	Config         map[string]string `json:"config"`
}

type organizationRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Alias       string `json:"alias"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *KeycloakClient) normalize() error {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Realm = strings.TrimSpace(c.Realm)
	c.AdminRealm = strings.TrimSpace(c.AdminRealm)
	c.AdminUser = strings.TrimSpace(c.AdminUser)
	c.PasswordFile = strings.TrimSpace(c.PasswordFile)
	if c.Realm == "" {
		c.Realm = "platform"
	}
	if c.AdminRealm == "" {
		c.AdminRealm = "master"
	}
	if c.AdminUser == "" {
		c.AdminUser = "platform-admin"
	}
	if c.PasswordFile == "" {
		c.PasswordFile = "/run/secrets/platform/identity-admin-password"
	}
	if c.BaseURL == "" {
		return errors.New("Keycloak base URL is required")
	}
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return errors.New("Keycloak base URL must be an absolute http(s) URL without userinfo")
	}
	if !filepath.IsAbs(c.PasswordFile) {
		return errors.New("Keycloak admin password file must be an absolute path")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return nil
}

func (c *KeycloakClient) Validate() error {
	if err := c.normalize(); err != nil {
		return err
	}
	info, err := os.Stat(c.PasswordFile)
	if err != nil {
		return fmt.Errorf("Keycloak admin password file unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("Keycloak admin password path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("Keycloak admin password file must not be group/world-accessible (mode %04o)", info.Mode().Perm())
	}
	return nil
}

func (c *KeycloakClient) password() (string, error) {
	raw, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(raw))
	if password == "" || len(password) > 4096 {
		return "", errors.New("Keycloak admin password is empty or invalid")
	}
	return password, nil
}

func (c *KeycloakClient) token(ctx context.Context) (string, error) {
	if err := c.normalize(); err != nil {
		return "", err
	}
	password, err := c.password()
	if err != nil {
		return "", fmt.Errorf("read Keycloak admin credential: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", c.AdminUser)
	form.Set("password", password)
	endpoint := c.BaseURL + "/realms/" + url.PathEscape(c.AdminRealm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Keycloak token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("Keycloak token request returned HTTP %d", resp.StatusCode)
	}
	var out tokenResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err = dec.Decode(&out); err != nil || strings.TrimSpace(out.AccessToken) == "" {
		return "", errors.New("Keycloak token response is invalid")
	}
	return out.AccessToken, nil
}

func (c *KeycloakClient) doJSON(ctx context.Context, method, path string, body any, expected ...int) (*http.Response, []byte, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, nil, err
	}
	var reader io.Reader
	if body != nil {
		raw, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, nil, marshalErr
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	resp.Body.Close()
	if readErr != nil {
		return resp, nil, readErr
	}
	for _, status := range expected {
		if resp.StatusCode == status {
			return resp, raw, nil
		}
	}
	return resp, raw, fmt.Errorf("Keycloak Admin API %s %s returned HTTP %d", method, path, resp.StatusCode)
}

func keycloakOrganizationAlias(platformOrganizationID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(platformOrganizationID)))
	return "4so-" + hex.EncodeToString(sum[:])[:20]
}

func (c *KeycloakClient) ensureOrganization(ctx context.Context, organization controlplane.Organization) (string, error) {
	alias := keycloakOrganizationAlias(organization.ID)
	path := "/admin/realms/" + url.PathEscape(c.Realm) + "/organizations?search=" + url.QueryEscape(alias) + "&exact=true"
	_, raw, err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var values []organizationRepresentation
	if err = json.Unmarshal(raw, &values); err != nil {
		return "", errors.New("decode Keycloak organization lookup")
	}
	for _, item := range values {
		if item.Alias == alias && item.ID != "" {
			return item.ID, nil
		}
	}
	name := strings.TrimSpace(organization.DisplayName)
	if name == "" {
		name = strings.TrimSpace(organization.Name)
	}
	if name == "" {
		name = "4SO Organization"
	}
	rep := organizationRepresentation{Name: name, Alias: alias, Enabled: true, Description: "Managed by 4SO Platform Factory organization " + organization.ID}
	resp, _, err := c.doJSON(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(c.Realm)+"/organizations", rep, http.StatusCreated)
	if err != nil {
		// HA replicas can race on the exact same alias. Re-read after a 409.
		if resp == nil || resp.StatusCode != http.StatusConflict {
			return "", err
		}
	}
	_, raw, err = c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	values = nil
	if err = json.Unmarshal(raw, &values); err != nil {
		return "", errors.New("decode Keycloak organization after create")
	}
	for _, item := range values {
		if item.Alias == alias && item.ID != "" {
			return item.ID, nil
		}
	}
	return "", errors.New("Keycloak organization create was not observable")
}

func desiredIdentityProvider(b controlplane.SAMLBroker) identityProviderRepresentation {
	hide := true
	trust := false
	config := map[string]string{
		"entityId":                b.EntityID,
		"idpEntityId":             b.EntityID,
		"singleSignOnServiceUrl":  b.SingleSignOnServiceURL,
		"signingCertificate":      b.SigningCertificate,
		"nameIDPolicyFormat":      b.NameIDPolicyFormat,
		"wantAuthnRequestsSigned": fmt.Sprintf("%t", b.WantAuthnRequestsSigned),
		"validateSignature":       "true",
		"wantAssertionsSigned":    "true",
		"postBindingAuthnRequest": "true",
		"postBindingResponse":     "true",
	}
	if b.SingleLogoutServiceURL != "" {
		config["singleLogoutServiceUrl"] = b.SingleLogoutServiceURL
	}
	return identityProviderRepresentation{Alias: b.KeycloakAlias, DisplayName: b.DisplayName, ProviderID: "saml", Enabled: b.Enabled, HideOnLogin: &hide, TrustEmail: &trust, Config: config}
}

func observedBrokerDigest(b controlplane.SAMLBroker, rep identityProviderRepresentation) (string, error) {
	if rep.Alias != b.KeycloakAlias || rep.ProviderID != "saml" {
		return "", errors.New("observed Keycloak identity provider identity differs from desired broker")
	}
	obs := b
	obs.DisplayName = strings.TrimSpace(rep.DisplayName)
	obs.Enabled = rep.Enabled
	obs.EntityID = strings.TrimSpace(rep.Config["entityId"])
	if obs.EntityID == "" {
		obs.EntityID = strings.TrimSpace(rep.Config["idpEntityId"])
	}
	obs.SingleSignOnServiceURL = strings.TrimSpace(rep.Config["singleSignOnServiceUrl"])
	obs.SingleLogoutServiceURL = strings.TrimSpace(rep.Config["singleLogoutServiceUrl"])
	obs.SigningCertificate = strings.TrimSpace(rep.Config["signingCertificate"])
	obs.NameIDPolicyFormat = strings.TrimSpace(rep.Config["nameIDPolicyFormat"])
	obs.WantAuthnRequestsSigned = strings.EqualFold(strings.TrimSpace(rep.Config["wantAuthnRequestsSigned"]), "true")
	normalized, err := controlplane.NormalizeSAMLBroker(obs)
	if err != nil {
		return "", errors.New("observed Keycloak SAML broker is invalid")
	}
	return controlplane.SAMLBrokerDesiredDigest(normalized), nil
}

func deletedObservedDigest(b controlplane.SAMLBroker, keycloakOrgID string) string {
	raw, _ := json.Marshal(struct {
		Authority, State, BrokerID, Alias, OrganizationID, KeycloakOrganizationID string
	}{controlplane.KeycloakSAMLBrokerAuthority, "DELETED", b.ID, b.KeycloakAlias, b.OrganizationID, keycloakOrgID})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c *KeycloakClient) getIdentityProvider(ctx context.Context, alias string) (identityProviderRepresentation, bool, error) {
	path := "/admin/realms/" + url.PathEscape(c.Realm) + "/identity-provider/instances/" + url.PathEscape(alias)
	resp, raw, err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return identityProviderRepresentation{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return identityProviderRepresentation{}, false, nil
	}
	var rep identityProviderRepresentation
	if err = json.Unmarshal(raw, &rep); err != nil {
		return rep, false, errors.New("decode Keycloak identity provider")
	}
	return rep, true, nil
}

func (c *KeycloakClient) organizationHasProvider(ctx context.Context, organizationID, alias string) (bool, identityProviderRepresentation, error) {
	path := "/admin/realms/" + url.PathEscape(c.Realm) + "/organizations/" + url.PathEscape(organizationID) + "/identity-providers/" + url.PathEscape(alias)
	resp, raw, err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return false, identityProviderRepresentation{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, identityProviderRepresentation{}, nil
	}
	var rep identityProviderRepresentation
	if err = json.Unmarshal(raw, &rep); err != nil {
		return false, rep, errors.New("decode organization-linked identity provider")
	}
	return true, rep, nil
}

func (c *KeycloakClient) ReconcileSAML(ctx context.Context, organization controlplane.Organization, broker controlplane.SAMLBroker) (string, error) {
	if err := c.normalize(); err != nil {
		return "", err
	}
	orgID, err := c.ensureOrganization(ctx, organization)
	if err != nil {
		return "", fmt.Errorf("ensure Keycloak organization: %w", err)
	}
	desired := desiredIdentityProvider(broker)
	current, exists, err := c.getIdentityProvider(ctx, broker.KeycloakAlias)
	if err != nil {
		return "", err
	}
	instancePath := "/admin/realms/" + url.PathEscape(c.Realm) + "/identity-provider/instances"
	if exists {
		if current.ProviderID != "saml" {
			return "", errors.New("Keycloak alias already belongs to a non-SAML identity provider")
		}
		if _, _, err = c.doJSON(ctx, http.MethodPut, instancePath+"/"+url.PathEscape(broker.KeycloakAlias), desired, http.StatusNoContent, http.StatusOK); err != nil {
			return "", fmt.Errorf("update Keycloak SAML identity provider: %w", err)
		}
	} else {
		if _, _, err = c.doJSON(ctx, http.MethodPost, instancePath, desired, http.StatusCreated, http.StatusOK); err != nil {
			return "", fmt.Errorf("create Keycloak SAML identity provider: %w", err)
		}
	}
	linked, _, err := c.organizationHasProvider(ctx, orgID, broker.KeycloakAlias)
	if err != nil {
		return "", err
	}
	if !linked {
		linkPath := "/admin/realms/" + url.PathEscape(c.Realm) + "/organizations/" + url.PathEscape(orgID) + "/identity-providers"
		// The Keycloak organization endpoint accepts a JSON string containing
		// the IdP alias or id. This keeps the provider realm-owned but limits
		// its organization visibility/membership semantics.
		if _, _, err = c.doJSON(ctx, http.MethodPost, linkPath, broker.KeycloakAlias, http.StatusNoContent); err != nil {
			return "", fmt.Errorf("link SAML identity provider to Keycloak organization: %w", err)
		}
	}
	linked, observed, err := c.organizationHasProvider(ctx, orgID, broker.KeycloakAlias)
	if err != nil || !linked {
		if err == nil {
			err = errors.New("Keycloak SAML identity provider link not observable")
		}
		return "", err
	}
	digest, err := observedBrokerDigest(broker, observed)
	if err != nil {
		return "", err
	}
	if digest != broker.DesiredDigest {
		return "", fmt.Errorf("Keycloak SAML read-back digest mismatch: desired=%s observed=%s", broker.DesiredDigest, digest)
	}
	return digest, nil
}

func (c *KeycloakClient) DeleteSAML(ctx context.Context, organization controlplane.Organization, broker controlplane.SAMLBroker) (string, error) {
	if err := c.normalize(); err != nil {
		return "", err
	}
	orgID, err := c.ensureOrganization(ctx, organization)
	if err != nil {
		return "", fmt.Errorf("resolve Keycloak organization: %w", err)
	}
	linked, _, err := c.organizationHasProvider(ctx, orgID, broker.KeycloakAlias)
	if err != nil {
		return "", err
	}
	if linked {
		unlinkPath := "/admin/realms/" + url.PathEscape(c.Realm) + "/organizations/" + url.PathEscape(orgID) + "/identity-providers/" + url.PathEscape(broker.KeycloakAlias)
		if _, _, err = c.doJSON(ctx, http.MethodDelete, unlinkPath, nil, http.StatusNoContent, http.StatusNotFound); err != nil {
			return "", fmt.Errorf("unlink Keycloak SAML identity provider: %w", err)
		}
	}
	instancePath := "/admin/realms/" + url.PathEscape(c.Realm) + "/identity-provider/instances/" + url.PathEscape(broker.KeycloakAlias)
	if _, _, err = c.doJSON(ctx, http.MethodDelete, instancePath, nil, http.StatusNoContent, http.StatusNotFound); err != nil {
		return "", fmt.Errorf("delete Keycloak SAML identity provider: %w", err)
	}
	if _, exists, err := c.getIdentityProvider(ctx, broker.KeycloakAlias); err != nil {
		return "", err
	} else if exists {
		return "", errors.New("deleted Keycloak SAML identity provider remains observable")
	}
	return deletedObservedDigest(broker, orgID), nil
}

type Store interface {
	GetOrganization(context.Context, string) (controlplane.Organization, error)
	ClaimIdentityAdminTask(context.Context, string, time.Duration, time.Time) (controlplane.IdentityAdminTask, error)
	CompleteIdentityAdminTask(context.Context, string, string, int64, string, string) (controlplane.IdentityAdminJob, controlplane.SAMLBroker, error)
	FailIdentityAdminTask(context.Context, string, string, int64, string, string) (controlplane.IdentityAdminJob, controlplane.SAMLBroker, error)
}

type Reconciler interface {
	ReconcileSAML(context.Context, controlplane.Organization, controlplane.SAMLBroker) (string, error)
	DeleteSAML(context.Context, controlplane.Organization, controlplane.SAMLBroker) (string, error)
}

type Worker struct {
	Store        Store
	Reconciler   Reconciler
	Logger       *slog.Logger
	Owner        string
	Lease        time.Duration
	PollInterval time.Duration
	Now          func() time.Time
}

func (w *Worker) normalize() error {
	if w.Store == nil || w.Reconciler == nil {
		return errors.New("identity admin worker store and reconciler are required")
	}
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	w.Owner = strings.TrimSpace(w.Owner)
	if w.Owner == "" {
		w.Owner = "identity-admin-worker"
	}
	if w.Lease <= 0 {
		w.Lease = 30 * time.Second
	}
	if w.PollInterval <= 0 {
		w.PollInterval = 2 * time.Second
	}
	if w.Now == nil {
		w.Now = func() time.Time { return time.Now().UTC() }
	}
	return nil
}

func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if err := w.normalize(); err != nil {
		return false, err
	}
	task, err := w.Store.ClaimIdentityAdminTask(ctx, w.Owner, w.Lease, w.Now())
	if errors.Is(err, controlplane.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	organization, err := w.Store.GetOrganization(ctx, task.Broker.OrganizationID)
	if err != nil {
		_, _, _ = w.Store.FailIdentityAdminTask(ctx, task.Job.ID, w.Owner, task.FenceToken, "organization authority unavailable", workerActor)
		return true, err
	}
	var observed string
	switch task.Job.Kind {
	case controlplane.IdentityAdminUpsertSAML:
		observed, err = w.Reconciler.ReconcileSAML(ctx, organization, task.Broker)
	case controlplane.IdentityAdminDeleteSAML:
		observed, err = w.Reconciler.DeleteSAML(ctx, organization, task.Broker)
	default:
		err = fmt.Errorf("unsupported identity admin job kind %q", task.Job.Kind)
	}
	if err != nil {
		// Do not persist remote response bodies or credentials in LastError.
		message := "Keycloak SAML reconciliation failed"
		if strings.Contains(err.Error(), "digest mismatch") {
			message = "Keycloak SAML read-back verification failed"
		}
		_, _, failErr := w.Store.FailIdentityAdminTask(ctx, task.Job.ID, w.Owner, task.FenceToken, message, workerActor)
		if failErr != nil {
			return true, errors.Join(err, failErr)
		}
		return true, err
	}
	_, _, err = w.Store.CompleteIdentityAdminTask(ctx, task.Job.ID, w.Owner, task.FenceToken, observed, workerActor)
	return true, err
}

func (w *Worker) Run(ctx context.Context) {
	if err := w.normalize(); err != nil {
		w.Logger.Error("identity admin worker configuration invalid", "error", err)
		return
	}
	run := func() {
		processed, err := w.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("identity admin reconciliation cycle incomplete", "error", err)
		} else if processed {
			w.Logger.Info("identity admin reconciliation completed")
		}
	}
	run()
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
