package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type BearerAuthenticator func(context.Context, string) (Principal, error)

type GroupMappingResult struct {
	Roles             []string
	OrganizationRoles map[string]string
	ProjectRoles      map[string]string
	MappingDigest     string
}

type GroupMapper func(context.Context, []string) (GroupMappingResult, error)

type SecurityAuditRecord struct {
	Category, Decision, ActorID, Authentication, Method, Path, ReasonCode, RequestID string
	StatusCode                                                                       int
	ScopeType, ScopeID, EffectiveRole, MappingDigest                                 string
}

type AuditSink func(context.Context, SecurityAuditRecord) error

type Config struct {
	Enabled             bool
	Issuer              string
	InternalBase        string
	ClientID            string
	RedirectURL         string
	SessionSecret       string
	BootstrapToken      string
	LocalDevelopment    bool
	CookieSecure        bool
	BearerAuthenticator BearerAuthenticator
	GroupMapper         GroupMapper
	GroupPropagationTTL time.Duration
	AuditSink           AuditSink
}

type Principal struct {
	Subject           string            `json:"sub"`
	Email             string            `json:"email,omitempty"`
	Name              string            `json:"name,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
	Expires           int64             `json:"exp"`
	Authentication    string            `json:"authentication,omitempty"`
	ServiceAccountID  string            `json:"serviceAccountId,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	OrganizationID    string            `json:"organizationId,omitempty"`
	ProjectID         string            `json:"projectId,omitempty"`
	Permissions       []string          `json:"permissions,omitempty"`
	Groups            []string          `json:"groups,omitempty"`
	MappingDigest     string            `json:"mappingDigest,omitempty"`
	MappedAt          int64             `json:"mappedAt,omitempty"`
	OrganizationRoles map[string]string `json:"organizationRoles,omitempty"`
	ProjectRoles      map[string]string `json:"projectRoles,omitempty"`
}

type statePayload struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	Expires      int64  `json:"exp"`
}

type Manager struct {
	config  Config
	http    *http.Client
	entropy io.Reader
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	keyExp  time.Time
}

func New(config Config) (*Manager, error) {
	config.Issuer = strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	config.InternalBase = strings.TrimRight(strings.TrimSpace(config.InternalBase), "/")
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.RedirectURL = strings.TrimSpace(config.RedirectURL)
	if !config.Enabled {
		return &Manager{config: config, http: &http.Client{Timeout: 10 * time.Second}, entropy: rand.Reader}, nil
	}
	for label, raw := range map[string]string{"OIDC issuer": config.Issuer, "OIDC internal base": config.InternalBase, "OIDC redirect URL": config.RedirectURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("%s must be an absolute URL", label)
		}
	}
	if config.Issuer == "" || config.InternalBase == "" || config.ClientID == "" || config.RedirectURL == "" {
		return nil, errors.New("OIDC issuer, internal base, client ID and redirect URL are required")
	}
	if len(config.SessionSecret) < 32 {
		return nil, errors.New("OIDC session secret must be at least 32 characters")
	}
	if config.GroupMapper != nil && config.GroupPropagationTTL <= 0 {
		config.GroupPropagationTTL = 5 * time.Minute
	}
	return &Manager{config: config, http: &http.Client{Timeout: 10 * time.Second}, entropy: rand.Reader}, nil
}

func (m *Manager) Enabled() bool { return m != nil && m.config.Enabled }

func (m *Manager) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", m.login)
	mux.HandleFunc("GET /auth/callback", m.callback)
	mux.HandleFunc("POST /auth/logout", m.logout)
	mux.HandleFunc("GET /auth/session", m.session)
}

func (m *Manager) apiTokenPrincipal(r *http.Request) (Principal, bool, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return Principal{}, false, nil
	}
	raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if !strings.HasPrefix(raw, "pft.") {
		return Principal{}, false, nil
	}
	if m.config.BearerAuthenticator == nil {
		return Principal{}, true, errors.New("API token authentication is unavailable")
	}
	principal, err := m.config.BearerAuthenticator(r.Context(), raw)
	return principal, true, err
}

func hasPermission(principal Principal, wanted string) bool {
	for _, permission := range principal.Permissions {
		if strings.TrimSpace(permission) == wanted {
			return true
		}
	}
	return false
}

func (m *Manager) auditRequest(r *http.Request, principal Principal, category, decision, reason string, status int) error {
	if m.config.AuditSink == nil {
		return nil
	}
	return m.config.AuditSink(r.Context(), SecurityAuditRecord{Category: category, Decision: decision, ActorID: principal.Subject, Authentication: principal.Authentication, Method: r.Method, Path: r.URL.Path, ReasonCode: reason, RequestID: r.Header.Get("X-Request-ID"), StatusCode: status, EffectiveRole: CanonicalRole(principal.Roles), MappingDigest: principal.MappingDigest})
}
func (m *Manager) authorizePrincipalForRequest(w http.ResponseWriter, r *http.Request, principal Principal) bool {
	deny := func(code, message string) bool {
		if err := m.auditRequest(r, principal, "AUTHORIZATION", "DENY", code, http.StatusForbidden); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authorization deny audit could not be durably recorded"}})
			return false
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": code, "message": message}})
		return false
	}
	if CanonicalRole(principal.Roles) == "" {
		return deny("PRODUCT_ROLE_REQUIRED", "the authenticated identity is not mapped to a product role")
	}
	if principal.Authentication == "api-token" && requiresOperatorRole(r) && !hasPermission(principal, "operate") {
		return deny("TOKEN_PERMISSION_REQUIRED", "this API token does not have operate permission")
	}
	if requiresOperatorRole(r) && !HasAnyRole(principal, "platform-admin", "platform-operator") {
		return deny("OPERATOR_ROLE_REQUIRED", "platform-operator or platform-admin is required for this action")
	}
	if err := m.auditRequest(r, principal, "AUTHORIZATION", "ALLOW", "PRODUCT_RBAC_ALLOWED", http.StatusOK); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authorization audit could not be durably recorded"}})
		return false
	}
	return true
}

func ensureRequestID(r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Request-ID")) == "" {
		if id, err := randomToken(12); err == nil {
			r.Header.Set("X-Request-ID", "auth-"+id)
		}
	}
}

func (m *Manager) RequireAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ensureRequestID(r)
		if m.validBootstrap(r) {
			principal := Principal{Subject: "bootstrap-installer", Roles: []string{"platform-admin"}, Expires: time.Now().Add(5 * time.Minute).Unix(), Authentication: "bootstrap"}
			if err := m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "BOOTSTRAP_TOKEN_ACCEPTED", http.StatusOK); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication audit could not be durably recorded"}})
				return
			}
			applyPrincipalHeaders(r, principal)
			if !m.authorizePrincipalForRequest(w, r, principal) {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
			return
		}
		if principal, attempted, err := m.apiTokenPrincipal(r); attempted {
			if err != nil {
				if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "api-token"}, "AUTHENTICATION", "DENY", "API_TOKEN_REJECTED", http.StatusUnauthorized); auditErr != nil {
					writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication deny audit could not be durably recorded"}})
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "API_TOKEN_REJECTED", "message": "API token is invalid, expired or revoked"}})
				return
			}
			if err := m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "API_TOKEN_ACCEPTED", http.StatusOK); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication audit could not be durably recorded"}})
				return
			}
			applyPrincipalHeaders(r, principal)
			if !m.authorizePrincipalForRequest(w, r, principal) {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
			return
		}
		if !m.Enabled() {
			if !m.config.LocalDevelopment {
				if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "disabled"}, "AUTHENTICATION", "DENY", "IDENTITY_AUTHORITY_REQUIRED", http.StatusUnauthorized); auditErr != nil {
					writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication deny audit could not be durably recorded"}})
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTHENTICATION_REQUIRED", "message": "OIDC or explicit loopback development mode is required"}})
				return
			}
			if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
				if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "local"}, "AUTHENTICATION", "DENY", "UNSUPPORTED_AUTHORIZATION_CREDENTIAL", http.StatusUnauthorized); auditErr != nil {
					writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication deny audit could not be durably recorded"}})
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTHENTICATION_REQUIRED", "message": "unsupported authorization credential"}})
				return
			}
			principal := Principal{Subject: "local-development", Roles: []string{"platform-admin"}, Expires: time.Now().Add(time.Hour).Unix(), Authentication: "local"}
			if err := m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "LOCAL_DEVELOPMENT", http.StatusOK); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication audit could not be durably recorded"}})
				return
			}
			applyPrincipalHeaders(r, principal)
			if !m.authorizePrincipalForRequest(w, r, principal) {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
			return
		}
		principal, err := m.authenticate(r)
		if err != nil {
			if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "oidc"}, "AUTHENTICATION", "DENY", "OIDC_AUTHENTICATION_REJECTED", http.StatusUnauthorized); auditErr != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication deny audit could not be durably recorded"}})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTHENTICATION_REQUIRED", "message": "sign in through the managed identity service"}})
			return
		}
		principal.Authentication = "oidc"
		if err := m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "OIDC_AUTHENTICATED", http.StatusOK); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "authentication audit could not be durably recorded"}})
			return
		}
		applyPrincipalHeaders(r, principal)
		if !m.authorizePrincipalForRequest(w, r, principal) {
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func applyPrincipalHeaders(r *http.Request, principal Principal) {
	r.Header.Set("X-Actor-ID", strings.TrimSpace(principal.Subject))
	r.Header.Del("X-Actor-Role")
	if role := CanonicalRole(principal.Roles); role != "" {
		r.Header.Set("X-Actor-Role", role)
	}
}

func requiresOperatorRole(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	// These POST endpoints are pure validation/planning operations and do not
	// mutate durable authority. Viewers may use them without gaining write access.
	switch r.URL.Path {
	case "/api/v1/blueprints/validate", "/api/v1/blueprints/authoring-roundtrip", "/api/v1/blueprints/resolve", "/api/v1/compatibility/evaluate", "/api/v1/plans", "/api/v1/installations/plans", "/api/v1/blueprint-releases/compare", "/api/v1/runtime-closure-reports/verify", "/api/v1/support-bundles", "/api/v1/ai/diagnose", "/mcp":
		return false
	default:
		return true
	}
}

func CanonicalRole(roles []string) string {
	for _, wanted := range []string{"platform-admin", "platform-operator", "platform-viewer"} {
		for _, role := range roles {
			if strings.TrimSpace(role) == wanted {
				return wanted
			}
		}
	}
	return ""
}

func HasAnyRole(principal Principal, roles ...string) bool {
	allowed := map[string]bool{}
	for _, role := range roles {
		allowed[strings.TrimSpace(role)] = true
	}
	for _, role := range principal.Roles {
		if allowed[strings.TrimSpace(role)] {
			return true
		}
	}
	return false
}

func (m *Manager) RequirePage(next http.Handler) http.Handler {
	if !m.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			if _, err := m.authenticate(r); err != nil {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type principalKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func (m *Manager) login(w http.ResponseWriter, r *http.Request) {
	if !m.Enabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	state, err := m.randomToken(24)
	if err != nil {
		http.Error(w, "OIDC login entropy unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := m.randomToken(24)
	if err != nil {
		http.Error(w, "OIDC login entropy unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, err := m.randomToken(48)
	if err != nil {
		http.Error(w, "OIDC login entropy unavailable", http.StatusServiceUnavailable)
		return
	}
	payload := statePayload{State: state, Nonce: nonce, CodeVerifier: verifier, Expires: time.Now().Add(10 * time.Minute).Unix()}
	signed, err := m.sign(payload)
	if err != nil {
		http.Error(w, "OIDC login state could not be created", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "platform_oidc_state", Value: signed, Path: "/auth", HttpOnly: true, Secure: m.config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	challenge := sha256.Sum256([]byte(verifier))
	params := url.Values{
		"client_id":             {m.config.ClientID},
		"redirect_uri":          {m.config.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, m.config.Issuer+"/protocol/openid-connect/auth?"+params.Encode(), http.StatusFound)
}

func (m *Manager) callback(w http.ResponseWriter, r *http.Request) {
	ensureRequestID(r)
	cookie, err := r.Cookie("platform_oidc_state")
	if err != nil {
		http.Error(w, "OIDC state cookie is missing", http.StatusBadRequest)
		return
	}
	var state statePayload
	if err = m.unsign(cookie.Value, &state); err != nil || state.Expires < time.Now().Unix() || subtle.ConstantTimeCompare([]byte(state.State), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "OIDC state is invalid or expired", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		http.Error(w, "OIDC authorization code is missing", http.StatusBadRequest)
		return
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {m.config.ClientID},
		"redirect_uri":  {m.config.RedirectURL},
		"code":          {code},
		"code_verifier": {state.CodeVerifier},
	}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, m.internalEndpoint("/protocol/openid-connect/token"), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := m.http.Do(request)
	if err != nil {
		http.Error(w, "OIDC token exchange failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	var token struct {
		IDToken string `json:"id_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&token) != nil || token.IDToken == "" {
		http.Error(w, "OIDC token exchange was rejected", http.StatusBadGateway)
		return
	}
	principal, err := m.verifyJWT(r.Context(), token.IDToken, state.Nonce)
	if err != nil {
		if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "oidc"}, "AUTHENTICATION", "DENY", "OIDC_CALLBACK_REJECTED", http.StatusUnauthorized); auditErr != nil {
			http.Error(w, "security audit unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "OIDC token verification failed", http.StatusUnauthorized)
		return
	}
	principal.Authentication = "oidc"
	if CanonicalRole(principal.Roles) == "" {
		if auditErr := m.auditRequest(r, principal, "AUTHENTICATION", "DENY", "OIDC_GROUP_MAPPING_REQUIRED", http.StatusForbidden); auditErr != nil {
			http.Error(w, "security audit unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "OIDC group is not mapped to a product role", http.StatusForbidden)
		return
	}
	if err = m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "OIDC_SESSION_CREATED", http.StatusFound); err != nil {
		http.Error(w, "security audit unavailable", http.StatusServiceUnavailable)
		return
	}
	session, err := m.sign(principal)
	if err != nil {
		http.Error(w, "OIDC session could not be created", http.StatusInternalServerError)
		return
	}
	maxAge := int(time.Until(time.Unix(principal.Expires, 0)).Seconds())
	if m.config.GroupMapper != nil && m.config.GroupPropagationTTL > 0 && maxAge > int(m.config.GroupPropagationTTL.Seconds()) {
		maxAge = int(m.config.GroupPropagationTTL.Seconds())
	}
	http.SetCookie(w, &http.Cookie{Name: "platform_session", Value: session, Path: "/", HttpOnly: true, Secure: m.config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	http.SetCookie(w, &http.Cookie{Name: "platform_oidc_state", Value: "", Path: "/auth", HttpOnly: true, Secure: m.config.CookieSecure, MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (m *Manager) logout(w http.ResponseWriter, r *http.Request) {
	ensureRequestID(r)
	principal, err := m.authenticate(r)
	if err != nil {
		principal = Principal{Subject: "anonymous", Authentication: "oidc"}
	}
	_ = m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "SESSION_LOGOUT", http.StatusOK)
	http.SetCookie(w, &http.Cookie{Name: "platform_session", Value: "", Path: "/", HttpOnly: true, Secure: m.config.CookieSecure, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed-out"})
}

func (m *Manager) session(w http.ResponseWriter, r *http.Request) {
	ensureRequestID(r)
	principal, err := m.authenticate(r)
	if err != nil {
		if auditErr := m.auditRequest(r, Principal{Subject: "anonymous", Authentication: "oidc"}, "AUTHENTICATION", "DENY", "SESSION_REJECTED", http.StatusUnauthorized); auditErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "session deny audit could not be durably recorded"}})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"status": "anonymous"})
		return
	}
	if principal.Authentication == "" {
		principal.Authentication = "oidc"
	}
	if err = m.auditRequest(r, principal, "AUTHENTICATION", "ALLOW", "SESSION_ACCEPTED", http.StatusOK); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "SECURITY_AUDIT_UNAVAILABLE", "message": "session audit could not be durably recorded"}})
		return
	}
	writeJSON(w, http.StatusOK, principal)
}

func (m *Manager) authenticate(r *http.Request) (Principal, error) {
	if !m.Enabled() {
		return Principal{Subject: "local-development", Roles: []string{"platform-admin"}, Expires: time.Now().Add(time.Hour).Unix(), Authentication: "local"}, nil
	}
	if header := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(header, "Bearer ") {
		return m.verifyJWT(r.Context(), strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")), "")
	}
	cookie, err := r.Cookie("platform_session")
	if err != nil {
		return Principal{}, err
	}
	var principal Principal
	if err = m.unsign(cookie.Value, &principal); err != nil || principal.Expires < time.Now().Unix() || principal.Subject == "" {
		return Principal{}, errors.New("session invalid")
	}
	if m.config.GroupMapper != nil {
		if principal.MappedAt == 0 || time.Since(time.Unix(principal.MappedAt, 0)) > m.config.GroupPropagationTTL {
			return Principal{}, errors.New("OIDC group propagation TTL expired")
		}
		mapped, mapErr := m.config.GroupMapper(r.Context(), principal.Groups)
		if mapErr != nil {
			return Principal{}, mapErr
		}
		principal.Roles = append([]string(nil), mapped.Roles...)
		principal.OrganizationRoles = mapped.OrganizationRoles
		principal.ProjectRoles = mapped.ProjectRoles
		principal.MappingDigest = mapped.MappingDigest
	}
	return principal, nil
}

func bootstrapRequestAllowed(r *http.Request) bool {
	path := r.URL.Path
	if r.Method == http.MethodGet {
		switch path {
		case "/api/v1/version", "/api/v1/identity/authority", "/api/v1/security-audit-events", "/api/v1/system-services", "/api/v1/organizations", "/api/v1/projects", "/api/v1/identity/group-mappings":
			return true
		}
	}
	if r.Method == http.MethodPost {
		if path == "/api/v1/organizations" || path == "/api/v1/projects" || path == "/api/v1/identity/group-mappings" || path == "/api/v1/system-services/git/repositories" || path == "/api/v1/system-services/git/revisions" {
			return true
		}
		if strings.HasPrefix(path, "/api/v1/identity/group-mappings/") && strings.HasSuffix(path, "/revoke") {
			return true
		}
	}
	return false
}

func (m *Manager) validBootstrap(r *http.Request) bool {
	if m.config.BootstrapToken == "" || !bootstrapRequestAllowed(r) {
		return false
	}
	provided := r.Header.Get("X-Platform-Bootstrap-Token")
	return len(provided) == len(m.config.BootstrapToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(m.config.BootstrapToken)) == 1
}

func (m *Manager) verifyJWT(ctx context.Context, raw, nonce string) (Principal, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Principal{}, errors.New("invalid JWT")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return Principal{}, errors.New("unsupported JWT header")
	}
	var claims struct {
		Subject  string          `json:"sub"`
		Email    string          `json:"email"`
		Name     string          `json:"name"`
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
		Nonce    string          `json:"nonce"`
		Groups   []string        `json:"groups"`
		Realm    struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Principal{}, err
	}
	if claims.Subject == "" || claims.Issuer != m.config.Issuer || claims.Expires < time.Now().Unix() || !audienceContains(claims.Audience, m.config.ClientID) {
		return Principal{}, errors.New("JWT claims rejected")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(nonce), []byte(claims.Nonce)) != 1 {
		return Principal{}, errors.New("JWT nonce mismatch")
	}
	keys, err := m.jwks(ctx)
	if err != nil {
		return Principal{}, err
	}
	key := keys[header.KeyID]
	if key == nil {
		m.invalidateKeys()
		keys, err = m.jwks(ctx)
		if err != nil {
			return Principal{}, err
		}
		key = keys[header.KeyID]
	}
	if key == nil {
		return Principal{}, errors.New("JWT signing key not found")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Principal{}, errors.New("JWT signature rejected")
	}
	principal := Principal{Subject: claims.Subject, Email: claims.Email, Name: claims.Name, Groups: append([]string(nil), claims.Groups...), Expires: claims.Expires, MappedAt: time.Now().Unix()}
	if m.config.GroupMapper != nil {
		mapped, mapErr := m.config.GroupMapper(ctx, claims.Groups)
		if mapErr != nil {
			return Principal{}, mapErr
		}
		principal.Roles = append([]string(nil), mapped.Roles...)
		principal.OrganizationRoles = mapped.OrganizationRoles
		principal.ProjectRoles = mapped.ProjectRoles
		principal.MappingDigest = mapped.MappingDigest
	} else {
		principal.Roles = append([]string(nil), claims.Realm.Roles...)
	}
	return principal, nil
}

func (m *Manager) jwks(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	m.mu.Lock()
	if len(m.keys) > 0 && time.Now().Before(m.keyExp) {
		copy := m.keys
		m.mu.Unlock()
		return copy, nil
	}
	m.mu.Unlock()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.internalEndpoint("/protocol/openid-connect/certs"), nil)
	response, err := m.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Keys []struct {
			KeyID string `json:"kid"`
			Type  string `json:"kty"`
			Use   string `json:"use"`
			N     string `json:"n"`
			E     string `json:"e"`
		} `json:"keys"`
	}
	if err = json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range payload.Keys {
		if item.Type != "RSA" || item.KeyID == "" {
			continue
		}
		nRaw, nErr := base64.RawURLEncoding.DecodeString(item.N)
		eRaw, eErr := base64.RawURLEncoding.DecodeString(item.E)
		if nErr != nil || eErr != nil || len(eRaw) == 0 {
			continue
		}
		e := 0
		for _, b := range eRaw {
			e = e<<8 + int(b)
		}
		keys[item.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(nRaw), E: e}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS did not contain RSA keys")
	}
	m.mu.Lock()
	m.keys, m.keyExp = keys, time.Now().Add(10*time.Minute)
	m.mu.Unlock()
	return keys, nil
}

func (m *Manager) invalidateKeys() {
	m.mu.Lock()
	m.keys, m.keyExp = nil, time.Time{}
	m.mu.Unlock()
}

func (m *Manager) internalEndpoint(suffix string) string {
	issuerURL, _ := url.Parse(m.config.Issuer)
	return m.config.InternalBase + strings.TrimRight(issuerURL.Path, "/") + suffix
}

func (m *Manager) sign(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(m.config.SessionSecret))
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m *Manager) unsign(value string, target any) error {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return errors.New("signed value malformed")
	}
	mac := hmac.New(sha256.New, []byte(m.config.SessionSecret))
	_, _ = mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, provided) {
		return errors.New("signed value rejected")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func decodeSegment(segment string, target any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == expected
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, item := range many {
		if item == expected {
			return true
		}
	}
	return false
}

func (m *Manager) randomToken(size int) (string, error) {
	reader := m.entropy
	if reader == nil {
		reader = rand.Reader
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
