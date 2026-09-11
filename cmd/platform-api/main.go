package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"platform.4so.io/factory/internal/buildinfo"
	"platform.4so.io/factory/internal/daemoncli"
	"strconv"
	"strings"
	"syscall"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/agentpki"
	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/api"
	"platform.4so.io/factory/internal/apitoken"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/bootmedia"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/identityadmin"
	"platform.4so.io/factory/internal/integrations"
	"platform.4so.io/factory/internal/managedinstall"
	"platform.4so.io/factory/internal/marketplace"
	"platform.4so.io/factory/internal/notification"
	"platform.4so.io/factory/internal/persistence"
	"platform.4so.io/factory/internal/pgdriver"
	"platform.4so.io/factory/internal/releaseartifact"
	"platform.4so.io/factory/webconsole"
)

var version = buildinfo.Version

const (
	postgresPingTimeout           = 10 * time.Second
	postgresMigrationTimeout      = 10 * time.Minute
	productionStoreStartupTimeout = postgresPingTimeout + postgresMigrationTimeout + 30*time.Second
	serverWriteTimeout            = 30 * time.Second
	httpShutdownTimeout           = 45 * time.Second
	securityAuditDrainTimeout     = 20 * time.Second
)

type postgresPoolConfig struct {
	MaxOpen int
	MaxIdle int
}

func postgresPoolConfigFromEnv(getenv func(string) string) (postgresPoolConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	parse := func(name string, def, min, max int) (int, error) {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			return def, nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v < min || v > max {
			return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
		}
		return v, nil
	}
	maxOpen, err := parse("PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS", 30, 2, 500)
	if err != nil {
		return postgresPoolConfig{}, err
	}
	maxIdle, err := parse("PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS", 10, 0, 500)
	if err != nil {
		return postgresPoolConfig{}, err
	}
	if maxIdle > maxOpen {
		return postgresPoolConfig{}, fmt.Errorf("PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS must not exceed PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS")
	}
	return postgresPoolConfig{MaxOpen: maxOpen, MaxIdle: maxIdle}, nil
}

func openStore(ctx context.Context, logger *slog.Logger) (controlplane.Store, func(), error) {
	statePath := os.Getenv("PLATFORM_FACTORY_STATE_FILE")
	postgresDSN := os.Getenv("PLATFORM_FACTORY_POSTGRES_DSN")
	if statePath != "" && postgresDSN != "" {
		return nil, func() {}, fmt.Errorf("PLATFORM_FACTORY_STATE_FILE and PLATFORM_FACTORY_POSTGRES_DSN are mutually exclusive")
	}
	if postgresDSN != "" {
		driverName := os.Getenv("PLATFORM_FACTORY_POSTGRES_DRIVER")
		if driverName == "" {
			if !pgdriver.Available() {
				return nil, func() {}, fmt.Errorf("PostgreSQL runtime is unavailable in this build: %s", pgdriver.Description())
			}
			driverName = pgdriver.Name()
		}
		db, err := sql.Open(driverName, postgresDSN)
		if err != nil {
			return nil, func() {}, fmt.Errorf("open PostgreSQL driver %q: %w; build the distribution with a registered, pinned PostgreSQL driver", driverName, err)
		}
		closeFn := func() { _ = db.Close() }
		poolConfig, configErr := postgresPoolConfigFromEnv(os.Getenv)
		if configErr != nil {
			closeFn()
			return nil, func() {}, configErr
		}
		db.SetConnMaxLifetime(30 * time.Minute)
		db.SetConnMaxIdleTime(5 * time.Minute)
		db.SetMaxOpenConns(poolConfig.MaxOpen)
		db.SetMaxIdleConns(poolConfig.MaxIdle)
		pingCtx, pingCancel := context.WithTimeout(ctx, postgresPingTimeout)
		err = db.PingContext(pingCtx)
		pingCancel()
		if err != nil {
			closeFn()
			return nil, func() {}, fmt.Errorf("connect PostgreSQL: %w", err)
		}
		// Migration startup has a separate budget from the connectivity probe.
		// HA replicas may legitimately wait for the migration advisory lock, and
		// production ALTER/INDEX work must not inherit the 10-second ping timeout.
		migrationMode, modeErr := persistence.ParseMigrationMode(os.Getenv("PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE"))
		if modeErr != nil {
			closeFn()
			return nil, func() {}, modeErr
		}
		quiescedApprovals, approvalErr := persistence.ParseQuiescedMigrationApprovals(os.Getenv("PLATFORM_FACTORY_POSTGRES_QUIESCED_MIGRATIONS"))
		if approvalErr != nil {
			closeFn()
			return nil, func() {}, approvalErr
		}
		migrationCtx, migrationCancel := context.WithTimeout(ctx, postgresMigrationTimeout)
		err = persistence.ApplyMigrationsWithCompatibility(migrationCtx, db, migrationMode, quiescedApprovals)
		migrationCancel()
		if err != nil {
			closeFn()
			return nil, func() {}, fmt.Errorf("apply PostgreSQL migrations: %w", err)
		}
		store, err := persistence.NewPostgresStore(db)
		if err != nil {
			closeFn()
			return nil, func() {}, err
		}
		logger.Info("PostgreSQL authority enabled", "driver", driverName)
		return store, closeFn, nil
	}
	if statePath != "" {
		fileStore, err := controlplane.OpenFileStore(statePath)
		if err != nil {
			return nil, func() {}, fmt.Errorf("open development state store: %w", err)
		}
		logger.Info("development durable state enabled", "path", statePath)
		return fileStore, func() {}, nil
	}
	return nil, func() {}, fmt.Errorf("durable control-plane authority is required: set PLATFORM_FACTORY_POSTGRES_DSN for runtime or PLATFORM_FACTORY_STATE_FILE for explicit development persistence")
}

func ensureInternalGitAuthority(ctx context.Context, store controlplane.Store) error {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_INTERNAL_GIT_URL")), "/")
	if baseURL == "" {
		return nil
	}
	username := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_INTERNAL_GIT_USERNAME"))
	if username == "" {
		return fmt.Errorf("PLATFORM_FACTORY_INTERNAL_GIT_USERNAME is required when internal Git is configured")
	}
	secretRef := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_INTERNAL_GIT_CREDENTIAL_REF"))
	if secretRef == "" {
		secretRef = "env://PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD"
	}
	providers, err := store.ListGitProviders(ctx)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		if provider.Default && provider.State == controlplane.GitProviderActive {
			return nil
		}
	}
	credentials, err := store.ListGitCredentials(ctx)
	if err != nil {
		return err
	}
	var credential controlplane.GitCredential
	for _, item := range credentials {
		if item.Name == "internal-forgejo" && item.State == controlplane.GitCredentialActive {
			credential = item
			break
		}
	}
	if credential.ID == "" {
		credential, err = store.CreateGitCredential(ctx, controlplane.GitCredential{Name: "internal-forgejo", Username: username, SecretRef: secretRef}, "system-bootstrap")
		if err != nil {
			return fmt.Errorf("bootstrap internal Git credential reference: %w", err)
		}
	}
	_, err = store.CreateGitProvider(ctx, controlplane.GitProvider{Name: "internal-forgejo", Kind: "FORGEJO", BaseURL: baseURL, CredentialID: credential.ID, Default: true}, "system-bootstrap")
	if err != nil {
		return fmt.Errorf("bootstrap internal Git provider authority: %w", err)
	}
	return nil
}

func gitConnectionResolver(store controlplane.Store) func(context.Context) (integrations.GitConnection, error) {
	return func(ctx context.Context) (integrations.GitConnection, error) {
		provider, credential, err := store.GetDefaultGitProvider(ctx)
		if err != nil {
			return integrations.GitConnection{}, err
		}
		return integrations.GitConnection{ProviderID: provider.ID, ProviderName: provider.Name, BaseURL: provider.BaseURL, CredentialID: credential.ID, Username: credential.Username, SecretRef: credential.SecretRef}, nil
	}
}

func loadCatalogSigningKey(localDevelopment bool) (ed25519.PrivateKey, string, error) {
	encoded := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_CATALOG_SIGNING_PRIVATE_KEY_B64"))
	if encoded != "" {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", fmt.Errorf("decode catalog signing key: %w", err)
		}
		switch len(raw) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(raw), "configured", nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(append([]byte(nil), raw...)), "configured", nil
		default:
			return nil, "", fmt.Errorf("catalog signing key must be a base64 Ed25519 seed or private key")
		}
	}
	if localDevelopment {
		seed := sha256.Sum256([]byte("4SO Platform Factory local-development catalog signer v1"))
		return ed25519.NewKeyFromSeed(seed[:]), "local-development", nil
	}
	return nil, "disabled", nil
}

func loadPublicCAPEM() (string, error) {
	encoded := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64"))
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode public CA PEM: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "", fmt.Errorf("public CA PEM is empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return "", fmt.Errorf("public CA PEM is invalid")
	}
	return string(raw), nil
}

type managedOKDProductionRuntime struct {
	executor *managedinstall.Executor
	media    *managedinstall.MediaStore
	poll     time.Duration
}

func decodeManagedOKDHMACKey() ([]byte, error) {
	encoded := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_HMAC_KEY_B64"))
	if encoded == "" {
		return nil, fmt.Errorf("PLATFORM_FACTORY_MANAGED_OKD_HMAC_KEY_B64 is required when Managed OKD worker is enabled")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode Managed OKD HMAC key: %w", err)
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("Managed OKD HMAC key must contain at least 32 bytes")
	}
	return raw, nil
}

func managedOKDDurationEnv(name string, fallback, max time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || (max > 0 && d > max) {
		return 0, fmt.Errorf("%s must be a positive duration not exceeding %s", name, max)
	}
	return d, nil
}

func configureManagedOKDProductionRuntime(apiServer *api.Server) (*managedOKDProductionRuntime, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_WORKER_ENABLED")), "true") {
		return nil, nil
	}
	key, err := decodeManagedOKDHMACKey()
	if err != nil {
		return nil, err
	}
	installTimeout, err := managedOKDDurationEnv("PLATFORM_FACTORY_MANAGED_OKD_INSTALL_TIMEOUT", 90*time.Minute, 6*time.Hour)
	if err != nil {
		return nil, err
	}
	commandTimeout, err := managedOKDDurationEnv("PLATFORM_FACTORY_MANAGED_OKD_COMMAND_TIMEOUT", 2*time.Minute, 30*time.Minute)
	if err != nil {
		return nil, err
	}
	registrationTimeout, err := managedOKDDurationEnv("PLATFORM_FACTORY_MANAGED_OKD_REGISTRATION_TIMEOUT", 30*time.Minute, 2*time.Hour)
	if err != nil {
		return nil, err
	}
	poll, err := managedOKDDurationEnv("PLATFORM_FACTORY_MANAGED_OKD_POLL_INTERVAL", 2*time.Second, time.Minute)
	if err != nil {
		return nil, err
	}
	mediaTTL, err := managedOKDDurationEnv("PLATFORM_FACTORY_MANAGED_OKD_MEDIA_TTL", 6*time.Hour, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	mediaPublicURL := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_MEDIA_PUBLIC_URL"))
	if mediaPublicURL == "" {
		mediaPublicURL = strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_PUBLIC_URL")), "/")
	}
	media := &managedinstall.MediaStore{
		Root:       os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_MEDIA_ROOT"),
		PublicBase: mediaPublicURL,
		SigningKey: key,
		TTL:        mediaTTL,
	}
	// Force validation before any request can queue work against a half-configured
	// runtime. ResolveAgentISOMediaURL additionally re-verifies the exact ISO bytes.
	if err := media.Validate(); err != nil {
		return nil, fmt.Errorf("managed OKD media runtime: %w", err)
	}
	ocMirrorPath := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OC_MIRROR_PATH"))
	ocMirrorSHA := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OC_MIRROR_SHA256"))
	disconnectedRegistry := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_DISCONNECTED_MIRROR_REGISTRY"))
	disconnectedValues := 0
	for _, value := range []string{ocMirrorPath, ocMirrorSHA, disconnectedRegistry} {
		if value != "" {
			disconnectedValues++
		}
	}
	if disconnectedValues != 0 && disconnectedValues != 3 {
		return nil, fmt.Errorf("disconnected Managed OKD runtime requires PLATFORM_FACTORY_MANAGED_OKD_OC_MIRROR_PATH, PLATFORM_FACTORY_MANAGED_OKD_OC_MIRROR_SHA256 and PLATFORM_FACTORY_MANAGED_OKD_DISCONNECTED_MIRROR_REGISTRY together")
	}
	workspace := &managedinstall.WorkspaceRuntime{Config: managedinstall.WorkspaceRuntimeConfig{
		WorkspaceRoot:              os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_WORKSPACE_ROOT"),
		WorkRoot:                   os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_WORK_ROOT"),
		OpenShiftInstall:           os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OPENSHIFT_INSTALL_PATH"),
		OpenShiftInstallSHA:        os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OPENSHIFT_INSTALL_SHA256"),
		OC:                         os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OC_PATH"),
		OCSHA:                      os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_OC_SHA256"),
		OCMirror:                   ocMirrorPath,
		OCMirrorSHA:                ocMirrorSHA,
		DisconnectedMirrorRegistry: disconnectedRegistry,
		InstallTimeout:             installTimeout,
		CommandTimeout:             commandTimeout,
	}}
	if err := workspace.Validate(); err != nil {
		return nil, fmt.Errorf("managed OKD exact workspace runtime: %w", err)
	}
	registrar, err := apiServer.NewManagedOKDRegistrar(workspace, key, registrationTimeout)
	if err != nil {
		return nil, err
	}
	resolver := bootmedia.FileCredentialResolver{Root: os.Getenv("PLATFORM_FACTORY_MANAGED_OKD_REDFISH_CREDENTIAL_ROOT")}
	if err := resolver.Validate(); err != nil {
		return nil, fmt.Errorf("managed OKD Redfish credential resolver: %w", err)
	}
	redfish := &bootmedia.RedfishProvider{Resolver: resolver}
	composite := managedinstall.CompositeInstaller{InstallRuntime: workspace, Registrar: registrar}
	executor := &managedinstall.Executor{BootProvider: redfish, MediaResolver: media, Installer: composite}
	if disconnectedValues == 3 {
		if err := workspace.ValidateDisconnected(); err != nil {
			return nil, fmt.Errorf("managed OKD disconnected runtime: %w", err)
		}
		executor.DisconnectedInstaller = workspace
	}
	return &managedOKDProductionRuntime{executor: executor, media: media, poll: poll}, nil
}

func loadAgentPKI() (*agentpki.Signer, []byte, error) {
	certFile := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_AGENT_CA_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_AGENT_CA_KEY_FILE"))
	if certFile == "" && keyFile == "" {
		return nil, nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, nil, fmt.Errorf("both PLATFORM_FACTORY_AGENT_CA_CERT_FILE and PLATFORM_FACTORY_AGENT_CA_KEY_FILE are required")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	signer, err := agentpki.NewSigner(certPEM, keyPEM, time.Now)
	return signer, certPEM, err
}

func serverTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS certificate and private key must be configured together")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
func agentServerTLSConfig(certFile, keyFile string, agentCAPEM []byte) (*tls.Config, error) {
	cfg, err := serverTLSConfig(certFile, keyFile)
	if err != nil || cfg == nil {
		return cfg, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(agentCAPEM) {
		return nil, fmt.Errorf("agent CA certificate is invalid")
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	return cfg, nil
}

func loopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	action, cliErr := daemoncli.Parse(os.Args[1:])
	if cliErr != nil {
		fmt.Fprintln(os.Stderr, cliErr)
		fmt.Fprintln(os.Stderr, daemoncli.Usage(filepath.Base(os.Args[0])))
		os.Exit(2)
	}
	switch action {
	case daemoncli.Help:
		fmt.Println(daemoncli.Usage(filepath.Base(os.Args[0])))
		return
	case daemoncli.Version:
		fmt.Println(version)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	addr := os.Getenv("PLATFORM_FACTORY_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	developmentRequested := strings.EqualFold(os.Getenv("PLATFORM_FACTORY_DEVELOPMENT_MODE"), "true")
	localDevelopment := developmentRequested && strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_STATE_FILE")) != "" && strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_POSTGRES_DSN")) == "" && loopbackListenAddress(addr)
	if developmentRequested && !localDevelopment {
		logger.Error("development mode requires file-state persistence and a loopback listener")
		os.Exit(1)
	}
	components, err := catalog.Load()
	if err != nil {
		logger.Error("catalog load failed", "error", err)
		os.Exit(1)
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), productionStoreStartupTimeout)
	store, closeStore, err := openStore(startupCtx, logger)
	startupCancel()
	if err != nil {
		logger.Error("control-plane store open failed", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	apiServer := api.New(version, components, logger, store)
	if releaseDigest := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_SOURCE_RELEASE_DIGEST")); releaseDigest != "" {
		producerDigest, digestErr := releaseartifact.RunningExecutableDigest()
		if digestErr != nil {
			logger.Error("runtime closure producer identity failed", "error", digestErr)
			os.Exit(1)
		}
		if configErr := apiServer.ConfigureRuntimeClosureReleaseIdentity(releaseDigest, producerDigest); configErr != nil {
			logger.Error("runtime closure release identity configuration failed", "error", configErr)
			os.Exit(1)
		}
	}
	catalogSigningKey, catalogSigningMode, err := loadCatalogSigningKey(localDevelopment)
	if err != nil {
		logger.Error("catalog signing key configuration failed", "error", err)
		os.Exit(1)
	}
	apiServer.ConfigureCatalogSigner(catalogSigningKey, catalogSigningMode)
	agentSigner, agentCAPEM, err := loadAgentPKI()
	if err != nil {
		logger.Error("agent PKI configuration failed", "error", err)
		os.Exit(1)
	}
	mtlsRequired := strings.EqualFold(os.Getenv("PLATFORM_FACTORY_AGENT_MTLS_REQUIRED"), "true")
	if mtlsRequired && agentSigner == nil {
		logger.Error("agent mTLS is required but agent CA signer is not configured")
		os.Exit(1)
	}
	apiServer.ConfigureAgentMTLS(agentSigner, mtlsRequired)
	gitCtx, gitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err = ensureInternalGitAuthority(gitCtx, store); err != nil {
		gitCancel()
		logger.Error("internal Git authority configuration failed", "error", err)
		os.Exit(1)
	}
	gitCancel()
	apiServer.ConfigureSystemServices(integrations.New(integrations.Config{
		GitConnectionResolver:      gitConnectionResolver(store),
		ZotURL:                     os.Getenv("PLATFORM_FACTORY_INTERNAL_REGISTRY_URL"),
		KeycloakURL:                os.Getenv("PLATFORM_FACTORY_INTERNAL_IDENTITY_URL"),
		ArgoCDURL:                  os.Getenv("PLATFORM_FACTORY_INTERNAL_GITOPS_URL"),
		RepositoryBootstrapEnabled: strings.EqualFold(os.Getenv("PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP"), "true"),
	}))
	publicCA, err := loadPublicCAPEM()
	if err != nil {
		logger.Error("public CA configuration failed", "error", err)
		os.Exit(1)
	}
	agentPublicURL := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_AGENT_PUBLIC_URL"))
	if agentPublicURL == "" {
		agentPublicURL = os.Getenv("PLATFORM_FACTORY_PUBLIC_URL")
	}
	apiServer.ConfigureFleetImport(os.Getenv("PLATFORM_FACTORY_FLEET_AGENT_IMAGE"), os.Getenv("PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE"), agentPublicURL, publicCA)
	managedOKDRuntime, err := configureManagedOKDProductionRuntime(apiServer)
	if err != nil {
		logger.Error("managed OKD production runtime configuration failed", "error", err)
		os.Exit(1)
	}
	if managedOKDRuntime != nil {
		apiServer.ConfigureManagedOKDInstallExecutor(managedOKDRuntime.executor)
		logger.Info("managed OKD production executor configured", "authority", managedinstall.WorkspaceRuntimeAuthority, "mediaAuthority", managedinstall.MediaStoreAuthority)
	}
	aiConfig, err := airuntime.ConfigFromEnv(os.Getenv)
	if err != nil {
		logger.Error("AI runtime configuration failed", "error", err)
		os.Exit(1)
	}
	aiRuntime, err := airuntime.New(aiConfig)
	if err != nil {
		logger.Error("AI runtime initialization failed", "error", err)
		os.Exit(1)
	}
	apiServer.ConfigureAIRuntime(aiRuntime)
	apiServer.ConfigureMarketplaceAdvisor(marketplace.NewRuntimeAdvisor(aiRuntime))
	groupTTL := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_OIDC_GROUP_PROPAGATION_TTL")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed <= 0 || parsed > 30*time.Minute {
			logger.Error("invalid OIDC group propagation TTL", "value", raw)
			os.Exit(1)
		}
		groupTTL = parsed
	}
	apiServer.ConfigureIdentityAuthority(groupTTL)
	mcpResourceURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_PUBLIC_URL")), "/")
	if mcpResourceURL != "" {
		mcpResourceURL += "/mcp"
	}
	mcpAudience := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_MCP_OAUTH_AUDIENCE"))
	if mcpAudience == "" {
		mcpAudience = "platform-mcp"
	}

	authManager, err := auth.New(auth.Config{
		Enabled:             strings.EqualFold(os.Getenv("PLATFORM_FACTORY_OIDC_ENABLED"), "true"),
		Issuer:              os.Getenv("PLATFORM_FACTORY_OIDC_ISSUER"),
		InternalBase:        os.Getenv("PLATFORM_FACTORY_OIDC_INTERNAL_BASE"),
		ClientID:            os.Getenv("PLATFORM_FACTORY_OIDC_CLIENT_ID"),
		RedirectURL:         os.Getenv("PLATFORM_FACTORY_OIDC_REDIRECT_URL"),
		MCPResourceURL:      mcpResourceURL,
		MCPAudience:         mcpAudience,
		SessionSecret:       os.Getenv("PLATFORM_FACTORY_SESSION_SECRET"),
		BootstrapToken:      os.Getenv("PLATFORM_FACTORY_BOOTSTRAP_TOKEN"),
		LocalDevelopment:    localDevelopment,
		CookieSecure:        !strings.EqualFold(os.Getenv("PLATFORM_FACTORY_COOKIE_INSECURE"), "true"),
		BearerAuthenticator: apitoken.Authenticator{Store: store}.Authenticate,
		GroupPropagationTTL: groupTTL,
		GroupMapper: func(ctx context.Context, groups []string) (auth.GroupMappingResult, error) {
			resolved, resolveErr := store.ResolveOIDCGroups(ctx, groups)
			if resolveErr != nil {
				return auth.GroupMappingResult{}, resolveErr
			}
			return auth.GroupMappingResult{Roles: resolved.ProductRoles, OrganizationRoles: resolved.OrganizationRoles, ProjectRoles: resolved.ProjectRoles, MappingDigest: resolved.MappingDigest}, nil
		},
		AuditSink: func(ctx context.Context, record auth.SecurityAuditRecord) error {
			_, auditErr := store.AppendSecurityAudit(ctx, controlplane.SecurityAuditInput{Category: record.Category, Decision: record.Decision, ActorID: record.ActorID, Authentication: record.Authentication, Method: record.Method, Path: record.Path, StatusCode: record.StatusCode, ReasonCode: record.ReasonCode, RequestID: record.RequestID, ScopeType: record.ScopeType, ScopeID: record.ScopeID, EffectiveRole: record.EffectiveRole, MappingDigest: record.MappingDigest})
			return auditErr
		},
	})
	if err != nil {
		logger.Error("identity configuration failed", "error", err)
		os.Exit(1)
	}
	root := http.NewServeMux()
	if managedOKDRuntime != nil {
		root.Handle("/managed-install-media/", managedOKDRuntime.media.Handler())
	}
	authManager.Routes(root)
	root.Handle("/api/", authManager.RequireAPI(apiServer.Handler()))
	root.Handle("/mcp", authManager.RequireAPI(apiServer.Handler()))
	if !mtlsRequired {
		root.Handle("/agent/", apiServer.Handler())
	}
	root.Handle("/healthz", apiServer.Handler())
	root.Handle("/readyz", apiServer.Handler())
	root.Handle("/", authManager.RequirePage(webconsole.Handler()))
	tlsConfig, err := serverTLSConfig(os.Getenv("PLATFORM_FACTORY_TLS_CERT_FILE"), os.Getenv("PLATFORM_FACTORY_TLS_KEY_FILE"))
	if err != nil {
		logger.Error("server TLS configuration failed", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{Addr: addr, Handler: root, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: serverWriteTimeout, IdleTimeout: 60 * time.Second, TLSConfig: tlsConfig}
	agentAddr := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_AGENT_LISTEN"))
	var agentSrv *http.Server
	if agentAddr != "" {
		agentTLS, agentErr := agentServerTLSConfig(os.Getenv("PLATFORM_FACTORY_AGENT_TLS_CERT_FILE"), os.Getenv("PLATFORM_FACTORY_AGENT_TLS_KEY_FILE"), agentCAPEM)
		if agentErr != nil || agentTLS == nil {
			logger.Error("agent TLS listener configuration failed", "error", agentErr)
			os.Exit(1)
		}
		agentMux := http.NewServeMux()
		agentMux.Handle("/agent/", apiServer.Handler())
		agentMux.Handle("/healthz", apiServer.Handler())
		agentMux.Handle("/readyz", apiServer.Handler())
		agentSrv = &http.Server{Addr: agentAddr, Handler: agentMux, TLSConfig: agentTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: serverWriteTimeout, IdleTimeout: 60 * time.Second}
	}
	if mtlsRequired && agentSrv == nil {
		logger.Error("agent mTLS requires PLATFORM_FACTORY_AGENT_LISTEN and agent TLS certificate/key")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if managedOKDRuntime != nil {
		go apiServer.RunManagedOKDInstallWorker(ctx, managedOKDRuntime.poll)
		logger.Info("managed OKD durable worker started", "pollInterval", managedOKDRuntime.poll)
	}
	notificationEnabled := !strings.EqualFold(os.Getenv("PLATFORM_FACTORY_NOTIFICATION_DISPATCHER_DISABLED"), "true")
	if notificationEnabled {
		notificationWorker := notification.New(store, logger)
		if raw := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_NOTIFICATION_POLL_INTERVAL")); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				logger.Error("invalid notification poll interval", "value", raw)
				os.Exit(1)
			}
			notificationWorker.PollInterval = d
		}
		if raw := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_NOTIFICATION_HEALTH_SCAN_INTERVAL")); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				logger.Error("invalid notification health scan interval", "value", raw)
				os.Exit(1)
			}
			notificationWorker.HealthScan = d
		}
		go notificationWorker.Run(ctx)
		logger.Info("notification dispatcher started", "backend", store.Backend(), "pollInterval", notificationWorker.PollInterval, "healthScanInterval", notificationWorker.HealthScan)
	} else {
		logger.Warn("notification dispatcher disabled by configuration")
	}
	dataProtectionSchedulerEnabled := !strings.EqualFold(os.Getenv("PLATFORM_FACTORY_DATA_PROTECTION_SCHEDULER_DISABLED"), "true")
	if dataProtectionSchedulerEnabled {
		poll, parseErr := api.DataProtectionSchedulerPollInterval(os.Getenv("PLATFORM_FACTORY_DATA_PROTECTION_SCHEDULER_POLL_INTERVAL"))
		if parseErr != nil {
			logger.Error("invalid data protection scheduler poll interval", "error", parseErr)
			os.Exit(1)
		}
		go apiServer.RunDataProtectionScheduler(ctx, poll)
		logger.Info("data protection scheduler started", "backend", store.Backend(), "pollInterval", poll, "timezone", "UTC")
	} else {
		logger.Warn("data protection scheduler disabled by configuration")
	}

	supportBundleWorkerEnabled := !strings.EqualFold(os.Getenv("PLATFORM_FACTORY_SUPPORT_BUNDLE_WORKER_DISABLED"), "true")
	if supportBundleWorkerEnabled {
		poll := 2 * time.Second
		if raw := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_SUPPORT_BUNDLE_POLL_INTERVAL")); raw != "" {
			d, parseErr := time.ParseDuration(raw)
			if parseErr != nil || d <= 0 || d > time.Minute {
				logger.Error("invalid support bundle poll interval", "value", raw)
				os.Exit(1)
			}
			poll = d
		}
		go apiServer.RunSupportBundleWorker(ctx, poll)
		logger.Info("durable support bundle worker started", "backend", store.Backend(), "pollInterval", poll)
	} else {
		logger.Warn("durable support bundle worker disabled by configuration")
	}

	identityAdminWorkerDisabled := strings.EqualFold(os.Getenv("PLATFORM_FACTORY_IDENTITY_ADMIN_WORKER_DISABLED"), "true")
	identityURL := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_INTERNAL_IDENTITY_URL"))
	if !identityAdminWorkerDisabled && identityURL != "" {
		client := &identityadmin.KeycloakClient{
			BaseURL:      identityURL,
			Realm:        strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_KEYCLOAK_REALM")),
			AdminRealm:   strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_KEYCLOAK_ADMIN_REALM")),
			AdminUser:    strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_KEYCLOAK_ADMIN_USERNAME")),
			PasswordFile: strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_KEYCLOAK_ADMIN_PASSWORD_FILE")),
		}
		if err := client.Validate(); err != nil {
			logger.Error("identity admin reconciler configuration invalid", "error", err)
			os.Exit(1)
		}
		poll := 2 * time.Second
		if raw := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_IDENTITY_ADMIN_POLL_INTERVAL")); raw != "" {
			d, parseErr := time.ParseDuration(raw)
			if parseErr != nil || d <= 0 || d > time.Minute {
				logger.Error("invalid identity admin poll interval", "value", raw)
				os.Exit(1)
			}
			poll = d
		}
		owner := "platform-api"
		if hostname, hostErr := os.Hostname(); hostErr == nil && strings.TrimSpace(hostname) != "" {
			owner = "platform-api/" + strings.TrimSpace(hostname)
		}
		worker := &identityadmin.Worker{Store: store, Reconciler: client, Logger: logger, Owner: owner, PollInterval: poll}
		go worker.Run(ctx)
		logger.Info("durable identity admin worker started", "backend", store.Backend(), "pollInterval", poll)
	} else if identityAdminWorkerDisabled {
		logger.Warn("durable identity admin worker disabled by configuration")
	} else {
		logger.Info("durable identity admin worker inactive", "reason", "internal identity URL is not configured")
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// Stop public and agent admission concurrently. A slow agent request must
		// not consume the public server's entire drain budget (or vice versa).
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), httpShutdownTimeout)
		type shutdownResult struct {
			name string
			err  error
		}
		results := make(chan shutdownResult, 2)
		serverCount := 1
		go func() { results <- shutdownResult{name: "public", err: srv.Shutdown(shutdownCtx)} }()
		if agentSrv != nil {
			serverCount++
			go func() { results <- shutdownResult{name: "agent", err: agentSrv.Shutdown(shutdownCtx)} }()
		}
		for i := 0; i < serverCount; i++ {
			result := <-results
			if result.err != nil {
				logger.Warn(result.name+" server graceful shutdown incomplete", "error", result.err)
			}
		}
		cancelShutdown()

		// HTTP admission is now closed, so no new security-audit work can enter.
		// Drain events that were intentionally retained after client cancellation
		// before the deferred PostgreSQL close terminates their processor.
		if drainer, ok := store.(interface{ DrainSecurityAudit(context.Context) error }); ok {
			drainCtx, cancelDrain := context.WithTimeout(context.Background(), securityAuditDrainTimeout)
			if err := drainer.DrainSecurityAudit(drainCtx); err != nil {
				logger.Error("security audit graceful drain incomplete", "error", err)
			}
			cancelDrain()
		}
	}()
	logger.Info("platform api started", "listen", addr, "version", version, "tls", tlsConfig != nil, "agentMTLSRequired", mtlsRequired, "agentListen", agentAddr)
	if agentSrv != nil {
		go func() {
			logger.Info("agent TLS listener started", "listen", agentAddr)
			if e := agentSrv.ListenAndServeTLS("", ""); e != nil && !errors.Is(e, http.ErrServerClosed) {
				logger.Error("agent TLS listener failed", "error", e)
				stop()
			}
		}()
	}
	var serveErr error
	if tlsConfig != nil {
		serveErr = srv.ListenAndServeTLS("", "")
	} else {
		serveErr = srv.ListenAndServe()
	}
	if err := serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		stop()
		<-shutdownDone
		os.Exit(1)
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
}
