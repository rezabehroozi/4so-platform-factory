package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"platform.4so.io/factory/internal/buildinfo"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/daemoncli"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/targetmodel"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = buildinfo.Version

var serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
var maintenancePollInterval = time.Second

type config struct {
	Hub                          string
	ImportID                     string
	Enrollment                   string
	TokenFile                    string
	CAFile                       string
	Namespace                    string
	ServiceAccount               string
	CredentialSecret             string
	BootstrapSecret              string
	CertificateSecret            string
	Interval                     time.Duration
	RuntimeProbeImage            string
	AgentImage                   string
	ObservabilityMetricsURL      string
	ObservabilityLogsURL         string
	ObservabilityAlertsURL       string
	ObservabilityBearerTokenFile string
	ObservabilityCAFile          string
	ObservabilityAllowHTTP       bool
	BackupNamespace              string
}

type agent struct {
	cfg                         config
	hub                         *http.Client
	kube                        *http.Client
	token                       string // legacy bootstrap/migration credential only
	clusterID                   string
	certificateNotAfter         time.Time
	log                         *slog.Logger
	observability               *http.Client
	observabilityAutoDiscovered bool
}

type storedCredential struct {
	Token          string    `json:"token,omitempty"` // legacy bearer, removed after certificate migration
	ClusterID      string    `json:"clusterId"`
	CertificatePEM string    `json:"certificatePem,omitempty"`
	PrivateKeyPEM  string    `json:"privateKeyPem,omitempty"`
	NotAfter       time.Time `json:"notAfter,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "host-maintenance" {
		if err := runHostMaintenanceCommand(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config{
		Hub:                          strings.TrimRight(os.Getenv("PLATFORM_HUB_URL"), "/"),
		ImportID:                     os.Getenv("PLATFORM_IMPORT_ID"),
		Enrollment:                   os.Getenv("PLATFORM_ENROLLMENT_TOKEN"),
		TokenFile:                    env("PLATFORM_AGENT_TOKEN_FILE", "/var/lib/4so-platform-agent/credential.json"),
		CAFile:                       env("PLATFORM_HUB_CA_FILE", ""),
		Namespace:                    env("PLATFORM_AGENT_NAMESPACE", "4so-platform-agent"),
		ServiceAccount:               strings.TrimSpace(os.Getenv("PLATFORM_AGENT_SERVICE_ACCOUNT")),
		CredentialSecret:             env("PLATFORM_AGENT_CREDENTIAL_SECRET", "4so-platform-agent-credential"),
		BootstrapSecret:              env("PLATFORM_AGENT_BOOTSTRAP_SECRET", "4so-platform-agent-bootstrap"),
		CertificateSecret:            env("PLATFORM_AGENT_CERTIFICATE_SECRET", "4so-platform-agent-certificate"),
		Interval:                     60 * time.Second,
		RuntimeProbeImage:            strings.TrimSpace(os.Getenv("PLATFORM_RUNTIME_PROBE_IMAGE")),
		AgentImage:                   strings.TrimSpace(os.Getenv("PLATFORM_AGENT_IMAGE")),
		ObservabilityMetricsURL:      strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_METRICS_URL")), "/"),
		ObservabilityLogsURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_LOGS_URL")), "/"),
		ObservabilityAlertsURL:       strings.TrimRight(strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_ALERTS_URL")), "/"),
		ObservabilityBearerTokenFile: strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_BEARER_TOKEN_FILE")),
		ObservabilityCAFile:          strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_CA_FILE")),
		ObservabilityAllowHTTP:       strings.EqualFold(strings.TrimSpace(os.Getenv("PLATFORM_OBSERVABILITY_ALLOW_HTTP")), "true"),
		BackupNamespace:              strings.TrimSpace(os.Getenv("PLATFORM_BACKUP_NAMESPACE")),
	}
	if cfg.Hub == "" || cfg.ImportID == "" {
		log.Error("hub URL and import ID are required")
		os.Exit(1)
	}
	a, err := newAgent(cfg, log)
	if err != nil {
		log.Error("agent initialization failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = a.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func newAgent(cfg config, log *slog.Logger) (*agent, error) {
	pool := x509.NewCertPool()
	raw, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("Kubernetes service-account CA is invalid")
	}
	kube := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	hubTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		hubCA, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return nil, readErr
		}
		hubPool, poolErr := x509.SystemCertPool()
		if poolErr != nil || hubPool == nil {
			hubPool = x509.NewCertPool()
		}
		if !hubPool.AppendCertsFromPEM(hubCA) {
			return nil, fmt.Errorf("hub CA file contains no certificate")
		}
		hubTLS.RootCAs = hubPool
	}
	observability, err := buildObservabilityHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &agent{cfg: cfg, hub: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: hubTLS}}, kube: kube, observability: observability, log: log}, nil
}

func (a *agent) run(ctx context.Context) error {
	if err := a.loadOrClaim(ctx); err != nil {
		return err
	}
	if delay := agentPollDelay(a.clusterID, a.cfg.Interval, 0); delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}

	// AGENT_SCHEDULER_V2 keeps liveness/inventory collection independent from
	// mutation execution. The task lane remains deliberately single-writer: one
	// sequential task cycle may be running and at most one newer inventory epoch
	// may be queued. This prevents a slow mutation from making the Agent appear
	// stale/offline without introducing concurrent Kubernetes writers.
	taskKick := make(chan struct{}, 1)
	var taskWG sync.WaitGroup
	taskWG.Add(1)
	go func() {
		defer taskWG.Done()
		a.runTaskLane(ctx, taskKick)
	}()
	defer taskWG.Wait()

	cycle := uint64(1)
	for {
		if err := a.ensureCertificateFresh(ctx); err != nil {
			a.log.Warn("agent certificate rotation check failed", "error", err)
		}
		// Inventory is the authority epoch for every agent task. Never enqueue a
		// task cycle before the control plane has accepted a fresh
		// identity/capability observation for this cycle.
		if err := a.report(ctx); err != nil {
			a.log.Warn("inventory report failed; mutation/task polling suppressed", "error", err)
			if heartbeatErr := a.heartbeat(ctx); heartbeatErr != nil {
				a.log.Warn("heartbeat failed", "error", heartbeatErr)
			}
		} else if !enqueueAgentTaskCycle(taskKick) {
			a.log.Debug("agent task lane busy; newest accepted inventory epoch already queued")
		}

		delay := agentPollDelay(a.clusterID, a.cfg.Interval, cycle)
		cycle++
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func enqueueAgentTaskCycle(taskKick chan<- struct{}) bool {
	select {
	case taskKick <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *agent) runTaskLane(ctx context.Context, taskKick <-chan struct{}) {
	runSingleWriterTaskLane(ctx, taskKick, a.processTaskCycle)
}

func runSingleWriterTaskLane(ctx context.Context, taskKick <-chan struct{}, cycle func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-taskKick:
			cycle(ctx)
		}
	}
}

type agentTaskProcessor struct {
	name string
	run  func(context.Context) error
}

func (a *agent) taskProcessors() []agentTaskProcessor {
	return []agentTaskProcessor{
		{name: "drift", run: a.processDriftTask},
		{name: "baseline", run: a.processBaselineTask},
		{name: "tenant", run: a.processTenantTask},
		{name: "provider profile", run: a.processProviderProfileTask},
		{name: "provider cluster", run: a.processProviderClusterTask},
		{name: "cluster maintenance", run: a.processClusterMaintenanceTask},
		{name: "workload logs", run: a.processWorkloadLogTask},
		{name: "runtime certification", run: a.processRuntimeCertificationTask},
		{name: "data protection", run: a.processDataProtectionTask},
		{name: "compliance scan", run: a.processComplianceScanTask},
		{name: "runtime verification", run: a.processRuntimeVerificationTask},
	}
}

func (a *agent) processTaskCycle(ctx context.Context) {
	cycleStarted := time.Now()
	a.log.Debug("agent task cycle started", "scheduler", "AGENT_SCHEDULER_V2")
	defer func() {
		a.log.Debug("agent task cycle completed", "scheduler", "AGENT_SCHEDULER_V2", "duration_ms", time.Since(cycleStarted).Milliseconds())
	}()
	processors := a.taskProcessors()
	for _, processor := range processors {
		if ctx.Err() != nil {
			return
		}
		if err := processor.run(ctx); err != nil {
			a.log.Warn(processor.name+" task failed", "error", err)
		}
	}
}

func agentPollDelay(clusterID string, interval time.Duration, cycle uint64) time.Duration {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", strings.TrimSpace(clusterID), cycle)))
	sample := int64(uint16(sum[0])<<8 | uint16(sum[1]))
	if cycle == 0 {
		// Spread mass enrollment/restart first contact over the first 20%% of
		// the normal interval instead of stampeding the control plane at once.
		window := interval / 5
		if window <= 0 {
			return 0
		}
		return time.Duration(sample * int64(window) / 65535)
	}
	spread := interval / 10
	if spread <= 0 {
		return interval
	}
	offset := time.Duration(sample*int64(2*spread)/65535) - spread
	delay := interval + offset
	minimum := interval / 2
	if minimum < time.Second {
		minimum = time.Second
	}
	if delay < minimum {
		return minimum
	}
	return delay
}

func (a *agent) loadOrClaim(ctx context.Context) error {
	// The Kubernetes Secret is the durable certificate authority for the agent.
	// Prefer it over the local cache so a crash after certificate rotation cannot
	// resurrect a revoked cached certificate on restart.
	if credential, ok, secretErr := a.readSecretCredential(ctx); secretErr != nil {
		return secretErr
	} else if ok {
		if credential.CertificatePEM != "" && credential.PrivateKeyPEM != "" {
			if accepted, err := a.acceptStoredCertificate(ctx, credential); err != nil {
				return err
			} else if accepted {
				if err = a.writeFileCredential(credential); err != nil {
					if a.log != nil {
						a.log.Error("authoritative certificate accepted but local cache refresh failed", "error", err)
					}
					return fmt.Errorf("refresh local certificate cache from authoritative Secret: %w", err)
				}
				return nil
			}
		}
		if credential.Token != "" && credential.ClusterID != "" {
			a.token, a.clusterID = credential.Token, credential.ClusterID
			return a.migrateBearerCredential(ctx)
		}
	}
	if credential, ok := a.readFileCredential(); ok {
		if credential.CertificatePEM != "" && credential.PrivateKeyPEM != "" {
			if accepted, err := a.acceptStoredCertificate(ctx, credential); err != nil {
				return err
			} else if accepted {
				return nil
			}
		}
		if credential.Token != "" && credential.ClusterID != "" {
			a.token, a.clusterID = credential.Token, credential.ClusterID
			return a.migrateBearerCredential(ctx)
		}
	}
	if strings.TrimSpace(a.cfg.Enrollment) == "" {
		return fmt.Errorf("no persisted agent certificate, legacy credential or enrollment token is available")
	}
	uid, err := a.clusterUID(ctx)
	if err != nil {
		return err
	}
	payload := map[string]string{"token": a.cfg.Enrollment, "externalUid": uid, "agentVersion": version}
	var response struct {
		AgentToken string `json:"agentToken"`
		Cluster    struct {
			ID string `json:"id"`
		} `json:"cluster"`
	}
	if err = a.hubJSON(ctx, http.MethodPost, a.cfg.Hub+"/agent/v1/cluster-imports/"+a.cfg.ImportID+"/claim", payload, "", &response); err != nil {
		return err
	}
	if response.AgentToken == "" || response.Cluster.ID == "" {
		return fmt.Errorf("claim response is incomplete")
	}
	a.token, a.clusterID = response.AgentToken, response.Cluster.ID
	if err = a.migrateBearerCredential(ctx); err != nil {
		return fmt.Errorf("issue initial mTLS certificate: %w", err)
	}
	if err = a.clearEnrollmentToken(ctx); err != nil {
		return fmt.Errorf("revoke enrollment token after successful claim: %w", err)
	}
	a.cfg.Enrollment = ""
	return nil
}

func (a *agent) acceptStoredCertificate(ctx context.Context, credential storedCredential) (bool, error) {
	if err := a.activateCertificate(credential); err != nil {
		return false, nil
	}
	a.clusterID = credential.ClusterID
	// A newly applied enrollment manifest is the explicit recovery signal after
	// certificate revocation/expiry. Validate the stored certificate with the
	// authority before ignoring that enrollment token.
	if strings.TrimSpace(a.cfg.Enrollment) == "" {
		return true, nil
	}
	valid, err := a.validateCurrentCertificate(ctx)
	if err != nil {
		return false, err
	}
	if valid {
		if err := a.clearEnrollmentToken(ctx); err != nil {
			return false, fmt.Errorf("revoke enrollment token after certificate validation: %w", err)
		}
		a.cfg.Enrollment = ""
		return true, nil
	}
	a.clearHubClientCertificate()
	a.clusterID = ""
	return false, nil
}

func (a *agent) validateCurrentCertificate(ctx context.Context) (bool, error) {
	if a.clusterID == "" {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/certificates/current", nil)
	if err != nil {
		return false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return true, nil
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound {
		return false, nil
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return false, fmt.Errorf("agent certificate validation %s: %s", res.Status, strings.TrimSpace(string(raw)))
}

func (a *agent) clearHubClientCertificate() {
	transport, ok := a.hub.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return
	}
	base := transport.TLSClientConfig.Clone()
	base.Certificates = nil
	transport.TLSClientConfig = base
	a.certificateNotAfter = time.Time{}
}

func (a *agent) migrateBearerCredential(ctx context.Context) error {
	credential, err := a.issueCertificate(ctx, false)
	if err != nil {
		return err
	}
	if err = a.persistSecretCredential(ctx, credential); err != nil {
		return fmt.Errorf("persist agent certificate: %w", err)
	}
	if err = a.writeFileCredential(credential); err != nil {
		a.log.Warn("local certificate cache could not be written", "error", err)
	}
	a.token = ""
	return a.activateCertificate(credential)
}

func (a *agent) issueCertificate(ctx context.Context, rotate bool) (storedCredential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return storedCredential{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "4so-platform-agent"}}, key)
	if err != nil {
		return storedCredential{}, err
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return storedCredential{}, err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/certificates/issue"
	token := a.token
	if rotate {
		endpoint = a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/certificates/rotate"
		token = ""
	}
	var response struct {
		Certificate struct {
			NotAfter time.Time `json:"notAfter"`
		} `json:"certificate"`
		CertificatePEM string `json:"certificatePem"`
	}
	if err = a.hubJSON(ctx, http.MethodPost, endpoint, map[string]string{"csrPem": csrPEM}, token, &response); err != nil {
		return storedCredential{}, err
	}
	if response.CertificatePEM == "" || response.Certificate.NotAfter.IsZero() {
		return storedCredential{}, fmt.Errorf("certificate response is incomplete")
	}
	return storedCredential{ClusterID: a.clusterID, CertificatePEM: response.CertificatePEM, PrivateKeyPEM: keyPEM, NotAfter: response.Certificate.NotAfter}, nil
}

func (a *agent) activateCertificate(credential storedCredential) error {
	pair, err := tls.X509KeyPair([]byte(credential.CertificatePEM), []byte(credential.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("load agent certificate: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("agent certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse agent certificate: %w", err)
	}
	now := time.Now().UTC()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("agent certificate is outside its validity window")
	}
	transport, ok := a.hub.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("hub transport does not support client certificates")
	}
	base := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		base = transport.TLSClientConfig.Clone()
	}
	if base.MinVersion < tls.VersionTLS12 {
		base.MinVersion = tls.VersionTLS12
	}
	base.Certificates = []tls.Certificate{pair}
	transport.TLSClientConfig = base
	a.certificateNotAfter = leaf.NotAfter
	return nil
}

func (a *agent) ensureCertificateFresh(ctx context.Context) error {
	if a.clusterID == "" || a.certificateNotAfter.IsZero() || time.Until(a.certificateNotAfter) > 7*24*time.Hour {
		return nil
	}
	credential, err := a.issueCertificate(ctx, true)
	if err != nil {
		return err
	}
	if err = a.persistSecretCredential(ctx, credential); err != nil {
		return err
	}
	if err = a.writeFileCredential(credential); err != nil {
		return err
	}
	return a.activateCertificate(credential)
}

func (a *agent) readFileCredential() (storedCredential, bool) {
	raw, err := os.ReadFile(a.cfg.TokenFile)
	if err != nil {
		return storedCredential{}, false
	}
	var credential storedCredential
	if json.Unmarshal(raw, &credential) != nil || credential.ClusterID == "" {
		return storedCredential{}, false
	}
	legacy := credential.Token != ""
	mtls := credential.CertificatePEM != "" && credential.PrivateKeyPEM != ""
	if !legacy && !mtls {
		return storedCredential{}, false
	}
	return credential, true
}

func (a *agent) writeFileCredential(credential storedCredential) error {
	raw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return durablefile.Replace(a.cfg.TokenFile, raw, 0o700, 0o600)
}

func (a *agent) readSecretCredential(ctx context.Context) (storedCredential, bool, error) {
	read := func(name string) (map[string]string, bool, error) {
		if strings.TrimSpace(name) == "" {
			return nil, false, nil
		}
		object, found, err := a.getKubeObject(ctx, "/api/v1/namespaces/"+a.cfg.Namespace+"/secrets/"+name)
		if err != nil || !found {
			return nil, found, err
		}
		raw, ok := object["data"].(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("agent credential Secret %s has invalid data", name)
		}
		data := make(map[string]string, len(raw))
		for key, value := range raw {
			text, ok := value.(string)
			if !ok {
				return nil, false, fmt.Errorf("agent credential Secret %s key %s is not a string", name, key)
			}
			data[key] = text
		}
		return data, true, nil
	}
	decode := func(data map[string]string, key string) (string, error) {
		if strings.TrimSpace(data[key]) == "" {
			return "", nil
		}
		raw, err := base64.StdEncoding.DecodeString(data[key])
		if err != nil {
			return "", fmt.Errorf("decode agent credential key %s: %w", key, err)
		}
		return string(raw), nil
	}
	if data, ok, err := read(a.cfg.CertificateSecret); err != nil {
		return storedCredential{}, false, err
	} else if ok {
		clusterID, err := decode(data, "clusterId")
		if err != nil {
			return storedCredential{}, false, err
		}
		certPEM, err := decode(data, "tls.crt")
		if err != nil {
			return storedCredential{}, false, err
		}
		keyPEM, err := decode(data, "tls.key")
		if err != nil {
			return storedCredential{}, false, err
		}
		notAfter, err := decode(data, "notAfter")
		if err != nil {
			return storedCredential{}, false, err
		}
		c := storedCredential{ClusterID: clusterID, CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		if notAfter != "" {
			c.NotAfter, err = time.Parse(time.RFC3339, notAfter)
			if err != nil {
				return storedCredential{}, false, fmt.Errorf("parse agent certificate notAfter: %w", err)
			}
		}
		if c.ClusterID == "" || c.CertificatePEM == "" || c.PrivateKeyPEM == "" {
			return storedCredential{}, false, fmt.Errorf("agent certificate Secret is incomplete")
		}
		return c, true, nil
	}
	if data, ok, err := read(a.cfg.CredentialSecret); err != nil {
		return storedCredential{}, false, err
	} else if ok {
		token, err := decode(data, "token")
		if err != nil {
			return storedCredential{}, false, err
		}
		clusterID, err := decode(data, "clusterId")
		if err != nil {
			return storedCredential{}, false, err
		}
		if token == "" || clusterID == "" {
			return storedCredential{}, false, fmt.Errorf("legacy agent credential Secret is incomplete")
		}
		return storedCredential{Token: token, ClusterID: clusterID}, true, nil
	}
	return storedCredential{}, false, nil
}

func (a *agent) persistSecretCredential(ctx context.Context, credential storedCredential) error {
	if credential.CertificatePEM == "" || credential.PrivateKeyPEM == "" {
		payload := map[string]any{"data": map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(credential.Token)), "clusterId": base64.StdEncoding.EncodeToString([]byte(credential.ClusterID))}}
		return a.kubeJSON(ctx, http.MethodPatch, "/api/v1/namespaces/"+a.cfg.Namespace+"/secrets/"+a.cfg.CredentialSecret, payload, &map[string]any{})
	}
	data := map[string]string{"clusterId": base64.StdEncoding.EncodeToString([]byte(credential.ClusterID)), "tls.crt": base64.StdEncoding.EncodeToString([]byte(credential.CertificatePEM)), "tls.key": base64.StdEncoding.EncodeToString([]byte(credential.PrivateKeyPEM)), "notAfter": base64.StdEncoding.EncodeToString([]byte(credential.NotAfter.UTC().Format(time.RFC3339)))}
	payload := map[string]any{"data": data}
	certName := a.cfg.CertificateSecret
	if strings.TrimSpace(certName) == "" {
		certName = "4so-platform-agent-certificate"
	}
	path := "/api/v1/namespaces/" + a.cfg.Namespace + "/secrets/" + certName
	if err := a.kubeJSON(ctx, http.MethodPatch, path, payload, &map[string]any{}); err != nil {
		return err
	}
	legacy := map[string]any{"data": map[string]string{"token": "", "clusterId": base64.StdEncoding.EncodeToString([]byte(credential.ClusterID))}}
	if strings.TrimSpace(a.cfg.CredentialSecret) != "" {
		if err := a.kubeJSON(ctx, http.MethodPatch, "/api/v1/namespaces/"+a.cfg.Namespace+"/secrets/"+a.cfg.CredentialSecret, legacy, &map[string]any{}); err != nil {
			return fmt.Errorf("clear legacy agent bearer credential: %w", err)
		}
	}
	return nil
}

func (a *agent) clearEnrollmentToken(ctx context.Context) error {
	payload := map[string]any{"data": map[string]string{"enrollmentToken": ""}}
	path := "/api/v1/namespaces/" + a.cfg.Namespace + "/secrets/" + a.cfg.BootstrapSecret
	return a.kubeJSON(ctx, http.MethodPatch, path, payload, &map[string]any{})
}

func (a *agent) clusterUID(ctx context.Context) (string, error) {
	var namespace struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/namespaces/kube-system", nil, &namespace); err != nil {
		return "", err
	}
	if namespace.Metadata.UID == "" {
		return "", fmt.Errorf("kube-system UID is empty")
	}
	return namespace.Metadata.UID, nil
}

const workloadExplorerItemLimit = 250
const workloadExplorerEventLimit = 100
const workloadExplorerPageSize = 100

func workloadListPagePath(base string, limit int, continueToken string) string {
	values := url.Values{}
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	if strings.TrimSpace(continueToken) != "" {
		values.Set("continue", continueToken)
	}
	if len(values) == 0 {
		return base
	}
	return base + "?" + values.Encode()
}

func workloadPageLimit(remaining int) int {
	if remaining < 1 {
		return 0
	}
	if remaining < workloadExplorerPageSize {
		return remaining
	}
	return workloadExplorerPageSize
}

func workloadImages(containers []struct {
	Image string `json:"image"`
}) []string {
	out := make([]string, 0, len(containers))
	seen := map[string]bool{}
	for _, container := range containers {
		image := strings.TrimSpace(container.Image)
		if image != "" && !seen[image] {
			seen[image] = true
			out = append(out, image)
		}
	}
	sort.Strings(out)
	return out
}

func clusterEventLess(a, b controlplane.ClusterEventObservation) bool {
	if !a.LastObservedAt.Equal(b.LastObservedAt) {
		return a.LastObservedAt.After(b.LastObservedAt)
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Reason != b.Reason {
		return a.Reason < b.Reason
	}
	if a.RegardingKind != b.RegardingKind {
		return a.RegardingKind < b.RegardingKind
	}
	if a.RegardingName != b.RegardingName {
		return a.RegardingName < b.RegardingName
	}
	if a.Message != b.Message {
		return a.Message < b.Message
	}
	return a.Count < b.Count
}

func (a *agent) discoverWorkloadExplorer(ctx context.Context) (controlplane.ClusterWorkloadExplorer, error) {
	out := controlplane.ClusterWorkloadExplorer{Authority: controlplane.WorkloadExplorerAuthorityMethod, Complete: true}
	type listMeta struct {
		Continue string `json:"continue"`
	}
	type controllerList struct {
		Metadata listMeta `json:"metadata"`
		Items    []struct {
			Metadata struct{ Name, Namespace string } `json:"metadata"`
			Spec     struct {
				Replicas *int `json:"replicas"`
				Template struct {
					Spec struct {
						Containers []struct {
							Image string `json:"image"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
			Status struct{ Replicas, ReadyReplicas, AvailableReplicas, NumberReady, Succeeded, Failed int } `json:"status"`
		} `json:"items"`
	}
	controllerPaths := []struct{ path, kind string }{
		{"/apis/apps/v1/deployments", "Deployment"},
		{"/apis/apps/v1/statefulsets", "StatefulSet"},
		{"/apis/apps/v1/daemonsets", "DaemonSet"},
		{"/apis/batch/v1/jobs", "Job"},
	}
	for targetIndex, target := range controllerPaths {
		if len(out.Workloads) >= workloadExplorerItemLimit {
			// We deliberately did not query the remaining controller families.
			out.Truncated = true
			break
		}
		continueToken := ""
		for {
			remaining := workloadExplorerItemLimit - len(out.Workloads)
			pageLimit := workloadPageLimit(remaining)
			if pageLimit == 0 {
				out.Truncated = true
				break
			}
			var list controllerList
			if err := a.kubeJSON(ctx, http.MethodGet, workloadListPagePath(target.path, pageLimit, continueToken), nil, &list); err != nil {
				return out, fmt.Errorf("workload explorer %s: %w", strings.ToLower(target.kind), err)
			}
			for _, item := range list.Items {
				desired := item.Status.Replicas
				if item.Spec.Replicas != nil {
					desired = *item.Spec.Replicas
				}
				ready := item.Status.ReadyReplicas
				if target.kind == "DaemonSet" {
					ready = item.Status.NumberReady
				}
				out.Workloads = append(out.Workloads, controlplane.ClusterWorkloadObservation{Kind: target.kind, Namespace: item.Metadata.Namespace, Name: item.Metadata.Name, DesiredReplicas: desired, ReadyReplicas: ready, Succeeded: item.Status.Succeeded, Failed: item.Status.Failed, Images: workloadImages(item.Spec.Template.Spec.Containers)})
				if len(out.Workloads) >= workloadExplorerItemLimit {
					break
				}
			}
			continueToken = strings.TrimSpace(list.Metadata.Continue)
			if continueToken == "" {
				break
			}
			if len(out.Workloads) >= workloadExplorerItemLimit {
				out.Truncated = true
				break
			}
		}
		if len(out.Workloads) >= workloadExplorerItemLimit && targetIndex < len(controllerPaths)-1 {
			out.Truncated = true
		}
	}
	sort.Slice(out.Workloads, func(i, j int) bool {
		a, b := out.Workloads[i], out.Workloads[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})

	var servicePageToken string
	for {
		remaining := workloadExplorerItemLimit - len(out.Services)
		pageLimit := workloadPageLimit(remaining)
		if pageLimit == 0 {
			out.Truncated = true
			break
		}
		var services struct {
			Metadata listMeta `json:"metadata"`
			Items    []struct {
				Metadata struct{ Name, Namespace string } `json:"metadata"`
				Spec     struct {
					Type        string   `json:"type"`
					ClusterIP   string   `json:"clusterIP"`
					ExternalIPs []string `json:"externalIPs"`
					Ports       []struct {
						Name     string `json:"name"`
						Port     int    `json:"port"`
						Protocol string `json:"protocol"`
					} `json:"ports"`
				} `json:"spec"`
			} `json:"items"`
		}
		if err := a.kubeJSON(ctx, http.MethodGet, workloadListPagePath("/api/v1/services", pageLimit, servicePageToken), nil, &services); err != nil {
			return out, fmt.Errorf("workload explorer services: %w", err)
		}
		for _, item := range services.Items {
			ports := make([]controlplane.ClusterServicePortObservation, 0, len(item.Spec.Ports))
			for _, p := range item.Spec.Ports {
				ports = append(ports, controlplane.ClusterServicePortObservation{Name: p.Name, Port: p.Port, Protocol: p.Protocol})
			}
			external := append([]string(nil), item.Spec.ExternalIPs...)
			sort.Strings(external)
			out.Services = append(out.Services, controlplane.ClusterServiceObservation{Namespace: item.Metadata.Namespace, Name: item.Metadata.Name, Type: item.Spec.Type, ClusterIP: item.Spec.ClusterIP, ExternalIPs: external, Ports: ports})
			if len(out.Services) >= workloadExplorerItemLimit {
				break
			}
		}
		servicePageToken = strings.TrimSpace(services.Metadata.Continue)
		if servicePageToken == "" {
			break
		}
		if len(out.Services) >= workloadExplorerItemLimit {
			out.Truncated = true
			break
		}
	}
	sort.Slice(out.Services, func(i, j int) bool {
		if out.Services[i].Namespace != out.Services[j].Namespace {
			return out.Services[i].Namespace < out.Services[j].Namespace
		}
		return out.Services[i].Name < out.Services[j].Name
	})

	var ingressPageToken string
	for {
		remaining := workloadExplorerItemLimit - len(out.Ingresses)
		pageLimit := workloadPageLimit(remaining)
		if pageLimit == 0 {
			out.Truncated = true
			break
		}
		var ingresses struct {
			Metadata listMeta `json:"metadata"`
			Items    []struct {
				Metadata struct {
					Name, Namespace string
					Annotations     map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec struct {
					IngressClassName *string `json:"ingressClassName"`
					Rules            []struct {
						Host string `json:"host"`
					} `json:"rules"`
					TLS []struct {
						Hosts []string `json:"hosts"`
					} `json:"tls"`
				} `json:"spec"`
			} `json:"items"`
		}
		if err := a.kubeJSON(ctx, http.MethodGet, workloadListPagePath("/apis/networking.k8s.io/v1/ingresses", pageLimit, ingressPageToken), nil, &ingresses); err != nil {
			return out, fmt.Errorf("workload explorer ingresses: %w", err)
		}
		for _, item := range ingresses.Items {
			class := ""
			if item.Spec.IngressClassName != nil {
				class = *item.Spec.IngressClassName
			} else {
				class = item.Metadata.Annotations["kubernetes.io/ingress.class"]
			}
			hosts := []string{}
			for _, r := range item.Spec.Rules {
				if strings.TrimSpace(r.Host) != "" {
					hosts = append(hosts, r.Host)
				}
			}
			tls := []string{}
			for _, t := range item.Spec.TLS {
				tls = append(tls, t.Hosts...)
			}
			sort.Strings(hosts)
			sort.Strings(tls)
			out.Ingresses = append(out.Ingresses, controlplane.ClusterIngressObservation{Namespace: item.Metadata.Namespace, Name: item.Metadata.Name, Class: class, Hosts: hosts, TLSHosts: tls})
			if len(out.Ingresses) >= workloadExplorerItemLimit {
				break
			}
		}
		ingressPageToken = strings.TrimSpace(ingresses.Metadata.Continue)
		if ingressPageToken == "" {
			break
		}
		if len(out.Ingresses) >= workloadExplorerItemLimit {
			out.Truncated = true
			break
		}
	}
	sort.Slice(out.Ingresses, func(i, j int) bool {
		if out.Ingresses[i].Namespace != out.Ingresses[j].Namespace {
			return out.Ingresses[i].Namespace < out.Ingresses[j].Namespace
		}
		return out.Ingresses[i].Name < out.Ingresses[j].Name
	})

	var pvcPageToken string
	for {
		remaining := workloadExplorerItemLimit - len(out.PVCs)
		pageLimit := workloadPageLimit(remaining)
		if pageLimit == 0 {
			out.Truncated = true
			break
		}
		var pvcs struct {
			Metadata listMeta `json:"metadata"`
			Items    []struct {
				Metadata struct{ Name, Namespace string } `json:"metadata"`
				Spec     struct {
					StorageClassName *string `json:"storageClassName"`
					Resources        struct {
						Requests map[string]string `json:"requests"`
					} `json:"resources"`
				} `json:"spec"`
				Status struct {
					Phase string `json:"phase"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := a.kubeJSON(ctx, http.MethodGet, workloadListPagePath("/api/v1/persistentvolumeclaims", pageLimit, pvcPageToken), nil, &pvcs); err != nil {
			return out, fmt.Errorf("workload explorer persistent volume claims: %w", err)
		}
		for _, item := range pvcs.Items {
			sc := ""
			if item.Spec.StorageClassName != nil {
				sc = *item.Spec.StorageClassName
			}
			out.PVCs = append(out.PVCs, controlplane.ClusterPVCObservation{Namespace: item.Metadata.Namespace, Name: item.Metadata.Name, StorageClass: sc, Phase: item.Status.Phase, Requested: item.Spec.Resources.Requests["storage"]})
			if len(out.PVCs) >= workloadExplorerItemLimit {
				break
			}
		}
		pvcPageToken = strings.TrimSpace(pvcs.Metadata.Continue)
		if pvcPageToken == "" {
			break
		}
		if len(out.PVCs) >= workloadExplorerItemLimit {
			out.Truncated = true
			break
		}
	}
	sort.Slice(out.PVCs, func(i, j int) bool {
		if out.PVCs[i].Namespace != out.PVCs[j].Namespace {
			return out.PVCs[i].Namespace < out.PVCs[j].Namespace
		}
		return out.PVCs[i].Name < out.PVCs[j].Name
	})

	var eventPageToken string
	for {
		remaining := workloadExplorerEventLimit - len(out.Events)
		pageLimit := workloadPageLimit(remaining)
		if pageLimit == 0 {
			out.Truncated = true
			break
		}
		var events struct {
			Metadata listMeta `json:"metadata"`
			Items    []struct {
				Metadata              struct{ Namespace string } `json:"metadata"`
				Type, Reason, Message string
				Count                 int
				Regarding             struct{ Kind, Name string } `json:"regarding"`
				InvolvedObject        struct{ Kind, Name string } `json:"involvedObject"`
				EventTime             time.Time                   `json:"eventTime"`
				LastTimestamp         time.Time                   `json:"lastTimestamp"`
			} `json:"items"`
		}
		if err := a.kubeJSON(ctx, http.MethodGet, workloadListPagePath("/api/v1/events", pageLimit, eventPageToken), nil, &events); err != nil {
			return out, fmt.Errorf("workload explorer events: %w", err)
		}
		for _, item := range events.Items {
			kind, name := item.Regarding.Kind, item.Regarding.Name
			if kind == "" {
				kind = item.InvolvedObject.Kind
				name = item.InvolvedObject.Name
			}
			last := item.EventTime
			if last.IsZero() {
				last = item.LastTimestamp
			}
			out.Events = append(out.Events, controlplane.ClusterEventObservation{Namespace: item.Metadata.Namespace, Type: item.Type, Reason: item.Reason, RegardingKind: kind, RegardingName: name, Message: item.Message, Count: item.Count, LastObservedAt: last})
			if len(out.Events) >= workloadExplorerEventLimit {
				break
			}
		}
		eventPageToken = strings.TrimSpace(events.Metadata.Continue)
		if eventPageToken == "" {
			break
		}
		if len(out.Events) >= workloadExplorerEventLimit {
			out.Truncated = true
			break
		}
	}
	sort.Slice(out.Events, func(i, j int) bool { return clusterEventLess(out.Events[i], out.Events[j]) })
	return out, nil
}

func (a *agent) report(ctx context.Context) error {
	var nodes struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				UID    string            `json:"uid"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				NodeInfo struct {
					OSImage        string `json:"osImage"`
					Architecture   string `json:"architecture"`
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
				Capacity    map[string]string `json:"capacity"`
				Allocatable map[string]string `json:"allocatable"`
				Conditions  []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/nodes", nil, &nodes); err != nil {
		return err
	}
	var deployments struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Replicas  int `json:"replicas"`
				Available int `json:"availableReplicas"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/apps/v1/deployments", nil, &deployments); err != nil {
		return fmt.Errorf("inventory deployments: %w", err)
	}

	var storageClasses struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Provisioner          string `json:"provisioner"`
			ReclaimPolicy        string `json:"reclaimPolicy"`
			VolumeBindingMode    string `json:"volumeBindingMode"`
			AllowVolumeExpansion *bool  `json:"allowVolumeExpansion"`
		} `json:"items"`
	}
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/storage.k8s.io/v1/storageclasses", nil, &storageClasses); err != nil {
		return fmt.Errorf("inventory storage classes: %w", err)
	}

	outNodes := make([]controlplane.ClusterNode, 0, len(nodes.Items))
	capacity := controlplane.ClusterCapacity{}
	kubernetesVersion := ""
	distribution := "kubernetes"
	distributionEvidenceMethod := controlplane.DistributionEvidenceKubeletV1
	distributionEvidenceUID := ""
	distributionEvidenceVersion := ""
	for _, node := range nodes.Items {
		ready := false
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				ready = true
			}
		}
		roles := []string{}
		for key := range node.Metadata.Labels {
			if strings.HasPrefix(key, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(key, "node-role.kubernetes.io/"))
			}
		}
		sort.Strings(roles)
		if kubernetesVersion == "" {
			kubernetesVersion = node.Status.NodeInfo.KubeletVersion
			distributionEvidenceVersion = kubernetesVersion
			lower := strings.ToLower(kubernetesVersion)
			switch {
			case strings.Contains(lower, "rke2"):
				distribution = "rke2"
			case strings.Contains(lower, "k3s"):
				distribution = "k3s"
			}
		}
		capacity.CPUCapacityMilli += parseCPUQuantity(node.Status.Capacity["cpu"])
		capacity.CPUAllocatableMilli += parseCPUQuantity(node.Status.Allocatable["cpu"])
		capacity.MemoryCapacityBytes += parseByteQuantity(node.Status.Capacity["memory"])
		capacity.MemoryAllocatableBytes += parseByteQuantity(node.Status.Allocatable["memory"])
		capacity.PodsCapacity += parseIntegerQuantity(node.Status.Capacity["pods"])
		capacity.PodsAllocatable += parseIntegerQuantity(node.Status.Allocatable["pods"])
		outNodes = append(outNodes, controlplane.ClusterNode{Name: node.Metadata.Name, UID: node.Metadata.UID, Roles: roles, OS: node.Status.NodeInfo.OSImage, Architecture: node.Status.NodeInfo.Architecture, KubeletVersion: node.Status.NodeInfo.KubeletVersion, Ready: ready})
	}
	sort.Slice(outNodes, func(i, j int) bool { return outNodes[i].Name < outNodes[j].Name })

	addons := make([]controlplane.ClusterAddOn, 0, len(deployments.Items))
	for _, deployment := range deployments.Items {
		addons = append(addons, controlplane.ClusterAddOn{Name: deployment.Metadata.Name, Namespace: deployment.Metadata.Namespace, Version: deployment.Metadata.Labels["app.kubernetes.io/version"], Healthy: deployment.Status.Replicas > 0 && deployment.Status.Available == deployment.Status.Replicas})
	}
	sort.Slice(addons, func(i, j int) bool {
		return addons[i].Namespace+"/"+addons[i].Name < addons[j].Namespace+"/"+addons[j].Name
	})

	classes := make([]controlplane.ClusterStorageClass, 0, len(storageClasses.Items))
	for _, item := range storageClasses.Items {
		isDefault := item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" || item.Metadata.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true"
		classes = append(classes, controlplane.ClusterStorageClass{Name: item.Metadata.Name, Provisioner: item.Provisioner, ReclaimPolicy: item.ReclaimPolicy, VolumeBindingMode: item.VolumeBindingMode, AllowVolumeExpansion: item.AllowVolumeExpansion != nil && *item.AllowVolumeExpansion, Default: isDefault})
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Name < classes[j].Name })

	workloadExplorer, workloadErr := a.discoverWorkloadExplorer(ctx)
	if workloadErr != nil {
		return workloadErr
	}

	networking := detectClusterNetworking(deployments.Items)
	networking.GatewayAPI = a.kubeDiscoveryAvailable(ctx, "/apis/gateway.networking.k8s.io/v1")
	apiResources, crds, apiDiscoveryComplete, crdDiscoveryComplete := a.discoverAPISurface(ctx)
	distribution, distributionEvidenceMethod, distributionEvidenceUID, distributionEvidenceVersion, err := a.detectDistributionAuthority(ctx, distribution, kubernetesVersion, crds, crdDiscoveryComplete)
	if err != nil {
		return fmt.Errorf("inventory distribution authority: %w", err)
	}
	if distribution == targetmodel.DistributionOKD || distribution == targetmodel.DistributionOpenShift {
		distributionComponents, discoverErr := a.discoverOpenShiftDistributionComponents(ctx)
		if discoverErr != nil {
			return fmt.Errorf("inventory distribution health authority: %w", discoverErr)
		}
		addons = append(addons, distributionComponents...)
		sort.Slice(addons, func(i, j int) bool {
			if addons[i].Kind == addons[j].Kind {
				return addons[i].Namespace+"/"+addons[i].Name < addons[j].Namespace+"/"+addons[j].Name
			}
			return addons[i].Kind < addons[j].Kind
		})
	}
	schemaDiscoveryVersion, schemaDiscoveryDigest, schemaDiscoveryComplete := a.discoverSchemaAuthority(ctx)
	_ = a.ensureObservabilityAdapterDiscovery(ctx)

	certificates := []controlplane.ClusterCertificateObservation{}
	kubeCert, err := a.kubeServerCertificate(ctx)
	if err != nil || kubeCert == nil {
		if err == nil {
			err = fmt.Errorf("Kubernetes API certificate is unavailable")
		}
		return fmt.Errorf("inventory Kubernetes API certificate: %w", err)
	}
	certificates = append(certificates, certificateObservation("kubernetes-api-server", kubeCert))
	agentCert := a.activeAgentCertificate()
	if agentCert == nil {
		return fmt.Errorf("inventory agent mTLS certificate is unavailable")
	}
	certificates = append(certificates, certificateObservation("4so-platform-agent", agentCert))
	sort.Slice(certificates, func(i, j int) bool { return certificates[i].Name < certificates[j].Name })

	externalUID, err := a.clusterUID(ctx)
	if err != nil || strings.TrimSpace(externalUID) == "" {
		if err == nil {
			err = fmt.Errorf("kube-system UID is empty")
		}
		return fmt.Errorf("inventory cluster identity continuity: %w", err)
	}

	capabilities := []string{"outbound-agent", "read-only-inventory", "agent-mtls", "agent-scheduler-v2", "capacity-inventory", "certificate-inventory", "cert.dns", "cert.tls"}
	if a.enrollmentPrincipalIsolated() {
		capabilities = append(capabilities, controlplane.TargetEnrollmentPrincipalIsolatedCapability)
	}
	if strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		capabilities = append(capabilities, "runtime-probe-image-digest-pinned")
	}
	if len(classes) > 0 {
		capabilities = append(capabilities, "storage-class-inventory")
	}
	if networking.CNI != "" {
		capabilities = append(capabilities, "cni-inventory")
	}
	if len(networking.IngressControllers) > 0 {
		capabilities = append(capabilities, "ingress-inventory")
	}
	if networking.GatewayAPI {
		capabilities = append(capabilities, "gateway-api")
	}
	if workloadExplorer.Complete {
		capabilities = append(capabilities, "workload-explorer-read")
	}
	if len(apiResources) > 0 {
		capabilities = append(capabilities, "api-surface-inventory")
	}
	if crdDiscoveryComplete {
		capabilities = append(capabilities, "crd-inventory")
	}
	if schemaDiscoveryComplete {
		capabilities = append(capabilities, "openapi-schema-authority", "strict-schema-dry-run")
	}
	if a.observabilityAdapterConfigured() {
		capabilities = append(capabilities, "cert.metrics", "cert.logs", "cert.alerts")
		if a.observabilityAutoDiscovered {
			capabilities = append(capabilities, "observability-adapter-auto-discovered")
		}
	}
	if networkCaps, ok := a.networkTenantIsolationCapabilities(apiResources); ok {
		capabilities = append(capabilities, networkCaps...)
		capabilities = append(capabilities, "network-tenant-isolation-probe-ready")
	}
	if storageCaps, ok := a.storageBackupCapabilities(ctx); ok {
		capabilities = append(capabilities, storageCaps...)
		capabilities = append(capabilities, "storage-backup-adapter-auto-discovered")
	}
	if a.dataProtectionCapabilityAvailable(ctx) {
		capabilities = append(capabilities, controlplane.DataProtectionAgentCapability)
	}
	basisCapabilities := append([]string(nil), capabilities...)
	// The control plane owns this marker after comparing the reported kube-system
	// UID. The agent already has that UID here, so include the expected server-owned
	// marker only for computing the exact activation basis digest.
	basisCapabilities = append(basisCapabilities, controlplane.TargetIdentityContinuityCapability)
	basisDigest := controlplane.ClusterInventoryMutationBasisDigest(controlplane.ClusterInventory{
		Distribution: distribution, DistributionEvidenceMethod: distributionEvidenceMethod, DistributionEvidenceUID: distributionEvidenceUID, DistributionEvidenceVersion: distributionEvidenceVersion,
		KubernetesVersion: kubernetesVersion, Nodes: outNodes, AddOns: addons, StorageClasses: classes, Capacity: capacity, Certificates: certificates, Networking: networking, WorkloadExplorer: workloadExplorer,
		APIResources: apiResources, CRDs: crds, APIDiscoveryComplete: apiDiscoveryComplete, CRDDiscoveryComplete: crdDiscoveryComplete,
		SchemaDiscoveryVersion: schemaDiscoveryVersion, SchemaDiscoveryDigest: schemaDiscoveryDigest, SchemaDiscoveryComplete: schemaDiscoveryComplete, Capabilities: basisCapabilities,
	})
	if a.mutationRBACActive(ctx, basisDigest) {
		capabilities = append(capabilities,
			"controlled-baseline-deployment",
			controlplane.TenantDeleteObservedCapability,
			controlplane.ClusterMaintenanceFencedReportCapability,
			controlplane.TargetMutationRBACActiveCapability,
		)
		if a.nodeHostMaintenanceExecutorReady(ctx, distribution) {
			capabilities = append(capabilities, controlplane.TargetNodeHostMaintenanceCapability, controlplane.TargetNodeOSPatchCapability)
		}
		if a.providerMachineLifecycleReady(ctx) {
			capabilities = append(capabilities, controlplane.TargetNodeProviderMachineLifecycleCapability)
		}
	}
	sort.Strings(capabilities)
	payload := map[string]any{"observedAt": time.Now().UTC(), "externalUid": externalUID, "distribution": distribution, "distributionEvidenceMethod": distributionEvidenceMethod, "distributionEvidenceUid": distributionEvidenceUID, "distributionEvidenceVersion": distributionEvidenceVersion, "kubernetesVersion": kubernetesVersion, "nodes": outNodes, "addOns": addons, "storageClasses": classes, "capacity": capacity, "certificates": certificates, "networking": networking, "workloadExplorer": workloadExplorer, "apiResources": apiResources, "crds": crds, "apiDiscoveryComplete": apiDiscoveryComplete, "crdDiscoveryComplete": crdDiscoveryComplete, "schemaDiscoveryVersion": schemaDiscoveryVersion, "schemaDiscoveryDigest": schemaDiscoveryDigest, "schemaDiscoveryComplete": schemaDiscoveryComplete, "capabilities": capabilities}
	return a.hubJSON(ctx, http.MethodPost, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/inventory", payload, "", &map[string]any{})
}

func (a *agent) detectDistributionAuthority(ctx context.Context, heuristic, kubernetesVersion string, crds []controlplane.ClusterCRDObservation, crdDiscoveryComplete bool) (string, string, string, string, error) {
	type clusterVersion struct {
		Metadata struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			Desired struct {
				Version string `json:"version"`
			} `json:"desired"`
		} `json:"status"`
	}
	var cv clusterVersion
	found, err := a.kubeJSONOptional(ctx, "/apis/config.openshift.io/v1/clusterversions/version", &cv)
	if err != nil {
		return "", "", "", "", err
	}
	if found {
		if !crdDiscoveryComplete {
			return "", "", "", "", fmt.Errorf("ClusterVersion exists but CRD discovery is incomplete")
		}
		for _, crd := range crds {
			if strings.EqualFold(strings.TrimSpace(crd.Name), "clusterversions.config.openshift.io") {
				return "", "", "", "", fmt.Errorf("ClusterVersion authority is ambiguous because a same-name CRD exists")
			}
		}
		if cv.Metadata.Name != "version" || strings.TrimSpace(cv.Metadata.UID) == "" || strings.TrimSpace(cv.Status.Desired.Version) == "" {
			return "", "", "", "", fmt.Errorf("ClusterVersion/version authority is incomplete")
		}
		releaseVersion := strings.TrimSpace(cv.Status.Desired.Version)
		if strings.Contains(strings.ToLower(releaseVersion), "okd") {
			return targetmodel.DistributionOKD, controlplane.DistributionEvidenceOKDClusterV1, strings.TrimSpace(cv.Metadata.UID), releaseVersion, nil
		}
		// ClusterVersion is shared by OKD and Red Hat OpenShift. Never collapse
		// a non-OKD release into the OKD identity; keep it recognized but
		// non-admitted until a dedicated target contract exists.
		return targetmodel.DistributionOpenShift, controlplane.DistributionEvidenceOpenShiftClusterV1, strings.TrimSpace(cv.Metadata.UID), releaseVersion, nil
	}
	return heuristic, controlplane.DistributionEvidenceKubeletV1, "", strings.TrimSpace(kubernetesVersion), nil
}

func conditionValue(conditions []struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}, wanted string) (string, string, string) {
	for _, condition := range conditions {
		if strings.EqualFold(strings.TrimSpace(condition.Type), wanted) {
			return strings.TrimSpace(condition.Status), strings.TrimSpace(condition.Reason), strings.TrimSpace(condition.Message)
		}
	}
	return "Unknown", "ConditionMissing", wanted + " condition is not reported"
}

func clusterVersionConditionSummary(conditions []struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}) (available, progressing, degraded, upgradeable, reason, message string) {
	available, availableReason, availableMessage := conditionValue(conditions, "Available")
	progressing, progressingReason, progressingMessage := conditionValue(conditions, "Progressing")
	// ClusterVersion reports release failure through the Failing condition, while
	// ClusterOperator reports Degraded. Project both onto the product's Degraded
	// field so the control plane has one health vocabulary without losing the
	// upstream condition semantics.
	degraded, degradedReason, degradedMessage := conditionValue(conditions, "Failing")
	upgradeable, upgradeableReason, upgradeableMessage := conditionValue(conditions, "Upgradeable")
	if strings.EqualFold(degraded, "True") {
		return available, progressing, degraded, upgradeable, degradedReason, degradedMessage
	}
	if !strings.EqualFold(available, "True") {
		return available, progressing, degraded, upgradeable, availableReason, availableMessage
	}
	if strings.EqualFold(progressing, "True") {
		return available, progressing, degraded, upgradeable, progressingReason, progressingMessage
	}
	if strings.EqualFold(upgradeable, "False") {
		return available, progressing, degraded, upgradeable, upgradeableReason, upgradeableMessage
	}
	return available, progressing, degraded, upgradeable, "", ""
}

func distributionConditionSummary(conditions []struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}) (available, progressing, degraded, upgradeable, reason, message string) {
	available, availableReason, availableMessage := conditionValue(conditions, "Available")
	progressing, progressingReason, progressingMessage := conditionValue(conditions, "Progressing")
	degraded, degradedReason, degradedMessage := conditionValue(conditions, "Degraded")
	upgradeable, upgradeableReason, upgradeableMessage := conditionValue(conditions, "Upgradeable")
	if strings.EqualFold(degraded, "True") {
		return available, progressing, degraded, upgradeable, degradedReason, degradedMessage
	}
	if !strings.EqualFold(available, "True") {
		return available, progressing, degraded, upgradeable, availableReason, availableMessage
	}
	if strings.EqualFold(progressing, "True") {
		return available, progressing, degraded, upgradeable, progressingReason, progressingMessage
	}
	if strings.EqualFold(upgradeable, "False") {
		return available, progressing, degraded, upgradeable, upgradeableReason, upgradeableMessage
	}
	return available, progressing, degraded, upgradeable, "", ""
}

func (a *agent) discoverOpenShiftDistributionComponents(ctx context.Context) ([]controlplane.ClusterAddOn, error) {
	type condition struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	type clusterOperator struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Version    string      `json:"version"`
			Conditions []condition `json:"conditions"`
		} `json:"status"`
	}
	var operators struct {
		Items []clusterOperator `json:"items"`
	}
	found, err := a.kubeJSONOptional(ctx, "/apis/config.openshift.io/v1/clusteroperators", &operators)
	if err != nil {
		return nil, err
	}
	if !found || len(operators.Items) == 0 {
		return nil, fmt.Errorf("ClusterOperator inventory is unavailable")
	}

	type clusterVersion struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Channel string `json:"channel"`
		} `json:"spec"`
		Status struct {
			Desired struct {
				Version string `json:"version"`
				Image   string `json:"image"`
			} `json:"desired"`
			Conditions []condition `json:"conditions"`
		} `json:"status"`
	}
	var cv clusterVersion
	found, err = a.kubeJSONOptional(ctx, "/apis/config.openshift.io/v1/clusterversions/version", &cv)
	if err != nil {
		return nil, err
	}
	if !found || cv.Metadata.Name != "version" || strings.TrimSpace(cv.Status.Desired.Version) == "" {
		return nil, fmt.Errorf("ClusterVersion/version health authority is unavailable")
	}

	toAnonymous := func(values []condition) []struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} {
		out := make([]struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}, 0, len(values))
		for _, v := range values {
			out = append(out, struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			}{v.Type, v.Status, v.Reason, v.Message})
		}
		return out
	}
	available, progressing, degraded, upgradeable, reason, message := clusterVersionConditionSummary(toAnonymous(cv.Status.Conditions))
	components := []controlplane.ClusterAddOn{{Name: "version", Kind: "cluster-version", Version: strings.TrimSpace(cv.Status.Desired.Version), Healthy: strings.EqualFold(available, "True") && !strings.EqualFold(progressing, "True") && !strings.EqualFold(degraded, "True"), Available: available, Progressing: progressing, Degraded: degraded, Upgradeable: upgradeable, Reason: reason, Message: message}}
	for _, operator := range operators.Items {
		available, progressing, degraded, upgradeable, reason, message := distributionConditionSummary(toAnonymous(operator.Status.Conditions))
		components = append(components, controlplane.ClusterAddOn{Name: strings.TrimSpace(operator.Metadata.Name), Kind: "cluster-operator", Version: strings.TrimSpace(operator.Status.Version), Healthy: strings.EqualFold(available, "True") && !strings.EqualFold(progressing, "True") && !strings.EqualFold(degraded, "True"), Available: available, Progressing: progressing, Degraded: degraded, Upgradeable: upgradeable, Reason: reason, Message: message})
	}
	return components, nil
}

func (a *agent) enrollmentPrincipalIsolated() bool {
	if strings.TrimSpace(a.cfg.ImportID) == "" || strings.TrimSpace(a.cfg.ServiceAccount) == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(a.cfg.ServiceAccount)), []byte(controlplane.FleetAgentServiceAccountName(a.cfg.ImportID))) == 1
}

func (a *agent) mutationRBACActive(ctx context.Context, expectedBasisDigest string) bool {
	if !a.mutationActivationIdentityBound(ctx, expectedBasisDigest) {
		return false
	}
	checks := []struct {
		group, version, resource, verb, namespace string
	}{
		{"", "v1", "configmaps", "create", "4so-platform-baseline"},
		{"batch", "v1", "jobs", "create", "4so-platform-baseline"},
		{"", "v1", "namespaces", "create", ""},
		{"", "v1", "nodes", "patch", ""},
		{"", "v1", "pods/eviction", "create", ""},
		{"cluster.x-k8s.io", "v1beta2", "clusters", "create", "4so-provider-system"},
	}
	for _, check := range checks {
		allowed, err := a.selfSubjectAccessAllowed(ctx, check.group, check.version, check.resource, check.verb, check.namespace)
		if err != nil || !allowed {
			return false
		}
	}
	return true
}

func (a *agent) providerMachineLifecycleReady(ctx context.Context) bool {
	checks := []struct{ group, version, resource, verb, namespace string }{
		{"cluster.x-k8s.io", "v1beta1", "machines", "get", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta1", "machines", "list", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta1", "machines", "patch", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta1", "machines", "delete", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta1", "machinesets", "get", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta1", "machinedeployments", "get", "4so-provider-system"},
		{"cluster.x-k8s.io", "v1beta2", "clusters", "patch", "4so-provider-system"},
	}
	for _, check := range checks {
		allowed, err := a.selfSubjectAccessAllowed(ctx, check.group, check.version, check.resource, check.verb, check.namespace)
		if err != nil || !allowed {
			return false
		}
	}
	return true
}

func (a *agent) mutationActivationIdentityBound(ctx context.Context, expectedBasisDigest string) bool {
	var activation struct {
		Data map[string]string `json:"data"`
	}
	path := "/api/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/configmaps/4so-platform-mutation-activation"
	found, err := a.kubeJSONOptional(ctx, path, &activation)
	if err != nil || !found {
		return false
	}
	if strings.TrimSpace(activation.Data["clusterId"]) == "" || activation.Data["clusterId"] != a.clusterID {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(activation.Data["revoked"]), "true") {
		return false
	}
	issuedDigest := strings.TrimSpace(activation.Data["issuedFromInventoryDigest"])
	expectedBasisDigest = strings.TrimSpace(expectedBasisDigest)
	if !strings.HasPrefix(issuedDigest, "sha256:") || !strings.HasPrefix(expectedBasisDigest, "sha256:") || subtle.ConstantTimeCompare([]byte(issuedDigest), []byte(expectedBasisDigest)) != 1 {
		return false
	}
	uid, err := a.clusterUID(ctx)
	if err != nil || strings.TrimSpace(uid) == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(uid), []byte(strings.TrimSpace(activation.Data["externalUid"]))) == 1
}

func (a *agent) selfSubjectAccessAllowed(ctx context.Context, group, version, resource, verb, namespace string) (bool, error) {
	body := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]any{
			"resourceAttributes": map[string]any{
				"namespace": namespace,
				"verb":      verb,
				"group":     group,
				"version":   version,
				"resource":  resource,
			},
		},
	}
	var response struct {
		Status struct {
			Allowed bool `json:"allowed"`
			Denied  bool `json:"denied"`
		} `json:"status"`
	}
	if err := a.kubeJSON(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body, &response); err != nil {
		return false, err
	}
	return response.Status.Allowed && !response.Status.Denied, nil
}

func parseCPUQuantity(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if strings.HasSuffix(value, "m") {
		v, _ := strconv.ParseInt(strings.TrimSuffix(value, "m"), 10, 64)
		return v
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(v * 1000)
}

func parseByteQuantity(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	multipliers := []struct {
		suffix string
		value  float64
	}{{"Ki", 1024}, {"Mi", 1024 * 1024}, {"Gi", 1024 * 1024 * 1024}, {"Ti", 1024 * 1024 * 1024 * 1024}, {"Pi", 1024 * 1024 * 1024 * 1024 * 1024}, {"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}, {"T", 1000 * 1000 * 1000 * 1000}}
	for _, item := range multipliers {
		if strings.HasSuffix(value, item.suffix) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(value, item.suffix), 64)
			if err != nil {
				return 0
			}
			return int64(v * item.value)
		}
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(v)
}

func parseIntegerQuantity(value string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return v
}

func detectClusterNetworking(items []struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Status struct {
		Replicas  int `json:"replicas"`
		Available int `json:"availableReplicas"`
	} `json:"status"`
}) controlplane.ClusterNetworking {
	candidates := []string{"cilium", "calico", "canal", "flannel", "antrea", "weave", "kube-router"}
	cnis := map[string]bool{}
	ingress := map[string]bool{}
	for _, item := range items {
		name := strings.ToLower(item.Metadata.Name)
		for _, candidate := range candidates {
			if strings.Contains(name, candidate) {
				cnis[candidate] = true
			}
		}
		if strings.Contains(name, "ingress") || strings.Contains(name, "traefik") || strings.Contains(name, "contour") || strings.Contains(name, "kong") {
			ingress[item.Metadata.Namespace+"/"+item.Metadata.Name] = true
		}
	}
	cniNames := make([]string, 0, len(cnis))
	for name := range cnis {
		cniNames = append(cniNames, name)
	}
	sort.Strings(cniNames)
	ingressNames := make([]string, 0, len(ingress))
	for name := range ingress {
		ingressNames = append(ingressNames, name)
	}
	sort.Strings(ingressNames)
	out := controlplane.ClusterNetworking{IngressControllers: ingressNames}
	if len(cniNames) > 0 {
		out.CNI = cniNames[0]
	}
	return out
}

func certificateObservation(name string, cert *x509.Certificate) controlplane.ClusterCertificateObservation {
	sum := sha256.Sum256(cert.Raw)
	return controlplane.ClusterCertificateObservation{Name: name, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SerialNumber: cert.SerialNumber.String(), Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC()}
}

func (a *agent) activeAgentCertificate() *x509.Certificate {
	transport, ok := a.hub.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) == 0 || len(transport.TLSClientConfig.Certificates[0].Certificate) == 0 {
		return nil
	}
	cert, _ := x509.ParseCertificate(transport.TLSClientConfig.Certificates[0].Certificate[0])
	return cert
}

func (a *agent) kubeServerCertificate(ctx context.Context) (*x509.Certificate, error) {
	serviceToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://kubernetes.default.svc/version", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	res, err := a.kube.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 || res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("Kubernetes API TLS certificate is unavailable")
	}
	return res.TLS.PeerCertificates[0], nil
}

func (a *agent) kubeDiscoveryAvailable(ctx context.Context, path string) bool {
	serviceToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://kubernetes.default.svc"+path, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	res, err := a.kube.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode/100 == 2
}

type kubeAPIGroupList struct {
	Groups []struct {
		Name     string `json:"name"`
		Versions []struct {
			GroupVersion string `json:"groupVersion"`
			Version      string `json:"version"`
		} `json:"versions"`
	} `json:"groups"`
}
type kubeAPIResourceList struct {
	GroupVersion string `json:"groupVersion"`
	APIResources []struct {
		Name       string   `json:"name"`
		Namespaced bool     `json:"namespaced"`
		Kind       string   `json:"kind"`
		Verbs      []string `json:"verbs"`
	} `json:"resources"`
}
type kubeCRDList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Group string `json:"group"`
			Scope string `json:"scope"`
			Names struct {
				Kind   string `json:"kind"`
				Plural string `json:"plural"`
			} `json:"names"`
			Versions []struct {
				Name    string `json:"name"`
				Served  bool   `json:"served"`
				Storage bool   `json:"storage"`
			} `json:"versions"`
		} `json:"spec"`
	} `json:"items"`
}

func (a *agent) discoverAPISurface(ctx context.Context) ([]controlplane.ClusterAPIResourceObservation, []controlplane.ClusterCRDObservation, bool, bool) {
	lists := []kubeAPIResourceList{}
	var core kubeAPIResourceList
	apiComplete := true
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1", nil, &core); err != nil {
		apiComplete = false
	} else {
		lists = append(lists, core)
	}
	var groups kubeAPIGroupList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis", nil, &groups); err != nil {
		apiComplete = false
	} else {
		seen := map[string]bool{}
		for _, group := range groups.Groups {
			for _, ver := range group.Versions {
				if ver.GroupVersion == "" || seen[ver.GroupVersion] {
					continue
				}
				seen[ver.GroupVersion] = true
				var list kubeAPIResourceList
				if err := a.kubeJSON(ctx, http.MethodGet, "/apis/"+ver.GroupVersion, nil, &list); err != nil {
					apiComplete = false
					continue
				}
				lists = append(lists, list)
			}
		}
	}
	resources := []controlplane.ClusterAPIResourceObservation{}
	for _, list := range lists {
		group, version := "", list.GroupVersion
		if parts := strings.Split(list.GroupVersion, "/"); len(parts) > 1 {
			group, version = parts[0], parts[len(parts)-1]
		}
		for _, item := range list.APIResources {
			if strings.Contains(item.Name, "/") || item.Kind == "" {
				continue
			}
			verbs := append([]string(nil), item.Verbs...)
			sort.Strings(verbs)
			resources = append(resources, controlplane.ClusterAPIResourceObservation{APIVersion: list.GroupVersion, Group: group, Version: version, Kind: item.Kind, Resource: item.Name, Namespaced: item.Namespaced, Verbs: verbs})
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].APIVersion == resources[j].APIVersion {
			return resources[i].Kind < resources[j].Kind
		}
		return resources[i].APIVersion < resources[j].APIVersion
	})

	crds := []controlplane.ClusterCRDObservation{}
	crdComplete := true
	var crdList kubeCRDList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", nil, &crdList); err != nil {
		crdComplete = false
	} else {
		for _, item := range crdList.Items {
			versions := make([]controlplane.ClusterCRDVersionObservation, 0, len(item.Spec.Versions))
			for _, v := range item.Spec.Versions {
				versions = append(versions, controlplane.ClusterCRDVersionObservation{Name: v.Name, Served: v.Served, Storage: v.Storage})
			}
			sort.Slice(versions, func(i, j int) bool { return versions[i].Name < versions[j].Name })
			crds = append(crds, controlplane.ClusterCRDObservation{Name: item.Metadata.Name, Group: item.Spec.Group, Kind: item.Spec.Names.Kind, Plural: item.Spec.Names.Plural, Scope: item.Spec.Scope, Versions: versions})
		}
	}
	sort.Slice(crds, func(i, j int) bool { return crds[i].Name < crds[j].Name })
	return resources, crds, apiComplete, crdComplete
}

func (a *agent) discoverSchemaAuthority(ctx context.Context) (string, string, bool) {
	for _, candidate := range []struct {
		version string
		path    string
	}{{"OPENAPI_V3", "/openapi/v3"}, {"OPENAPI_V2", "/openapi/v2"}} {
		digest, err := a.kubeDocumentDigest(ctx, candidate.path)
		if err == nil && strings.HasPrefix(digest, "sha256:") {
			return candidate.version, digest, true
		}
	}
	return "", "", false
}

func (a *agent) kubeDocumentDigest(ctx context.Context, path string) (string, error) {
	req, err := a.kubeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	res, err := a.kube.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("Kubernetes schema API %s", res.Status)
	}
	const maxSchemaDocument = int64(64 << 20)
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(res.Body, maxSchemaDocument+1))
	if err != nil {
		return "", err
	}
	if n == 0 || n > maxSchemaDocument {
		return "", fmt.Errorf("Kubernetes schema document size is invalid")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (a *agent) heartbeat(ctx context.Context) error {
	externalUID, err := a.clusterUID(ctx)
	if err != nil || strings.TrimSpace(externalUID) == "" {
		if err == nil {
			err = fmt.Errorf("kube-system UID is empty")
		}
		return fmt.Errorf("heartbeat cluster identity continuity: %w", err)
	}
	payload := map[string]string{"agentVersion": version, "externalUid": externalUID}
	return a.hubJSON(ctx, http.MethodPost, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/heartbeat", payload, "", &map[string]any{})
}

func (a *agent) kubeJSON(ctx context.Context, method, path string, in any, out any) error {
	serviceToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		raw, marshalErr := json.Marshal(in)
		if marshalErr != nil {
			return marshalErr
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://kubernetes.default.svc"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	if method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/merge-patch+json")
	} else if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("Kubernetes API %s: %s", res.Status, string(raw))
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (a *agent) kubeJSONOptional(ctx context.Context, path string, out any) (bool, error) {
	serviceToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://kubernetes.default.svc"+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	res, err := a.kube.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(res.Body, 2048))
		return false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return false, fmt.Errorf("Kubernetes API %s: %s", res.Status, string(raw))
	}
	if out == nil {
		return true, nil
	}
	if err = json.NewDecoder(res.Body).Decode(out); err != nil {
		return false, err
	}
	return true, nil
}

func (a *agent) hubJSON(ctx context.Context, method, endpoint string, in any, token string, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("hub API %s: %s", res.Status, string(body))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

var baselineResourcePaths = map[string]string{
	"ResourceQuota/4so-baseline-quota":       "/api/v1/namespaces/4so-platform-baseline/resourcequotas/4so-baseline-quota",
	"LimitRange/4so-baseline-limits":         "/api/v1/namespaces/4so-platform-baseline/limitranges/4so-baseline-limits",
	"NetworkPolicy/4so-default-deny-ingress": "/apis/networking.k8s.io/v1/namespaces/4so-platform-baseline/networkpolicies/4so-default-deny-ingress",
	"ServiceAccount/4so-baseline-observer":   "/api/v1/namespaces/4so-platform-baseline/serviceaccounts/4so-baseline-observer",
	"ConfigMap/4so-baseline-revision":        "/api/v1/namespaces/4so-platform-baseline/configmaps/4so-baseline-revision",
}

func taskExecutionContext(parent context.Context, leaseExpiresAt time.Time) (context.Context, context.CancelFunc, error) {
	now := time.Now().UTC()
	if leaseExpiresAt.IsZero() || !leaseExpiresAt.After(now) {
		return nil, nil, fmt.Errorf("agent task lease is absent or expired")
	}
	ctx, cancel := context.WithDeadline(parent, leaseExpiresAt)
	return ctx, cancel, nil
}

func (a *agent) processBaselineTask(ctx context.Context) error {
	task, ok, err := a.nextBaselineTask(ctx)
	if err != nil || !ok {
		return err
	}
	result := controlplane.BaselineTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	if err = validateBaselineTask(task); err != nil {
		result.Success = false
		result.Error = err.Error()
		return a.reportBaselineTask(ctx, task, result)
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	switch task.Action {
	case "PLAN":
		result = a.planBaseline(execCtx, task)
	case "APPLY":
		result = a.applyBaseline(execCtx, task)
	case "ROLLBACK":
		result = a.rollbackBaseline(execCtx, task)
	default:
		result = controlplane.BaselineTaskResult{Action: task.Action, Success: false, Error: "unsupported baseline task action"}
	}
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportBaselineTask(ctx, task, result)
}

func validateBaselineTask(task controlplane.BaselineTask) error {
	if task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) || task.TargetNamespace != "4so-platform-baseline" || task.BaselineID != "secure-namespace-foundation" || (task.BaselineVersion != "1.0.0" && task.BaselineVersion != "1.1.0") || !strings.HasPrefix(task.DesiredDigest, "sha256:") {
		return fmt.Errorf("baseline task identity is not allowed")
	}
	if len(task.Resources) != len(baselineResourcePaths) {
		return fmt.Errorf("baseline task resource count is invalid")
	}
	seen := map[string]bool{}
	for _, resource := range task.Resources {
		key := resource.Kind + "/" + resource.Name
		if resource.Namespace != task.TargetNamespace || baselineResourcePaths[key] == "" || seen[key] {
			return fmt.Errorf("resource %s is outside the baseline allowlist", key)
		}
		seen[key] = true
		if task.Action != "ROLLBACK" {
			if resource.Object == nil {
				return fmt.Errorf("resource %s has no desired object", key)
			}
			metadata, _ := resource.Object["metadata"].(map[string]any)
			if metadata["name"] != resource.Name || metadata["namespace"] != resource.Namespace {
				return fmt.Errorf("resource %s metadata mismatch", key)
			}
			annotations, _ := metadata["annotations"].(map[string]any)
			if annotations["platform.4so.io/desired-digest"] != task.DesiredDigest {
				return fmt.Errorf("resource %s digest annotation mismatch", key)
			}
		}
	}
	return nil
}

func (a *agent) nextBaselineTask(ctx context.Context) (controlplane.BaselineTask, bool, error) {
	var task controlplane.BaselineTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/baseline-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("hub task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) planBaseline(ctx context.Context, task controlplane.BaselineTask) controlplane.BaselineTaskResult {
	changes := make([]controlplane.BaselinePlanChange, 0, len(task.Resources))
	currentObjects := make(map[string]map[string]any, len(task.Resources))
	for _, resource := range task.Resources {
		current, found, err := a.getKubeObject(ctx, baselineResourcePaths[resource.Kind+"/"+resource.Name])
		if err != nil {
			return controlplane.BaselineTaskResult{Action: "PLAN", Success: false, Error: err.Error()}
		}
		action, currentDigest, reason := "ADD", "", "resource does not exist"
		if found {
			currentObjects[resource.Kind+"/"+resource.Name] = current
			currentDigest = objectDesiredDigest(current)
			if currentDigest == task.DesiredDigest && kubeObjectContainsDesiredFields(current, resource.Object) {
				action, reason = "NOOP", "desired revision and managed fields are already present"
			} else {
				action, reason = "UPDATE", "managed resource differs from desired revision"
			}
		}
		changes = append(changes, controlplane.BaselinePlanChange{Resource: resource.Kind + "/" + resource.Name, Action: action, Current: currentDigest, Desired: task.DesiredDigest, Reason: reason})
	}
	schemaEvidence := make(map[string]controlplane.PlanSchemaCompatibility, len(task.Resources))
	rollbackEvidence := make(map[string]controlplane.PlanRollbackResource, len(task.Resources))
	changeByResource := make(map[string]controlplane.BaselinePlanChange, len(changes))
	for _, change := range changes {
		changeByResource[change.Resource] = change
	}
	for _, resource := range task.Resources {
		key := resource.Kind + "/" + resource.Name
		schemaEvidence[key] = a.schemaDryRunCompatibility(ctx, task, resource)
		rollbackEvidence[key] = a.rollbackFeasibility(ctx, task, resource, changeByResource[key], currentObjects[key])
	}
	impact := controlplane.AnalyzePlanningImpactWithSchema(task.Resources, currentObjects, changes, task.Inventory, schemaEvidence, rollbackEvidence)
	evidencePlan, evidenceErr := a.baselineEvidenceCollectionPlan(task)
	if evidenceErr != nil {
		return controlplane.BaselineTaskResult{Action: "PLAN", Success: false, Error: evidenceErr.Error()}
	}
	impact.Evidence = evidencePlan
	impact.Digest = controlplane.PlanningImpactDigest(impact)
	return controlplane.BaselineTaskResult{Action: "PLAN", Success: true, ObservedDigest: a.currentBaselineDigest(ctx), Changes: changes, Impact: impact}
}

func evidenceArtifactKey(resource controlplane.BaselineTaskResource) string {
	v := strings.ToLower(resource.Kind + "-" + resource.Name)
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return "resource-readback-" + strings.Trim(b.String(), "-")
}

func (a *agent) baselineEvidenceCollectionPlan(task controlplane.BaselineTask) (controlplane.PlanEvidenceCollection, error) {
	if strings.TrimSpace(task.DeploymentID) == "" {
		return controlplane.PlanEvidenceCollection{}, fmt.Errorf("evidence collection requires deployment id")
	}
	artifacts := make([]controlplane.PlanEvidenceArtifact, 0, len(task.Resources)+1)
	for _, resource := range task.Resources {
		path, err := schemaResourcePath(task.Inventory, resource)
		if err != nil {
			return controlplane.PlanEvidenceCollection{}, fmt.Errorf("evidence plan source for %s/%s: %w", resource.Kind, resource.Name, err)
		}
		key := evidenceArtifactKey(resource)
		artifacts = append(artifacts, controlplane.PlanEvidenceArtifact{
			Key: key, Kind: "KUBE_RESOURCE_READBACK", Resource: resource.Kind + "/" + resource.Name,
			Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc" + path,
			OutputLocation: "/api/v1/baseline-deployments/" + task.DeploymentID + "/evidence/" + key,
			MediaType:      "application/json", Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays,
		})
	}
	key := "baseline-convergence"
	artifacts = append(artifacts, controlplane.PlanEvidenceArtifact{
		Key: key, Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence",
		OutputLocation: "/api/v1/baseline-deployments/" + task.DeploymentID + "/evidence/" + key, MediaType: "application/json",
		Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays,
	})
	plan := controlplane.FinalizeEvidenceCollectionPlan(artifacts)
	if err := controlplane.ValidateEvidenceCollectionPlanSemantics(plan, task.DeploymentID, task.Resources); err != nil {
		return controlplane.PlanEvidenceCollection{}, err
	}
	return plan, nil
}

func schemaResourcePath(inv controlplane.ClusterInventory, resource controlplane.BaselineTaskResource) (string, error) {
	var discovered *controlplane.ClusterAPIResourceObservation
	for i := range inv.APIResources {
		item := &inv.APIResources[i]
		if item.APIVersion == resource.APIVersion && item.Kind == resource.Kind {
			discovered = item
			break
		}
	}
	if discovered == nil {
		return "", fmt.Errorf("resource %s/%s is absent from API discovery", resource.APIVersion, resource.Kind)
	}
	patchAllowed := false
	for _, verb := range discovered.Verbs {
		if verb == "patch" {
			patchAllowed = true
			break
		}
	}
	if !patchAllowed {
		return "", fmt.Errorf("resource %s/%s does not advertise patch", resource.APIVersion, resource.Kind)
	}
	name := strings.TrimSpace(resource.Name)
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("resource name is invalid")
	}
	base := "/apis/" + resource.APIVersion
	if resource.APIVersion == "v1" {
		base = "/api/v1"
	}
	if discovered.Namespaced {
		namespace := strings.TrimSpace(resource.Namespace)
		if namespace == "" || strings.Contains(namespace, "/") {
			return "", fmt.Errorf("namespaced resource %s/%s has invalid namespace", resource.APIVersion, resource.Kind)
		}
		base += "/namespaces/" + namespace
	} else if strings.TrimSpace(resource.Namespace) != "" {
		return "", fmt.Errorf("cluster-scoped resource %s/%s must not carry namespace", resource.APIVersion, resource.Kind)
	}
	return base + "/" + discovered.Resource + "/" + name, nil
}

func (a *agent) schemaDryRunCompatibility(ctx context.Context, task controlplane.BaselineTask, resource controlplane.BaselineTaskResource) controlplane.PlanSchemaCompatibility {
	evidence := controlplane.PlanSchemaCompatibility{
		Status:             "FAIL",
		Method:             controlplane.PlanSchemaValidationMethod,
		SchemaIndexVersion: task.Inventory.SchemaDiscoveryVersion,
		SchemaIndexDigest:  task.Inventory.SchemaDiscoveryDigest,
	}
	if !task.Inventory.SchemaDiscoveryComplete || !strings.HasPrefix(task.Inventory.SchemaDiscoveryDigest, "sha256:") {
		evidence.FailureDigest = digestText("schema discovery is incomplete")
		return evidence
	}
	path, pathErr := schemaResourcePath(task.Inventory, resource)
	if pathErr != nil || resource.Object == nil {
		if pathErr != nil {
			evidence.FailureDigest = digestText(pathErr.Error())
		} else {
			evidence.FailureDigest = digestText("resource object is unavailable")
		}
		return evidence
	}
	raw, err := json.Marshal(resource.Object)
	if err != nil {
		evidence.FailureDigest = digestText(err.Error())
		return evidence
	}
	query := "?fieldManager=4so-platform-agent-plan&force=false&dryRun=All&fieldValidation=Strict"
	req, err := a.kubeRequest(ctx, http.MethodPatch, path+query, bytes.NewReader(raw), "application/apply-patch+yaml")
	if err != nil {
		evidence.FailureDigest = digestText(err.Error())
		return evidence
	}
	res, err := a.kube.Do(req)
	if err != nil {
		evidence.FailureDigest = digestText(err.Error())
		return evidence
	}
	defer res.Body.Close()
	evidence.HTTPStatus = res.StatusCode
	evidence.Warnings = boundedWarningHeaders(res.Header.Values("Warning"))
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	if res.StatusCode/100 == 2 {
		evidence.Status = "PASS"
		return evidence
	}
	evidence.FailureDigest = digestText(fmt.Sprintf("status=%d body=%s", res.StatusCode, string(body)))
	return evidence
}

func sanitizeRollbackObject(resource controlplane.BaselineTaskResource, current map[string]any) (map[string]any, error) {
	if current == nil {
		return nil, fmt.Errorf("current object is unavailable")
	}
	if strings.EqualFold(resource.Kind, "Secret") {
		return nil, fmt.Errorf("sensitive Secret pre-image requires external recovery authority")
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	delete(out, "status")
	meta, _ := out["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		out["metadata"] = meta
	}
	for _, key := range []string{"uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "selfLink"} {
		delete(meta, key)
	}
	meta["name"] = resource.Name
	if resource.Namespace != "" {
		meta["namespace"] = resource.Namespace
	} else {
		delete(meta, "namespace")
	}
	out["apiVersion"] = resource.APIVersion
	out["kind"] = resource.Kind
	return out, nil
}

func rollbackObjectDigest(object map[string]any) string {
	raw, _ := json.Marshal(object)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func discoveredAPIResource(inv controlplane.ClusterInventory, resource controlplane.BaselineTaskResource) (*controlplane.ClusterAPIResourceObservation, bool) {
	for i := range inv.APIResources {
		item := &inv.APIResources[i]
		if item.APIVersion == resource.APIVersion && item.Kind == resource.Kind {
			return item, true
		}
	}
	return nil, false
}

func hasVerb(verbs []string, want string) bool {
	for _, verb := range verbs {
		if verb == want {
			return true
		}
	}
	return false
}

func (a *agent) rollbackDeleteAuthorization(ctx context.Context, task controlplane.BaselineTask, resource controlplane.BaselineTaskResource) (bool, int, string) {
	discovered, ok := discoveredAPIResource(task.Inventory, resource)
	if !ok || !hasVerb(discovered.Verbs, "delete") {
		return false, 0, "target API discovery does not advertise delete"
	}
	group := discovered.Group
	if resource.APIVersion != "v1" && group == "" {
		group, _ = splitAPIVersionLocal(resource.APIVersion)
	}
	body := map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": map[string]any{"resourceAttributes": map[string]any{"namespace": resource.Namespace, "verb": "delete", "group": group, "version": discovered.Version, "resource": discovered.Resource, "name": resource.Name}}}
	raw, _ := json.Marshal(body)
	req, err := a.kubeRequest(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", bytes.NewReader(raw), "application/json")
	if err != nil {
		return false, 0, err.Error()
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return false, 0, err.Error()
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	if res.StatusCode/100 != 2 {
		return false, res.StatusCode, fmt.Sprintf("SelfSubjectAccessReview status=%d", res.StatusCode)
	}
	var parsed struct {
		Status struct {
			Allowed bool   `json:"allowed"`
			Denied  bool   `json:"denied"`
			Reason  string `json:"reason"`
		} `json:"status"`
	}
	if err = json.Unmarshal(payload, &parsed); err != nil {
		return false, res.StatusCode, err.Error()
	}
	if !parsed.Status.Allowed || parsed.Status.Denied {
		if parsed.Status.Reason == "" {
			parsed.Status.Reason = "delete access denied"
		}
		return false, res.StatusCode, parsed.Status.Reason
	}
	return true, res.StatusCode, ""
}

func splitAPIVersionLocal(apiVersion string) (string, string) {
	parts := strings.SplitN(apiVersion, "/", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	return parts[0], parts[1]
}

func kubeObjectResourceVersion(object map[string]any) (string, error) {
	metadata, _ := object["metadata"].(map[string]any)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	resourceVersion = strings.TrimSpace(resourceVersion)
	if resourceVersion == "" {
		return "", fmt.Errorf("Kubernetes object resourceVersion is required")
	}
	return resourceVersion, nil
}

func rollbackRestoreUpdateObject(restore, current map[string]any, expectedUID string) (map[string]any, error) {
	uid, err := kubeObjectUID(current)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(expectedUID) == "" || uid != expectedUID {
		return nil, fmt.Errorf("rollback pre-image UID mismatch")
	}
	resourceVersion, err := kubeObjectResourceVersion(current)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(restore)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	metadata, _ := object["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		object["metadata"] = metadata
	}
	metadata["uid"] = uid
	metadata["resourceVersion"] = resourceVersion
	return object, nil
}

func (a *agent) rollbackRestoreDryRun(ctx context.Context, task controlplane.BaselineTask, resource controlplane.BaselineTaskResource, restore, current map[string]any, expectedUID string) (int, []string, string) {
	path, err := schemaResourcePath(task.Inventory, resource)
	if err != nil {
		return 0, nil, err.Error()
	}
	update, err := rollbackRestoreUpdateObject(restore, current, expectedUID)
	if err != nil {
		return 0, nil, err.Error()
	}
	raw, err := json.Marshal(update)
	if err != nil {
		return 0, nil, err.Error()
	}
	query := "?dryRun=All&fieldValidation=Strict"
	req, err := a.kubeRequest(ctx, http.MethodPut, path+query, bytes.NewReader(raw), "application/json")
	if err != nil {
		return 0, nil, err.Error()
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer res.Body.Close()
	warnings := boundedWarningHeaders(res.Header.Values("Warning"))
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	if res.StatusCode/100 != 2 {
		return res.StatusCode, warnings, fmt.Sprintf("status=%d body=%s", res.StatusCode, string(body))
	}
	return res.StatusCode, warnings, ""
}

func (a *agent) restoreKubeObjectWithUID(ctx context.Context, path string, restore, current map[string]any, expectedUID string) error {
	update, err := rollbackRestoreUpdateObject(restore, current, expectedUID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(update)
	if err != nil {
		return err
	}
	req, err := a.kubeRequest(ctx, http.MethodPut, path, bytes.NewReader(raw), "application/json")
	if err != nil {
		return err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	if res.StatusCode == http.StatusConflict {
		return fmt.Errorf("rollback pre-image UID/resourceVersion conflict for %s: %s", path, string(body))
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("rollback pre-image update %s: status=%d body=%s", path, res.StatusCode, string(body))
	}
	return nil
}

func (a *agent) rollbackFeasibility(ctx context.Context, task controlplane.BaselineTask, resource controlplane.BaselineTaskResource, change controlplane.BaselinePlanChange, current map[string]any) controlplane.PlanRollbackResource {
	item := controlplane.PlanRollbackResource{Resource: resource.Kind + "/" + resource.Name, ChangeAction: change.Action, Status: "FAIL", AuthorizationStatus: "NOT_EXECUTED", DryRunStatus: "NOT_EXECUTED", SchemaIndexVersion: task.Inventory.SchemaDiscoveryVersion, SchemaIndexDigest: task.Inventory.SchemaDiscoveryDigest}
	fail := func(message string) controlplane.PlanRollbackResource {
		item.FailureDigest = digestText(message)
		return item
	}
	switch strings.ToUpper(change.Action) {
	case "NOOP":
		observedUID, err := kubeObjectUID(current)
		if err != nil {
			return fail(err.Error())
		}
		observed, err := sanitizeRollbackObject(resource, current)
		if err != nil {
			return fail(err.Error())
		}
		item.ObservedUID = observedUID
		item.ObservedObjectDigest = rollbackObjectDigest(observed)
		item.Strategy, item.Status, item.AuthorizationStatus, item.DryRunStatus = "NO_ACTION", "PASS", "NOT_REQUIRED", "NOT_REQUIRED"
		return item
	case "ADD":
		item.Strategy, item.DryRunStatus = "DELETE_CREATED_RESOURCE", "NOT_APPLICABLE"
		allowed, status, reason := a.rollbackDeleteAuthorization(ctx, task, resource)
		item.HTTPStatus = status
		if !allowed {
			return fail(reason)
		}
		item.AuthorizationStatus, item.Status = "PASS", "PASS"
		return item
	case "UPDATE", "DELETE":
		item.Strategy = "RESTORE_PREIMAGE"
		observedUID, err := kubeObjectUID(current)
		if err != nil {
			return fail(err.Error())
		}
		restore, err := sanitizeRollbackObject(resource, current)
		if err != nil {
			return fail(err.Error())
		}
		item.ObservedUID = observedUID
		item.ObservedObjectDigest = rollbackObjectDigest(restore)
		item.RestoreObject = restore
		item.RestoreObjectDigest = item.ObservedObjectDigest
		status, warnings, reason := a.rollbackRestoreDryRun(ctx, task, resource, restore, current, observedUID)
		item.HTTPStatus, item.Warnings = status, warnings
		if reason != "" {
			return fail(reason)
		}
		item.AuthorizationStatus, item.DryRunStatus, item.Status = "PASS", "PASS", "PASS"
		return item
	default:
		item.Strategy = "UNSUPPORTED"
		return fail("unsupported change action: " + change.Action)
	}
}

func digestText(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func boundedWarningHeaders(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > 512 {
			value = value[:512]
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
		if len(out) == 8 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func baselineRollbackByResource(task controlplane.BaselineTask) (map[string]controlplane.PlanRollbackResource, error) {
	if len(task.Rollback) != len(task.Resources) {
		return nil, fmt.Errorf("rollback evidence is incomplete; re-plan before apply")
	}
	out := make(map[string]controlplane.PlanRollbackResource, len(task.Rollback))
	for _, item := range task.Rollback {
		if item.Resource == "" || out[item.Resource].Resource != "" {
			return nil, fmt.Errorf("rollback evidence identity is invalid; re-plan before apply")
		}
		out[item.Resource] = item
	}
	return out, nil
}

func baselineObservedObjectDigest(resource controlplane.BaselineTaskResource, current map[string]any) (string, error) {
	observed, err := sanitizeRollbackObject(resource, current)
	if err != nil {
		return "", err
	}
	return rollbackObjectDigest(observed), nil
}

func (a *agent) applyBaselineResource(ctx context.Context, task controlplane.BaselineTask, resource controlplane.BaselineTaskResource, rollback controlplane.PlanRollbackResource) error {
	path := baselineResourcePaths[resource.Kind+"/"+resource.Name]
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("inspect %s before apply: %w", rollback.Resource, err)
	}
	switch rollback.Strategy {
	case "NO_ACTION":
		if !found {
			return fmt.Errorf("planned NOOP resource disappeared; re-plan before apply: %s", rollback.Resource)
		}
		uid, uidErr := kubeObjectUID(current)
		observedDigest, digestErr := baselineObservedObjectDigest(resource, current)
		if uidErr != nil || digestErr != nil || uid != rollback.ObservedUID || observedDigest != rollback.ObservedObjectDigest || objectDesiredDigest(current) != task.DesiredDigest {
			return fmt.Errorf("planned NOOP resource changed after planning; re-plan before apply: %s", rollback.Resource)
		}
		return nil
	case "DELETE_CREATED_RESOURCE":
		if found {
			if !baselineObjectOwnedByTask(current, task) || !kubeObjectContainsDesiredFields(current, resource.Object) {
				return fmt.Errorf("planned ADD target changed or appeared outside the approved state; re-plan before apply: %s", rollback.Resource)
			}
			return a.serverSideApplyConditional(ctx, path, resource.Object, current)
		}
		collectionPath := strings.TrimSuffix(path, "/"+resource.Name)
		created, conflict, createErr := a.createKubeObject(ctx, collectionPath, resource.Object)
		if createErr != nil {
			return createErr
		}
		if created {
			return nil
		}
		if !conflict {
			return fmt.Errorf("baseline resource create returned no result: %s", rollback.Resource)
		}
		current, found, err = a.getKubeObject(ctx, path)
		if err != nil || !found {
			return fmt.Errorf("verify concurrent baseline resource create %s: found=%v err=%v", rollback.Resource, found, err)
		}
		if !baselineObjectOwnedByTask(current, task) || !kubeObjectContainsDesiredFields(current, resource.Object) {
			return fmt.Errorf("refusing to adopt concurrently created or drifted baseline resource: %s", rollback.Resource)
		}
		return a.serverSideApplyConditional(ctx, path, resource.Object, current)
	case "RESTORE_PREIMAGE":
		if !found {
			return fmt.Errorf("planned UPDATE target disappeared; re-plan before apply: %s", rollback.Resource)
		}
		uid, uidErr := kubeObjectUID(current)
		if uidErr != nil || uid != rollback.ObservedUID {
			return fmt.Errorf("planned UPDATE target identity changed; re-plan before apply: %s", rollback.Resource)
		}
		observedDigest, digestErr := baselineObservedObjectDigest(resource, current)
		if digestErr != nil {
			return fmt.Errorf("inspect planned UPDATE target %s: %w", rollback.Resource, digestErr)
		}
		if observedDigest != rollback.ObservedObjectDigest {
			// A retry may observe the exact desired state from a prior successful
			// SSA, but ownership labels alone are not state authority. Any other
			// post-plan mutation must force a re-plan.
			if !baselineObjectOwnedByTask(current, task) || !kubeObjectContainsDesiredFields(current, resource.Object) {
				return fmt.Errorf("planned UPDATE target changed after planning; re-plan before apply: %s", rollback.Resource)
			}
		}
		return a.serverSideApplyConditional(ctx, path, resource.Object, current)
	default:
		return fmt.Errorf("unsupported rollback strategy %s for apply resource %s", rollback.Strategy, rollback.Resource)
	}
}

func (a *agent) applyBaseline(ctx context.Context, task controlplane.BaselineTask) controlplane.BaselineTaskResult {
	if err := controlplane.ValidateEvidenceCollectionPlanSemantics(task.EvidencePlan, task.DeploymentID, task.Resources); err != nil || !strings.HasPrefix(task.PlanImpactDigest, "sha256:") {
		if err == nil {
			err = fmt.Errorf("plan impact digest is missing")
		}
		return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: "evidence collection contract is invalid; re-plan before apply: " + err.Error()}
	}
	rollbackByResource, err := baselineRollbackByResource(task)
	if err != nil {
		return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: err.Error()}
	}
	for _, resource := range task.Resources {
		item, ok := rollbackByResource[resource.Kind+"/"+resource.Name]
		if !ok {
			return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: "rollback evidence is missing for resource; re-plan before apply"}
		}
		if err := a.applyBaselineResource(ctx, task, resource, item); err != nil {
			return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: err.Error()}
		}
	}
	for _, resource := range task.Resources {
		current, found, err := a.getKubeObject(ctx, baselineResourcePaths[resource.Kind+"/"+resource.Name])
		if err != nil || !found {
			return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: fmt.Sprintf("verify %s: %v", resource.Name, err)}
		}
		if objectDesiredDigest(current) != task.DesiredDigest {
			return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, Error: "managed resource digest annotation mismatch after apply"}
		}
	}
	observed := a.currentBaselineDigest(ctx)
	if observed != task.DesiredDigest {
		return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, ObservedDigest: observed, Error: "baseline convergence digest does not match desired digest"}
	}
	evidence, err := a.collectBaselineEvidence(ctx, task, observed)
	if err != nil {
		return controlplane.BaselineTaskResult{Action: "APPLY", Success: false, ObservedDigest: observed, Error: "evidence collection failed: " + err.Error()}
	}
	return controlplane.BaselineTaskResult{Action: "APPLY", Success: true, ObservedDigest: observed, Evidence: evidence}
}

func baselineEvidencePayload(payload map[string]any) (string, int64) {
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), int64(len(raw))
}

func (a *agent) collectBaselineEvidence(ctx context.Context, task controlplane.BaselineTask, observed string) ([]controlplane.BaselineEvidenceArtifact, error) {
	byResource := map[string]controlplane.BaselineTaskResource{}
	for _, resource := range task.Resources {
		byResource[resource.Kind+"/"+resource.Name] = resource
	}
	out := make([]controlplane.BaselineEvidenceArtifact, 0, len(task.EvidencePlan.Artifacts))
	for _, spec := range task.EvidencePlan.Artifacts {
		var payload map[string]any
		switch spec.Kind {
		case "KUBE_RESOURCE_READBACK":
			resource, ok := byResource[spec.Resource]
			if !ok {
				return nil, fmt.Errorf("planned evidence resource %s is not part of task", spec.Resource)
			}
			path := baselineResourcePaths[resource.Kind+"/"+resource.Name]
			current, found, err := a.getKubeObject(ctx, path)
			if err != nil || !found {
				return nil, fmt.Errorf("read back %s: found=%v err=%v", spec.Resource, found, err)
			}
			payload = current
		case "BASELINE_CONVERGENCE":
			payload = map[string]any{
				"deploymentId": task.DeploymentID, "baselineId": task.BaselineID, "baselineVersion": task.BaselineVersion,
				"desiredDigest": task.DesiredDigest, "observedDigest": observed, "planImpactDigest": task.PlanImpactDigest,
				"evidencePlanDigest": task.EvidencePlan.Digest, "resourceCount": len(task.Resources), "status": "CONVERGED",
			}
		default:
			return nil, fmt.Errorf("unsupported planned evidence kind %s", spec.Kind)
		}
		digest, size := baselineEvidencePayload(payload)
		out = append(out, controlplane.BaselineEvidenceArtifact{Key: spec.Key, Kind: spec.Kind, Resource: spec.Resource, Authority: spec.Authority, Digest: digest, MediaType: spec.MediaType, Location: spec.OutputLocation, Size: size, Required: spec.Required, RetentionDays: spec.RetentionDays, Payload: payload})
	}
	if err := controlplane.ValidateCollectedBaselineEvidence(task.EvidencePlan, task.DeploymentID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func baselineObjectOwnedByTask(object map[string]any, task controlplane.BaselineTask) bool {
	metadata, _ := object["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	return annotations["platform.4so.io/managed"] == "true" &&
		annotations["platform.4so.io/deployment-id"] == task.DeploymentID &&
		annotations["platform.4so.io/desired-digest"] == task.DesiredDigest &&
		labels["app.kubernetes.io/managed-by"] == "4so-platform-factory"
}

func (a *agent) rollbackBaseline(ctx context.Context, task controlplane.BaselineTask) controlplane.BaselineTaskResult {
	if len(task.Rollback) == 0 {
		return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback feasibility evidence is missing; re-plan before rollback"}
	}
	desiredByResource := make(map[string]controlplane.BaselineTaskResource, len(task.Resources))
	for _, resource := range task.Resources {
		desiredByResource[resource.Kind+"/"+resource.Name] = resource
	}
	for i := len(task.Rollback) - 1; i >= 0; i-- {
		item := task.Rollback[i]
		path, ok := baselineResourcePaths[item.Resource]
		if !ok {
			return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback resource path is unknown: " + item.Resource}
		}
		switch item.Strategy {
		case "NO_ACTION":
			continue
		case "DELETE_CREATED_RESOURCE":
			desired, desiredOK := desiredByResource[item.Resource]
			if !desiredOK {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback desired resource is missing: " + item.Resource}
			}
			current, found, err := a.getKubeObject(ctx, path)
			if err != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "inspect rollback deletion " + item.Resource + ": " + err.Error()}
			}
			if !found {
				continue
			}
			if !baselineObjectOwnedByTask(current, task) || !kubeObjectContainsDesiredFields(current, desired.Object) {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "refusing rollback deletion of resource whose approved applied state changed: " + item.Resource}
			}
			uid, uidErr := kubeObjectUID(current)
			if uidErr != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback deletion UID " + item.Resource + ": " + uidErr.Error()}
			}
			resourceVersion, rvErr := kubeObjectResourceVersion(current)
			if rvErr != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback deletion resourceVersion " + item.Resource + ": " + rvErr.Error()}
			}
			if err := a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, path, uid, resourceVersion, 30*time.Second); err != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "confirm rollback deletion " + item.Resource + ": " + err.Error()}
			}
		case "RESTORE_PREIMAGE":
			desired, desiredOK := desiredByResource[item.Resource]
			if !desiredOK {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback desired resource is missing: " + item.Resource}
			}
			if item.Status != "PASS" || strings.TrimSpace(item.ObservedUID) == "" || item.RestoreObject == nil || rollbackObjectDigest(item.RestoreObject) != item.RestoreObjectDigest {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "rollback restore snapshot failed integrity validation for " + item.Resource}
			}
			current, found, err := a.getKubeObject(ctx, path)
			if err != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "inspect rollback restore " + item.Resource + ": " + err.Error()}
			}
			if !found {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "refusing rollback restore because the original resource no longer exists: " + item.Resource}
			}
			uid, uidErr := kubeObjectUID(current)
			if uidErr != nil || uid != item.ObservedUID {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "refusing rollback restore because the original resource identity changed: " + item.Resource}
			}
			restoreMetadata, _ := item.RestoreObject["metadata"].(map[string]any)
			currentRestore, sanitizeErr := sanitizeRollbackObject(controlplane.BaselineTaskResource{APIVersion: fmt.Sprint(item.RestoreObject["apiVersion"]), Kind: fmt.Sprint(item.RestoreObject["kind"]), Namespace: fmt.Sprint(restoreMetadata["namespace"]), Name: fmt.Sprint(restoreMetadata["name"])}, current)
			if sanitizeErr == nil && rollbackObjectDigest(currentRestore) == item.RestoreObjectDigest {
				continue
			}
			if !baselineObjectOwnedByTask(current, task) || !kubeObjectContainsDesiredFields(current, desired.Object) {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "refusing rollback restore of resource whose approved applied state changed: " + item.Resource}
			}
			if err := a.restoreKubeObjectWithUID(ctx, path, item.RestoreObject, current, item.ObservedUID); err != nil {
				return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "restore pre-image " + item.Resource + ": " + err.Error()}
			}
		default:
			return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: false, Error: "unsupported rollback strategy for " + item.Resource}
		}
	}
	return controlplane.BaselineTaskResult{Action: "ROLLBACK", Success: true, ObservedDigest: ""}
}

func kubeObjectContainsDesiredFields(current, desired any) bool {
	switch want := desired.(type) {
	case map[string]any:
		have, ok := current.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range want {
			currentValue, exists := have[key]
			if !exists || !kubeObjectContainsDesiredFields(currentValue, value) {
				return false
			}
		}
		return true
	case []any:
		have, ok := current.([]any)
		if !ok || len(have) != len(want) {
			return false
		}
		for i := range want {
			if !kubeObjectContainsDesiredFields(have[i], want[i]) {
				return false
			}
		}
		return true
	default:
		if haveNumber, ok := kubeJSONNumber(current); ok {
			wantNumber, wantOK := kubeJSONNumber(desired)
			return wantOK && haveNumber == wantNumber
		}
		return reflect.DeepEqual(current, desired)
	}
}

func kubeJSONNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		v, err := typed.Float64()
		return v, err == nil
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case float32:
		return float64(typed), true
	case float64:
		return typed, true
	default:
		return 0, false
	}
}

func objectDesiredDigest(object map[string]any) string {
	metadata, _ := object["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	v, _ := annotations["platform.4so.io/desired-digest"].(string)
	return v
}
func (a *agent) currentBaselineDigest(ctx context.Context) string {
	object, found, err := a.getKubeObject(ctx, baselineResourcePaths["ConfigMap/4so-baseline-revision"])
	if err != nil || !found {
		return ""
	}
	data, _ := object["data"].(map[string]any)
	v, _ := data["desiredDigest"].(string)
	return v
}

func (a *agent) getKubeObject(ctx context.Context, path string) (map[string]any, bool, error) {
	req, err := a.kubeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, false, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, false, fmt.Errorf("Kubernetes API %s: %s", res.Status, string(raw))
	}
	var out map[string]any
	if err = json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}
func (a *agent) createKubeObject(ctx context.Context, collectionPath string, object map[string]any) (bool, bool, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return false, false, err
	}
	req, err := a.kubeRequest(ctx, http.MethodPost, collectionPath, bytes.NewReader(raw), "application/json")
	if err != nil {
		return false, false, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return false, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusConflict {
		return false, true, nil
	}
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return false, false, fmt.Errorf("create %s: %s", res.Status, string(body))
	}
	return true, false, nil
}

func (a *agent) serverSideApplyConditional(ctx context.Context, path string, object, current map[string]any) error {
	resourceVersion, err := kubeObjectResourceVersion(current)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return err
	}
	var conditional map[string]any
	if err = json.Unmarshal(raw, &conditional); err != nil {
		return err
	}
	metadata, _ := conditional["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		conditional["metadata"] = metadata
	}
	metadata["resourceVersion"] = resourceVersion
	raw, err = json.Marshal(conditional)
	if err != nil {
		return err
	}
	req, err := a.kubeRequest(ctx, http.MethodPatch, path+"?fieldManager=4so-platform-agent&force=true", bytes.NewReader(raw), "application/apply-patch+yaml")
	if err != nil {
		return err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	if res.StatusCode == http.StatusConflict {
		return fmt.Errorf("conditional server-side apply resourceVersion conflict for %s: %s", path, string(body))
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("conditional server-side apply %s: status=%d body=%s", path, res.StatusCode, string(body))
	}
	return nil
}

func kubeObjectUID(object map[string]any) (string, error) {
	metadata, _ := object["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", fmt.Errorf("Kubernetes object UID is missing")
	}
	return uid, nil
}

func (a *agent) requestKubeObjectDeletionWithPreconditions(ctx context.Context, path, uid, resourceVersion string) (bool, error) {
	uid = strings.TrimSpace(uid)
	resourceVersion = strings.TrimSpace(resourceVersion)
	if uid == "" {
		return false, fmt.Errorf("delete UID precondition is required")
	}
	preconditions := map[string]any{"uid": uid}
	if resourceVersion != "" {
		preconditions["resourceVersion"] = resourceVersion
	}
	body := map[string]any{
		"apiVersion":    "v1",
		"kind":          "DeleteOptions",
		"preconditions": preconditions,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	req, err := a.kubeRequest(ctx, http.MethodDelete, path, bytes.NewReader(raw), "application/json")
	if err != nil {
		return false, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return true, nil
	}
	if res.StatusCode == http.StatusConflict {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return false, fmt.Errorf("delete identity precondition conflict for %s: %s", path, string(body))
	}
	if res.StatusCode/100 == 2 {
		return false, nil
	}
	rawBody, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return false, fmt.Errorf("delete %s: %s", res.Status, string(rawBody))
}

func (a *agent) deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx context.Context, path, uid, resourceVersion string, timeout time.Duration) error {
	if strings.TrimSpace(resourceVersion) == "" {
		return fmt.Errorf("delete resourceVersion precondition is required")
	}
	alreadyAbsent, err := a.requestKubeObjectDeletionWithPreconditions(ctx, path, uid, resourceVersion)
	if err != nil {
		return err
	}
	if alreadyAbsent {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		current, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			return fmt.Errorf("observe deletion %s: %w", path, err)
		}
		if !found {
			return nil
		}
		currentUID, uidErr := kubeObjectUID(current)
		if uidErr != nil {
			return fmt.Errorf("observe deletion %s: %w", path, uidErr)
		}
		if currentUID != uid {
			return fmt.Errorf("Kubernetes object %s was replaced during deletion", path)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for deletion of %s", path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (a *agent) kubeRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Request, error) {
	serviceToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://kubernetes.default.svc"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}
func (a *agent) reportBaselineTask(ctx context.Context, task controlplane.BaselineTask, result controlplane.BaselineTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/baseline-tasks/" + task.DeploymentID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.DeploymentRev))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("hub result API %s: %s", res.Status, string(body))
	}
	return nil
}

var certificationAllowedResources = map[string]string{
	"ResourceQuota/4so-baseline-quota":       "resourcequotas",
	"LimitRange/4so-baseline-limits":         "limitranges",
	"NetworkPolicy/4so-default-deny-ingress": "networkpolicies",
	"ServiceAccount/4so-baseline-observer":   "serviceaccounts",
	"ConfigMap/4so-catalog-render-revision":  "configmaps",
}

func (a *agent) processRuntimeCertificationTask(ctx context.Context) error {
	task, ok, err := a.nextRuntimeCertificationTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.runRuntimeCertification(execCtx, task)
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportRuntimeCertificationTask(ctx, task, result)
}

func (a *agent) nextRuntimeCertificationTask(ctx context.Context) (controlplane.RuntimeCertificationTask, bool, error) {
	var task controlplane.RuntimeCertificationTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/runtime-certification-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("runtime certification task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

const (
	componentRuntimeTaskMaxResources = 256
	componentRuntimeTaskMaxBytes     = 4 << 20
)

func componentRuntimeResourcePath(resource map[string]any) (string, string, error) {
	apiVersion, _ := resource["apiVersion"].(string)
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	apiVersion, kind, name, namespace = strings.TrimSpace(apiVersion), strings.TrimSpace(kind), strings.TrimSpace(name), strings.TrimSpace(namespace)
	if apiVersion == "" || kind == "" || name == "" {
		return "", "", fmt.Errorf("component runtime resource identity is incomplete")
	}
	escape := url.PathEscape
	identity := apiVersion + "/" + kind + "/" + namespace + "/" + name
	type mapping struct {
		collection string
		namespaced bool
	}
	mappings := map[string]mapping{
		"apiextensions.k8s.io/v1|CustomResourceDefinition":                 {"/apis/apiextensions.k8s.io/v1/customresourcedefinitions", false},
		"admissionregistration.k8s.io/v1|ValidatingAdmissionPolicy":        {"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", false},
		"admissionregistration.k8s.io/v1|ValidatingAdmissionPolicyBinding": {"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings", false},
		"v1|ServiceAccount":                               {"/api/v1/namespaces/%s/serviceaccounts", true},
		"rbac.authorization.k8s.io/v1|ClusterRole":        {"/apis/rbac.authorization.k8s.io/v1/clusterroles", false},
		"rbac.authorization.k8s.io/v1|ClusterRoleBinding": {"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", false},
		"rbac.authorization.k8s.io/v1|Role":               {"/apis/rbac.authorization.k8s.io/v1/namespaces/%s/roles", true},
		"rbac.authorization.k8s.io/v1|RoleBinding":        {"/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings", true},
		"apps/v1|Deployment":                              {"/apis/apps/v1/namespaces/%s/deployments", true},
	}
	m, ok := mappings[apiVersion+"|"+kind]
	if !ok {
		return "", "", fmt.Errorf("component runtime resource %s/%s is outside executable allowlist", apiVersion, kind)
	}
	collection := m.collection
	if m.namespaced {
		if namespace == "" {
			return "", "", fmt.Errorf("component runtime resource %s requires namespace", identity)
		}
		collection = fmt.Sprintf(collection, escape(namespace))
	} else if namespace != "" {
		return "", "", fmt.Errorf("cluster-scoped component runtime resource %s must not set namespace", identity)
	}
	return collection + "/" + escape(name), identity, nil
}

func certificationResourcePath(task controlplane.RuntimeCertificationTask, resource map[string]any) (string, string, error) {
	if task.Profile == controlplane.RuntimeCertificationComponentV1 {
		return componentRuntimeResourcePath(resource)
	}
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if kind == "Namespace" {
		if name != task.Namespace || namespace != "" {
			return "", "", fmt.Errorf("namespace resource identity is not allowed")
		}
		return "/api/v1/namespaces/" + name, kind + "/" + name, nil
	}
	key := kind + "/" + name
	if certificationAllowedResources[key] == "" || namespace != task.Namespace {
		return "", "", fmt.Errorf("resource %s is outside runtime certification allowlist", key)
	}
	switch kind {
	case "NetworkPolicy":
		return "/apis/networking.k8s.io/v1/namespaces/" + task.Namespace + "/networkpolicies/" + name, key, nil
	default:
		return "/api/v1/namespaces/" + task.Namespace + "/" + certificationAllowedResources[key] + "/" + name, key, nil
	}
}

func validateRuntimeCertificationTask(task controlplane.RuntimeCertificationTask) error {
	if task.RunID == "" || task.RunRevision < 1 || task.TaskFenceToken < 1 || task.TaskAttempt < 1 || task.CatalogReleaseID == "" || task.Namespace == "" || strings.TrimSpace(task.CleanupToken) == "" || len(task.Resources) == 0 {
		return fmt.Errorf("runtime certification task identity is incomplete")
	}
	if task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("runtime certification task lease is absent or expired")
	}
	if !strings.HasPrefix(task.InventoryDigest, "sha256:") || !strings.HasPrefix(task.EnvironmentFingerprint, "sha256:") || !strings.HasPrefix(task.ManifestDigest, "sha256:") || !strings.HasPrefix(task.SourceLockDigest, "sha256:") || !strings.HasPrefix(task.RenderedDigest, "sha256:") {
		return fmt.Errorf("runtime certification context is not digest-bound")
	}
	if task.Profile != controlplane.RuntimeCertificationFoundationV1 && task.Profile != controlplane.RuntimeCertificationObservabilityV1 && task.Profile != controlplane.RuntimeCertificationTargetV1 && task.Profile != controlplane.RuntimeCertificationComponentV1 {
		return fmt.Errorf("unsupported runtime certification profile")
	}
	if task.Phase != controlplane.RuntimeCertificationPhaseInstall && task.Phase != controlplane.RuntimeCertificationPhaseVerify && task.Phase != controlplane.RuntimeCertificationPhaseFailure && task.Phase != controlplane.RuntimeCertificationPhaseRemove {
		return fmt.Errorf("unsupported runtime certification phase")
	}
	if task.Profile != controlplane.RuntimeCertificationComponentV1 && (task.Phase == controlplane.RuntimeCertificationPhaseFailure || task.Phase == controlplane.RuntimeCertificationPhaseRemove) {
		return fmt.Errorf("extended runtime certification phases are component-only")
	}
	if len(task.Resources) > componentRuntimeTaskMaxResources {
		return fmt.Errorf("runtime certification task exceeds resource limit")
	}
	rawResources, err := json.Marshal(task.Resources)
	if err != nil || len(rawResources) > componentRuntimeTaskMaxBytes {
		return fmt.Errorf("runtime certification task exceeds serialized payload limit")
	}
	if task.Profile == controlplane.RuntimeCertificationComponentV1 {
		if strings.TrimSpace(task.ComponentName) == "" || strings.TrimSpace(task.ComponentRelease) == "" {
			return fmt.Errorf("component runtime certification identity is incomplete")
		}
	} else if strings.TrimSpace(task.ComponentName) != "" || strings.TrimSpace(task.ComponentRelease) != "" {
		return fmt.Errorf("component runtime identity is not allowed for non-component profile")
	}
	seen := map[string]bool{}
	for _, resource := range task.Resources {
		_, identity, err := certificationResourcePath(task, resource)
		if err != nil {
			return err
		}
		if seen[identity] {
			return fmt.Errorf("duplicate certification resource %s", identity)
		}
		seen[identity] = true
		metadata, _ := resource["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		if labels["app.kubernetes.io/managed-by"] != "4so-platform-factory" {
			return fmt.Errorf("resource %s is missing managed-by identity", identity)
		}
	}
	if task.Profile != controlplane.RuntimeCertificationComponentV1 && len(task.Resources) != 6 {
		return fmt.Errorf("foundation certification requires exactly six allowlisted resources")
	}
	return nil
}

func (a *agent) runRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	if err := validateRuntimeCertificationTask(task); err != nil {
		result.Error = err.Error()
		return result
	}
	if task.Profile == controlplane.RuntimeCertificationComponentV1 {
		switch task.Phase {
		case controlplane.RuntimeCertificationPhaseInstall:
			return a.installComponentRuntimeCertification(ctx, task)
		case controlplane.RuntimeCertificationPhaseVerify:
			return a.verifyComponentRuntimeCertification(ctx, task)
		case controlplane.RuntimeCertificationPhaseFailure:
			return a.failureRecoverComponentRuntimeCertification(ctx, task)
		case controlplane.RuntimeCertificationPhaseRemove:
			return a.removeComponentRuntimeCertification(ctx, task)
		}
	}
	if task.Phase == controlplane.RuntimeCertificationPhaseInstall {
		return a.installRuntimeCertification(ctx, task)
	}
	return a.verifyRuntimeCertification(ctx, task)
}

func runtimeCertificationNamespaceOwnedByTask(object map[string]any, task controlplane.RuntimeCertificationTask) bool {
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	return labels["app.kubernetes.io/managed-by"] == "4so-platform-factory" &&
		labels["platform.4so.io/catalog-release-id"] == task.CatalogReleaseID &&
		labels["platform.4so.io/component"] == "secure-namespace-foundation"
}

func runtimeCertificationNamespaceResource(task controlplane.RuntimeCertificationTask) (map[string]any, error) {
	for _, resource := range task.Resources {
		kind, _ := resource["kind"].(string)
		metadata, _ := resource["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if kind == "Namespace" && name == task.Namespace {
			return resource, nil
		}
	}
	return nil, fmt.Errorf("runtime certification namespace resource is missing")
}

func (a *agent) ensureRuntimeCertificationNamespace(ctx context.Context, task controlplane.RuntimeCertificationTask) (bool, error) {
	resource, err := runtimeCertificationNamespaceResource(task)
	if err != nil {
		return false, err
	}
	path := "/api/v1/namespaces/" + task.Namespace
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return false, err
	}
	if found {
		if task.TaskAttempt <= 1 || !runtimeCertificationNamespaceOwnedByTask(current, task) {
			return false, fmt.Errorf("fresh install target namespace already exists")
		}
		if err := a.serverSideApplyConditional(ctx, path, resource, current); err != nil {
			return false, err
		}
		return true, nil
	}
	created, conflict, err := a.createKubeObject(ctx, "/api/v1/namespaces", resource)
	if err != nil {
		return false, err
	}
	if created {
		return false, nil
	}
	if !conflict {
		return false, fmt.Errorf("runtime certification namespace create returned no result")
	}
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil {
		return false, fmt.Errorf("verify concurrent runtime certification namespace create: %w", err)
	}
	if !found || task.TaskAttempt <= 1 || !runtimeCertificationNamespaceOwnedByTask(current, task) {
		return false, fmt.Errorf("refusing to adopt concurrently created runtime certification namespace")
	}
	if err := a.serverSideApplyConditional(ctx, path, resource, current); err != nil {
		return false, err
	}
	return true, nil
}

func metadataString(metadata map[string]any, key string) string {
	value, ok := metadata[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func runtimeCertificationResourceOwnedByDesired(current, desired map[string]any) bool {
	currentMeta, _ := current["metadata"].(map[string]any)
	desiredMeta, _ := desired["metadata"].(map[string]any)
	if metadataString(currentMeta, "name") != metadataString(desiredMeta, "name") || metadataString(currentMeta, "namespace") != metadataString(desiredMeta, "namespace") {
		return false
	}
	currentLabels, _ := currentMeta["labels"].(map[string]any)
	desiredLabels, _ := desiredMeta["labels"].(map[string]any)
	for _, key := range []string{"app.kubernetes.io/managed-by", "platform.4so.io/component", "platform.4so.io/catalog-release-id", "platform.4so.io/runtime-certification-profile"} {
		if desiredLabels[key] != nil && currentLabels[key] != desiredLabels[key] {
			return false
		}
	}
	return true
}

func kubeCollectionPath(path string) (string, error) {
	idx := strings.LastIndex(strings.TrimRight(path, "/"), "/")
	if idx <= 0 {
		return "", fmt.Errorf("Kubernetes object path has no collection parent: %s", path)
	}
	return path[:idx], nil
}

func (a *agent) ensureRuntimeCertificationResource(ctx context.Context, task controlplane.RuntimeCertificationTask, resource map[string]any) error {
	path, identity, err := certificationResourcePath(task, resource)
	if err != nil {
		return err
	}
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("inspect certification resource %s: %w", identity, err)
	}
	if found {
		if task.TaskAttempt <= 1 || !runtimeCertificationResourceOwnedByDesired(current, resource) {
			return fmt.Errorf("fresh certification resource %s already exists or is not owned by this certification", identity)
		}
		return a.serverSideApplyConditional(ctx, path, resource, current)
	}
	collection, err := kubeCollectionPath(path)
	if err != nil {
		return err
	}
	created, conflict, err := a.createKubeObject(ctx, collection, resource)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	if !conflict {
		return fmt.Errorf("certification resource %s create returned no result", identity)
	}
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("verify concurrent certification resource create %s: %w", identity, err)
	}
	if !found || task.TaskAttempt <= 1 || !runtimeCertificationResourceOwnedByDesired(current, resource) {
		return fmt.Errorf("refusing to adopt concurrently created certification resource %s", identity)
	}
	return a.serverSideApplyConditional(ctx, path, resource, current)
}

type runtimeCertificationCleanupRef struct {
	Path         string
	Owner        string
	CleanupToken string
	UID          string
}

func runtimeCertificationEphemeralOwnedBy(object map[string]any, owner, cleanupToken string) bool {
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	token := strings.TrimSpace(cleanupToken)
	if token == "" || strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/runtime-certification"])) != strings.TrimSpace(owner) {
		return false
	}
	return strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/runtime-cleanup-token"])) == token
}

// ensureRuntimeCertificationEphemeralObject uses create-or-verify semantics for
// runtime-certification resources. It never force-adopts a same-name object.
func (a *agent) ensureRuntimeCertificationEphemeralObject(ctx context.Context, path string, object map[string]any, owner, cleanupToken string) (string, error) {
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	token := strings.TrimSpace(cleanupToken)
	if token == "" {
		return "", fmt.Errorf("runtime certification cleanup token is required for %s", path)
	}
	if labels == nil {
		labels = map[string]any{}
		metadata["labels"] = labels
	}
	labels["platform.4so.io/runtime-cleanup-token"] = token
	if strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/runtime-certification"])) != strings.TrimSpace(owner) {
		return "", fmt.Errorf("runtime certification object %s is missing expected ownership label", path)
	}
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return "", err
	}
	if found {
		if !runtimeCertificationEphemeralOwnedBy(current, owner, token) || !kubeObjectContainsDesiredFields(current, object) {
			return "", fmt.Errorf("runtime certification object %s already exists with foreign or drifted state", path)
		}
		return kubeObjectUID(current)
	}
	collection, err := kubeCollectionPath(path)
	if err != nil {
		return "", err
	}
	created, conflict, err := a.createKubeObject(ctx, collection, object)
	if err != nil {
		return "", err
	}
	if !created && !conflict {
		return "", fmt.Errorf("runtime certification object %s create returned no result", path)
	}
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil {
		return "", err
	}
	if !found || !runtimeCertificationEphemeralOwnedBy(current, owner, token) || !kubeObjectContainsDesiredFields(current, object) {
		if conflict {
			return "", fmt.Errorf("refusing to adopt concurrently created runtime certification object %s", path)
		}
		return "", fmt.Errorf("runtime certification object %s was not created with expected identity", path)
	}
	return kubeObjectUID(current)
}

func (a *agent) cleanupRuntimeCertificationEphemeralObject(ctx context.Context, ref runtimeCertificationCleanupRef, timeout time.Duration) error {
	if strings.TrimSpace(ref.Path) == "" {
		return nil
	}
	current, found, err := a.getKubeObject(ctx, ref.Path)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !runtimeCertificationEphemeralOwnedBy(current, ref.Owner, ref.CleanupToken) {
		return fmt.Errorf("refusing to delete runtime certification object %s with foreign ownership", ref.Path)
	}
	uid, err := kubeObjectUID(current)
	if err != nil {
		return err
	}
	if strings.TrimSpace(ref.UID) != "" && uid != strings.TrimSpace(ref.UID) {
		return fmt.Errorf("runtime certification object %s was replaced before cleanup", ref.Path)
	}
	rv, err := kubeObjectResourceVersion(current)
	if err != nil {
		return err
	}
	return a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, ref.Path, uid, rv, timeout)
}

func (a *agent) runtimeCertificationCleanupRef(ctx context.Context, path, owner, cleanupToken string) (runtimeCertificationCleanupRef, error) {
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return runtimeCertificationCleanupRef{}, err
	}
	token := strings.TrimSpace(cleanupToken)
	if token == "" {
		return runtimeCertificationCleanupRef{}, fmt.Errorf("runtime certification cleanup token is required for %s", path)
	}
	if !found || !runtimeCertificationEphemeralOwnedBy(current, owner, token) {
		return runtimeCertificationCleanupRef{}, fmt.Errorf("runtime certification object %s is missing expected ownership", path)
	}
	uid, err := kubeObjectUID(current)
	if err != nil {
		return runtimeCertificationCleanupRef{}, err
	}
	return runtimeCertificationCleanupRef{Path: path, Owner: owner, CleanupToken: token, UID: uid}, nil
}

func componentRuntimeResourceReady(resource, current map[string]any) (bool, string) {
	kind, _ := resource["kind"].(string)
	switch kind {
	case "CustomResourceDefinition":
		status, _ := current["status"].(map[string]any)
		conditions, _ := status["conditions"].([]any)
		for _, item := range conditions {
			condition, _ := item.(map[string]any)
			if condition["type"] == "Established" && condition["status"] == "True" {
				return true, "CRD Established=True"
			}
		}
		return false, "CRD Established=True condition is missing"
	case "Deployment":
		metadata, _ := current["metadata"].(map[string]any)
		status, _ := current["status"].(map[string]any)
		generation := int64(0)
		if v, ok := metadata["generation"].(float64); ok {
			generation = int64(v)
		}
		observed := int64(0)
		if v, ok := status["observedGeneration"].(float64); ok {
			observed = int64(v)
		}
		ready := int64(0)
		if v, ok := status["readyReplicas"].(float64); ok {
			ready = int64(v)
		}
		desired := int64(1)
		spec, _ := resource["spec"].(map[string]any)
		if v, ok := spec["replicas"].(float64); ok {
			desired = int64(v)
		}
		if generation > 0 && observed >= generation && ready >= desired {
			return true, fmt.Sprintf("deployment ready=%d desired=%d observedGeneration=%d", ready, desired, observed)
		}
		return false, fmt.Sprintf("deployment not ready: ready=%d desired=%d generation=%d observed=%d", ready, desired, generation, observed)
	default:
		return true, "resource persisted with exact desired ownership/read-back"
	}
}

func (a *agent) installComponentRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	fresh := true
	for _, resource := range task.Resources {
		path, _, err := certificationResourcePath(task, resource)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		_, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		if found {
			fresh = false
			break
		}
	}
	checks = append(checks, check("fresh-install-target", started, fresh, "all component resources absent before first mutation"))
	if !fresh {
		result.Checks, result.Error = checks, "component fresh-install target contains existing resources"
		return result
	}
	for _, resource := range task.Resources {
		path, identity, err := certificationResourcePath(task, resource)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		collection, err := kubeCollectionPath(path)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		started = time.Now()
		created, conflict, err := a.createKubeObject(ctx, collection, resource)
		if err != nil || !created || conflict {
			detail := "resource create failed"
			if err != nil {
				detail = err.Error()
			}
			checks = append(checks, check("apply/"+identity, started, false, detail))
			result.Checks, result.Error = checks, detail
			return result
		}
		current, found, getErr := a.getKubeObject(ctx, path)
		owned := getErr == nil && found && runtimeCertificationResourceOwnedByDesired(current, resource)
		desiredMatch := getErr == nil && found && kubeObjectContainsDesiredFields(current, resource)
		ok := owned && desiredMatch
		detail := fmt.Sprintf("resource created; found=%t owned=%t desiredMatch=%t", found, owned, desiredMatch)
		if getErr != nil {
			detail = getErr.Error()
		}
		checks = append(checks, check("apply/"+identity, started, ok, detail))
		if !ok {
			result.Checks, result.Error = checks, "component resource read-back failed"
			return result
		}
	}
	// Exercise a real, non-destructive failure control against the Kubernetes API:
	// re-creating an already-owned object must be rejected with HTTP 409. This
	// proves duplicate mutation does not silently replace/adopt runtime state.
	firstPath, firstIdentity, err := certificationResourcePath(task, task.Resources[0])
	if err != nil {
		result.Checks, result.Error = checks, err.Error()
		return result
	}
	collection, err := kubeCollectionPath(firstPath)
	if err != nil {
		result.Checks, result.Error = checks, err.Error()
		return result
	}
	started = time.Now()
	created, conflict, err := a.createKubeObject(ctx, collection, task.Resources[0])
	negativeOK := err == nil && !created && conflict
	detail := fmt.Sprintf("duplicate create rejected for %s; created=%t conflict=%t", firstIdentity, created, conflict)
	if err != nil {
		detail = err.Error()
	}
	checks = append(checks, check("component-failure-control/duplicate-create-conflict", started, negativeOK, detail))
	if !negativeOK {
		result.Checks, result.Error = checks, "component duplicate-create failure control did not fail closed"
		return result
	}
	result.Success, result.Checks = true, checks
	return result
}

func (a *agent) verifyComponentRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	checkpointOK := strings.HasPrefix(task.InstallCheckpointDigest, "sha256:")
	checks = append(checks, check("durable-install-checkpoint", started, checkpointOK, "install checkpoint="+task.InstallCheckpointDigest))
	allPass := checkpointOK
	for _, resource := range task.Resources {
		path, identity, err := certificationResourcePath(task, resource)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		started = time.Now()
		current, found, getErr := a.getKubeObject(ctx, path)
		persisted := getErr == nil && found && runtimeCertificationResourceOwnedByDesired(current, resource) && kubeObjectContainsDesiredFields(current, resource)
		detail := "resource persists with exact desired ownership/read-back"
		if getErr != nil {
			detail = getErr.Error()
		}
		checks = append(checks, check("verify/"+identity, started, persisted, detail))
		if !persisted {
			allPass = false
		}
		started = time.Now()
		ready, readyDetail := false, "resource unavailable for readiness"
		if persisted {
			ready, readyDetail = componentRuntimeResourceReady(resource, current)
		}
		checks = append(checks, check("component-readiness/"+identity, started, ready, readyDetail))
		if !ready {
			allPass = false
		}
	}
	dependencyChecks := []struct {
		key string
		fn  func(context.Context) bool
	}{
		{"nodes-ready", func(ctx context.Context) bool {
			ready, total, err := a.nodeReadiness(ctx)
			return err == nil && total > 0 && ready == total
		}},
		{"cluster-dns-service", func(ctx context.Context) bool {
			for _, p := range []string{"/api/v1/namespaces/kube-system/services/kube-dns", "/api/v1/namespaces/kube-system/services/coredns"} {
				_, found, err := a.getKubeObject(ctx, p)
				if err == nil && found {
					return true
				}
			}
			return false
		}},
		{"kubernetes-api-tls", func(ctx context.Context) bool { _, _, err := a.nodeReadiness(ctx); return err == nil }},
	}
	for _, dep := range dependencyChecks {
		started = time.Now()
		ok := dep.fn(ctx)
		checks = append(checks, check(dep.key, started, ok, "component runtime cluster health prerequisite"))
		checks = append(checks, check("component-dependency/"+dep.key, started, ok, "component runtime dependency prerequisite"))
		if !ok {
			allPass = false
		}
	}
	result.Success, result.Checks = allPass, checks
	if !allPass {
		result.Error = "one or more component runtime readiness checks failed"
	}
	return result
}

func componentRuntimeCRDInstanceListPath(resource map[string]any) (string, bool) {
	kind, _ := resource["kind"].(string)
	if kind != "CustomResourceDefinition" {
		return "", false
	}
	spec, _ := resource["spec"].(map[string]any)
	group, _ := spec["group"].(string)
	names, _ := spec["names"].(map[string]any)
	plural, _ := names["plural"].(string)
	versions, _ := spec["versions"].([]any)
	version := ""
	for _, raw := range versions {
		item, _ := raw.(map[string]any)
		served, _ := item["served"].(bool)
		name, _ := item["name"].(string)
		if served && strings.TrimSpace(name) != "" {
			version = strings.TrimSpace(name)
			break
		}
	}
	if strings.TrimSpace(group) == "" || strings.TrimSpace(plural) == "" || version == "" {
		return "", false
	}
	return "/apis/" + url.PathEscape(strings.TrimSpace(group)) + "/" + url.PathEscape(version) + "/" + url.PathEscape(strings.TrimSpace(plural)), true
}

const componentRuntimeFailureTokenAnnotation = "platform.4so.io/runtime-certification-failure-token"

func componentRuntimePriorCleanupToken(task controlplane.RuntimeCertificationTask, phase controlplane.RuntimeCertificationPhase, token string) bool {
	for _, generation := range task.PriorCleanupGenerations {
		if generation.Phase == phase && strings.TrimSpace(generation.Token) == strings.TrimSpace(token) && strings.TrimSpace(token) != "" {
			return true
		}
	}
	return false
}

func componentRuntimeFailureToken(resource map[string]any) string {
	metadata, _ := resource["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	token, _ := annotations[componentRuntimeFailureTokenAnnotation].(string)
	return strings.TrimSpace(token)
}

func (a *agent) clearComponentRuntimeFailureToken(ctx context.Context, path string) error {
	patch := map[string]any{"metadata": map[string]any{"annotations": map[string]any{componentRuntimeFailureTokenAnnotation: nil}}}
	return a.mergePatchKubeObject(ctx, path, patch)
}

func (a *agent) failureRecoverComponentRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	if len(task.Resources) == 0 {
		result.Error = "component failure-recovery requires at least one resource"
		return result
	}
	resource := task.Resources[0]
	path, identity, err := certificationResourcePath(task, resource)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil || !found {
		result.Error = "component failure-recovery target is absent"
		return result
	}
	ownedDesired := runtimeCertificationResourceOwnedByDesired(current, resource)
	priorToken := componentRuntimeFailureToken(current)
	resumingOwnDrift := !ownedDesired && componentRuntimePriorCleanupToken(task, controlplane.RuntimeCertificationPhaseFailure, priorToken)
	if !ownedDesired && !resumingOwnDrift {
		result.Error = "component failure-recovery target is no longer owned and has no prior fenced failure token"
		return result
	}
	originalUID, err := kubeObjectUID(current)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	started := time.Now()
	drifted := current
	if !resumingOwnDrift {
		patch := map[string]any{"metadata": map[string]any{
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "4so-certification-drift"},
			"annotations": map[string]any{componentRuntimeFailureTokenAnnotation: task.CleanupToken},
		}}
		if err = a.mergePatchKubeObject(ctx, path, patch); err != nil {
			checks = append(checks, check("component-failure-recovery/drift-injected", started, false, err.Error()))
			result.Checks, result.Error = checks, err.Error()
			return result
		}
		drifted, found, err = a.getKubeObject(ctx, path)
		driftUID, uidErr := kubeObjectUID(drifted)
		driftObserved := err == nil && found && uidErr == nil && driftUID == originalUID && !runtimeCertificationResourceOwnedByDesired(drifted, resource) && componentRuntimeFailureToken(drifted) == task.CleanupToken
		checks = append(checks, check("component-failure-recovery/drift-injected", started, driftObserved, "fenced ownership drift injected without object replacement for "+identity))
		if !driftObserved {
			result.Checks, result.Error = checks, "component ownership drift was not observed"
			return result
		}
	} else {
		checks = append(checks, check("component-failure-recovery/drift-injected", started, true, "resumed self-owned drift from prior fenced failure attempt for "+identity))
	}
	started = time.Now()
	if err = a.serverSideApplyConditional(ctx, path, resource, drifted); err != nil {
		checks = append(checks, check("component-failure-recovery/reconciled", started, false, err.Error()))
		result.Checks, result.Error = checks, err.Error()
		return result
	}
	if err = a.clearComponentRuntimeFailureToken(ctx, path); err != nil {
		checks = append(checks, check("component-failure-recovery/reconciled", started, false, "desired state reapplied but fenced failure token could not be cleared: "+err.Error()))
		result.Checks, result.Error = checks, err.Error()
		return result
	}
	restored, found, getErr := a.getKubeObject(ctx, path)
	restoredUID, restoredUIDErr := kubeObjectUID(restored)
	reconciled := getErr == nil && found && restoredUIDErr == nil && restoredUID == originalUID && runtimeCertificationResourceOwnedByDesired(restored, resource) && componentRuntimeFailureToken(restored) == "" && kubeObjectContainsDesiredFields(restored, resource)
	checks = append(checks, check("component-failure-recovery/reconciled", started, reconciled, "desired ownership restored on the same Kubernetes UID and fenced drift token removed"))
	if !reconciled {
		result.Checks, result.Error = checks, "component desired state was not restored after injected drift"
		return result
	}
	started = time.Now()
	ready, detail := componentRuntimeResourceReady(resource, restored)
	checks = append(checks, check("component-failure-recovery/readiness-restored", started, ready, detail))
	result.Success, result.Checks = ready, checks
	if !ready {
		result.Error = "component readiness did not recover after injected drift"
	}
	return result
}

func (a *agent) removeComponentRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	removeRetry := false
	for _, generation := range task.PriorCleanupGenerations {
		if generation.Phase == controlplane.RuntimeCertificationPhaseRemove {
			removeRetry = true
			break
		}
	}
	for i := len(task.Resources) - 1; i >= 0; i-- {
		resource := task.Resources[i]
		path, identity, err := certificationResourcePath(task, resource)
		if err != nil {
			result.Checks, result.Error = checks, err.Error()
			return result
		}
		started := time.Now()
		current, found, getErr := a.getKubeObject(ctx, path)
		if getErr != nil {
			checks = append(checks, check("component-remove/"+identity, started, false, getErr.Error()))
			result.Checks, result.Error = checks, getErr.Error()
			return result
		}
		if !found {
			if removeRetry {
				checks = append(checks, check("component-remove/"+identity, started, true, "resource already absent after prior fenced REMOVE attempt"))
				continue
			}
			checks = append(checks, check("component-remove/"+identity, started, false, "resource disappeared before first REMOVE attempt"))
			result.Checks, result.Error = checks, "component resource disappeared before first remove attempt"
			return result
		}
		if !runtimeCertificationResourceOwnedByDesired(current, resource) {
			checks = append(checks, check("component-remove/"+identity, started, false, "refusing to delete resource not owned by exact component certification desired state"))
			result.Checks, result.Error = checks, "component remove ownership check failed"
			return result
		}
		if listPath, ok := componentRuntimeCRDInstanceListPath(resource); ok {
			instances, listErr := a.listKubeObjects(ctx, listPath)
			if listErr != nil {
				checks = append(checks, check("component-remove/"+identity, started, false, "cannot prove CRD has zero instances: "+listErr.Error()))
				result.Checks, result.Error = checks, "component CRD remove safety check failed"
				return result
			}
			if len(instances) != 0 {
				checks = append(checks, check("component-remove/"+identity, started, false, fmt.Sprintf("refusing to delete CRD with %d live custom resources", len(instances))))
				result.Checks, result.Error = checks, "component CRD has live custom resources"
				return result
			}
		}
		uid, uidErr := kubeObjectUID(current)
		rv, rvErr := kubeObjectResourceVersion(current)
		if uidErr != nil || rvErr != nil {
			detail := "component remove identity precondition missing"
			if uidErr != nil {
				detail = uidErr.Error()
			} else if rvErr != nil {
				detail = rvErr.Error()
			}
			checks = append(checks, check("component-remove/"+identity, started, false, detail))
			result.Checks, result.Error = checks, detail
			return result
		}
		if err = a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, path, uid, rv, 30*time.Second); err != nil {
			checks = append(checks, check("component-remove/"+identity, started, false, err.Error()))
			result.Checks, result.Error = checks, err.Error()
			return result
		}
		checks = append(checks, check("component-remove/"+identity, started, true, "owned resource removed with UID/resourceVersion preconditions"))
	}
	result.Success, result.Checks = true, checks
	return result
}

func (a *agent) installRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	resumed, err := a.ensureRuntimeCertificationNamespace(ctx, task)
	if err != nil {
		checks = append(checks, check("fresh-install-target", started, false, err.Error()))
		result.Checks, result.Error = checks, err.Error()
		return result
	}
	if resumed {
		checks = append(checks, check("fresh-install-target", started, true, "resuming interrupted install on namespace owned by the same catalog release"))
	} else {
		checks = append(checks, check("fresh-install-target", started, true, "target namespace was created atomically for this certification run"))
	}
	// The namespace is one of the six rendered resources. Record its apply
	// evidence explicitly so the Agent result shape matches the authority's
	// resourceCount contract instead of relying on a synthetic smoke fixture.
	nsResource, nsErr := runtimeCertificationNamespaceResource(task)
	if nsErr != nil {
		result.Checks, result.Error = checks, nsErr.Error()
		return result
	}
	_, nsIdentity, nsErr := certificationResourcePath(task, nsResource)
	if nsErr != nil {
		result.Checks, result.Error = checks, nsErr.Error()
		return result
	}
	currentNamespace, nsFound, nsGetErr := a.getKubeObject(ctx, "/api/v1/namespaces/"+task.Namespace)
	nsOK := nsGetErr == nil && nsFound && kubeObjectContainsDesiredFields(currentNamespace, nsResource)
	checks = append(checks, check("apply/"+nsIdentity, time.Now(), nsOK, "certification namespace ownership and desired labels read back"))
	if !nsOK {
		result.Checks, result.Error = checks, "certification namespace desired state could not be verified"
		return result
	}
	for _, resource := range task.Resources {
		kind, _ := resource["kind"].(string)
		if kind == "Namespace" {
			continue
		}
		path, identity, pathErr := certificationResourcePath(task, resource)
		if pathErr != nil {
			result.Checks, result.Error = checks, pathErr.Error()
			return result
		}
		started = time.Now()
		if err = a.ensureRuntimeCertificationResource(ctx, task, resource); err != nil {
			checks = append(checks, check("apply/"+identity, started, false, err.Error()))
			result.Checks, result.Error = checks, err.Error()
			return result
		}
		current, currentFound, getErr := a.getKubeObject(ctx, path)
		ok := getErr == nil && currentFound && kubeObjectContainsDesiredFields(current, resource)
		detail := "resource created/reconciled and desired fields read back"
		if getErr != nil {
			detail = getErr.Error()
		} else if currentFound && !kubeObjectContainsDesiredFields(current, resource) {
			detail = "resource read-back does not match rendered desired fields"
		}
		checks = append(checks, check("apply/"+identity, started, ok, detail))
		if !ok {
			result.Checks, result.Error = checks, "applied resource desired state could not be verified"
			return result
		}
	}
	result.Success, result.Checks = true, checks
	return result
}

func (a *agent) verifyRuntimeCertification(ctx context.Context, task controlplane.RuntimeCertificationTask) controlplane.RuntimeCertificationResult {
	result := controlplane.RuntimeCertificationResult{Phase: task.Phase, InventoryDigest: task.InventoryDigest, RenderedDigest: task.RenderedDigest}
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	checkpointOK := strings.HasPrefix(task.InstallCheckpointDigest, "sha256:")
	checks = append(checks, check("durable-install-checkpoint", started, checkpointOK, "install checkpoint="+task.InstallCheckpointDigest))
	allPass := checkpointOK
	for _, resource := range task.Resources {
		path, identity, err := certificationResourcePath(task, resource)
		if err != nil {
			result.Error = err.Error()
			result.Checks = checks
			return result
		}
		started = time.Now()
		current, found, getErr := a.getKubeObject(ctx, path)
		ok := getErr == nil && found && kubeObjectContainsDesiredFields(current, resource)
		detail := "resource persisted after install checkpoint and still matches rendered desired fields"
		if getErr != nil {
			detail = getErr.Error()
		}
		checks = append(checks, check("verify/"+identity, started, ok, detail))
		if !ok {
			allPass = false
		}
	}
	started = time.Now()
	ready, total, nodeErr := a.nodeReadiness(ctx)
	nodesOK := nodeErr == nil && total > 0 && ready == total
	checks = append(checks, check("nodes-ready", started, nodesOK, fmt.Sprintf("ready=%d total=%d", ready, total)))
	if !nodesOK {
		allPass = false
	}
	started = time.Now()
	dnsFound := false
	for _, path := range []string{"/api/v1/namespaces/kube-system/services/kube-dns", "/api/v1/namespaces/kube-system/services/coredns"} {
		_, found, err := a.getKubeObject(ctx, path)
		if err == nil && found {
			dnsFound = true
			break
		}
	}
	checks = append(checks, check("cluster-dns-service", started, dnsFound, "kube-system DNS service discovery"))
	if !dnsFound {
		allPass = false
	}
	started = time.Now()
	_, _, tlsErr := a.nodeReadiness(ctx)
	tlsOK := tlsErr == nil
	checks = append(checks, check("kubernetes-api-tls", started, tlsOK, "Kubernetes API request validated through configured service-account CA"))
	if !tlsOK {
		allPass = false
	}
	if task.Profile == controlplane.RuntimeCertificationObservabilityV1 || task.Profile == controlplane.RuntimeCertificationTargetV1 {
		observabilityChecks, observabilityOK, observabilityError := a.verifyObservabilityRuntime(ctx, task)
		checks = append(checks, observabilityChecks...)
		if !observabilityOK {
			allPass = false
			result.Error = observabilityError
		}
	}
	if task.Profile == controlplane.RuntimeCertificationTargetV1 {
		if len(task.PriorCleanupGenerations) > 0 {
			cleanupStarted := time.Now()
			if cleanupErr := a.cleanupPriorRuntimeCertificationAttempts(ctx, task); cleanupErr != nil {
				checks = append(checks, check("target-runtime/prior-attempt-cleanup", cleanupStarted, false, cleanupErr.Error()))
				result.Success = false
				result.Checks = checks
				result.Error = cleanupErr.Error()
				return result
			}
			checks = append(checks, check("target-runtime/prior-attempt-cleanup", cleanupStarted, true, "prior VERIFY attempts reconciled before new target-runtime mutation"))
		}
		networkChecks, networkOK, networkBlocked, networkError := a.verifyNetworkTenantIsolationRuntime(ctx, task)
		checks = append(checks, networkChecks...)
		if !networkOK {
			allPass = false
			result.Blocked = networkBlocked
			result.Error = networkError
		}
		storageChecks, storageOK, storageBlocked, storageError := a.verifyStorageBackupRuntime(ctx, task)
		checks = append(checks, storageChecks...)
		if !storageOK {
			allPass = false
			result.Blocked = storageBlocked
			result.Error = storageError
		}
	}
	result.Success, result.Checks = allPass, checks
	if !allPass && result.Error == "" {
		result.Error = "one or more runtime certification checks failed"
	}
	return result
}

func (a *agent) reportRuntimeCertificationTask(ctx context.Context, task controlplane.RuntimeCertificationTask, result controlplane.RuntimeCertificationResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/runtime-certification-tasks/"+task.RunID+"/result", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.RunRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("runtime certification result API %s: %s", res.Status, string(raw))
	}
	return nil
}

type probeOutput struct {
	DNSResolved    bool     `json:"dnsResolved"`
	Addresses      []string `json:"addresses"`
	TCPConnected   bool     `json:"tcpConnected"`
	DurationMillis int64    `json:"durationMillis"`
	Error          string   `json:"error"`
}

func probeOutputFromPodTermination(object map[string]any) (probeOutput, error) {
	var output probeOutput
	status, _ := object["status"].(map[string]any)
	items, _ := status["containerStatuses"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if strings.TrimSpace(fmt.Sprint(item["name"])) != "probe" {
			continue
		}
		state, _ := item["state"].(map[string]any)
		terminated, _ := state["terminated"].(map[string]any)
		message := strings.TrimSpace(fmt.Sprint(terminated["message"]))
		if message == "" {
			return output, fmt.Errorf("probe container termination message is missing")
		}
		if err := json.Unmarshal([]byte(message), &output); err != nil {
			return output, fmt.Errorf("decode probe termination message: %w", err)
		}
		return output, nil
	}
	return output, fmt.Errorf("probe container termination status is missing")
}

func (a *agent) processRuntimeVerificationTask(ctx context.Context) error {
	task, ok, err := a.nextRuntimeVerificationTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.runRuntimeVerification(execCtx, task)
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportRuntimeVerificationTask(ctx, task, result)
}

func (a *agent) nextRuntimeVerificationTask(ctx context.Context) (controlplane.RuntimeVerificationTask, bool, error) {
	var task controlplane.RuntimeVerificationTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/runtime-verification-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("runtime verification task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func validateRuntimeVerificationTask(task controlplane.RuntimeVerificationTask, configuredImage string) error {
	if task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) || task.TargetNamespace != "4so-platform-baseline" || !strings.HasPrefix(task.DesiredDigest, "sha256:") {
		return fmt.Errorf("runtime verification target is not allowed")
	}
	if task.ProbeImage == "" || task.ProbeImage != configuredImage || !strings.Contains(task.ProbeImage, "@sha256:") {
		return fmt.Errorf("runtime probe image is not the configured digest-pinned image")
	}
	if task.VerificationID == "" || task.BaselineDeploymentID == "" || task.VerificationRevision < 1 {
		return fmt.Errorf("runtime verification task identity is incomplete")
	}
	return nil
}

func check(key string, started time.Time, ok bool, detail string) controlplane.RuntimeCheck {
	status := "FAIL"
	if ok {
		status = "PASS"
	}
	return controlplane.RuntimeCheck{Key: key, Status: status, Detail: detail, DurationMillis: time.Since(started).Milliseconds()}
}

func (a *agent) runRuntimeVerification(ctx context.Context, task controlplane.RuntimeVerificationTask) controlplane.RuntimeVerificationResult {
	result := controlplane.RuntimeVerificationResult{}
	if err := validateRuntimeVerificationTask(task, a.cfg.RuntimeProbeImage); err != nil {
		result.Error = err.Error()
		return result
	}
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	observed := a.currentBaselineDigest(ctx)
	checks = append(checks, check("baseline-digest-equality", started, observed == task.DesiredDigest, "observed="+observed))
	started = time.Now()
	resourcesOK := true
	for key, path := range baselineResourcePaths {
		obj, found, err := a.getKubeObject(ctx, path)
		if err != nil || !found || objectDesiredDigest(obj) != task.DesiredDigest {
			resourcesOK = false
			break
		}
		_ = key
	}
	checks = append(checks, check("baseline-resources-present", started, resourcesOK, "all five allowlisted resources match the desired digest"))
	started = time.Now()
	ready, total, err := a.nodeReadiness(ctx)
	checks = append(checks, check("nodes-ready", started, err == nil && total > 0 && ready == total, fmt.Sprintf("ready=%d total=%d", ready, total)))
	probeChecks, probeErr := a.runProbeJob(ctx, task)
	checks = append(checks, probeChecks...)
	allPass := probeErr == nil
	for _, c := range checks {
		if c.Status != "PASS" {
			allPass = false
		}
	}
	result.Success = allPass && observed == task.DesiredDigest
	result.ObservedDigest = observed
	result.Checks = checks
	if probeErr != nil {
		result.Error = probeErr.Error()
	} else if !result.Success {
		result.Error = "one or more runtime checks failed"
	}
	return result
}

func (a *agent) nodeReadiness(ctx context.Context) (int, int, error) {
	var nodes struct {
		Items []struct {
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/nodes", nil, &nodes); err != nil {
		return 0, 0, err
	}
	ready := 0
	for _, n := range nodes.Items {
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready++
				break
			}
		}
	}
	return ready, len(nodes.Items), nil
}

func runtimeVerificationJobOwnedByTask(object map[string]any, task controlplane.RuntimeVerificationTask) bool {
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	return labels["platform.4so.io/runtime-verification"] == task.VerificationID
}

func (a *agent) deleteRuntimeVerificationJob(ctx context.Context, path string, task controlplane.RuntimeVerificationTask, expectedUID string, timeout time.Duration) error {
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !runtimeVerificationJobOwnedByTask(current, task) {
		return fmt.Errorf("refusing to delete runtime verification Job not owned by verification %s", task.VerificationID)
	}
	uid, err := kubeObjectUID(current)
	if err != nil {
		return err
	}
	if strings.TrimSpace(expectedUID) != "" && uid != strings.TrimSpace(expectedUID) {
		return fmt.Errorf("runtime verification Job was replaced before cleanup")
	}
	resourceVersion, err := kubeObjectResourceVersion(current)
	if err != nil {
		return err
	}
	return a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, path, uid, resourceVersion, timeout)
}

func (a *agent) runProbeJob(ctx context.Context, task controlplane.RuntimeVerificationTask) (checks []controlplane.RuntimeCheck, err error) {
	name := "4so-runtime-probe-" + strings.TrimPrefix(task.VerificationID, "rtv_")
	if len(name) > 63 {
		name = name[:63]
	}
	jobPath := "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/" + name
	if err := a.deleteRuntimeVerificationJob(ctx, jobPath, task, "", 30*time.Second); err != nil {
		return []controlplane.RuntimeCheck{check("probe-job-replaced", time.Now(), false, err.Error())}, err
	}
	job := map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": name, "namespace": "4so-platform-baseline", "labels": map[string]any{"platform.4so.io/runtime-verification": task.VerificationID}}, "spec": map[string]any{"backoffLimit": 0, "ttlSecondsAfterFinished": 300, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"job-name": name, "platform.4so.io/runtime-verification": task.VerificationID}}, "spec": map[string]any{"restartPolicy": "Never", "serviceAccountName": "4so-baseline-observer", "automountServiceAccountToken": false, "containers": []any{map[string]any{"name": "probe", "image": task.ProbeImage, "imagePullPolicy": "IfNotPresent"}}}}}}
	started := time.Now()
	var createdJob struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := a.kubeJSON(ctx, http.MethodPost, "/apis/batch/v1/namespaces/4so-platform-baseline/jobs", job, &createdJob); err != nil {
		return []controlplane.RuntimeCheck{check("probe-job-created", started, false, err.Error())}, err
	}
	if strings.TrimSpace(createdJob.Metadata.UID) == "" {
		err := fmt.Errorf("runtime probe job response did not include metadata.uid")
		return []controlplane.RuntimeCheck{check("probe-job-created", started, false, err.Error())}, err
	}
	checks = []controlplane.RuntimeCheck{check("probe-job-created", started, true, "ephemeral digest-pinned probe job created")}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if cleanupErr := a.deleteRuntimeVerificationJob(cleanupCtx, jobPath, task, createdJob.Metadata.UID, 10*time.Second); cleanupErr != nil {
			checks = append(checks, check("probe-job-cleanup", time.Now(), false, cleanupErr.Error()))
			if err == nil {
				err = fmt.Errorf("runtime verification probe cleanup failed: %w", cleanupErr)
			} else {
				err = fmt.Errorf("%v; runtime verification probe cleanup failed: %w", err, cleanupErr)
			}
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var status struct {
			Status struct {
				Succeeded int `json:"succeeded"`
				Failed    int `json:"failed"`
			} `json:"status"`
		}
		if err := a.kubeJSON(ctx, http.MethodGet, jobPath, nil, &status); err != nil {
			return append(checks, check("probe-job-completed", started, false, err.Error())), err
		}
		if status.Status.Failed > 0 {
			return append(checks, check("probe-job-completed", started, false, "probe job failed")), fmt.Errorf("probe job failed")
		}
		if status.Status.Succeeded > 0 {
			checks = append(checks, check("probe-job-completed", started, true, "probe workload scheduled and completed"))
			output, err := a.probePodResult(ctx, name, createdJob.Metadata.UID)
			if err != nil {
				return append(checks, check("probe-result-read", time.Now(), false, err.Error())), err
			}
			checks = append(checks, controlplane.RuntimeCheck{Key: "cluster-dns", Status: passFail(output.DNSResolved), Detail: strings.Join(output.Addresses, ","), DurationMillis: output.DurationMillis})
			checks = append(checks, controlplane.RuntimeCheck{Key: "kubernetes-api-service-tcp", Status: passFail(output.TCPConnected), Detail: output.Error, DurationMillis: output.DurationMillis})
			return checks, nil
		}
		select {
		case <-ctx.Done():
			return checks, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return append(checks, check("probe-job-completed", started, false, "timed out")), fmt.Errorf("runtime probe job timed out")
}
func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
func (a *agent) probePodResult(ctx context.Context, jobName, jobUID string) (probeOutput, error) {
	var empty probeOutput
	path := "/api/v1/namespaces/4so-platform-baseline/pods?labelSelector=job-name%3D" + jobName
	var pods map[string]any
	if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &pods); err != nil {
		return empty, err
	}
	items, _ := pods["items"].([]any)
	for _, raw := range items {
		pod, _ := raw.(map[string]any)
		metadata, _ := pod["metadata"].(map[string]any)
		owners, _ := metadata["ownerReferences"].([]any)
		owned := false
		for _, ownerRaw := range owners {
			owner, _ := ownerRaw.(map[string]any)
			if strings.TrimSpace(fmt.Sprint(owner["uid"])) == jobUID {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		return probeOutputFromPodTermination(pod)
	}
	return empty, fmt.Errorf("probe pod for job uid %s not found", jobUID)
}
func (a *agent) reportRuntimeVerificationTask(ctx context.Context, task controlplane.RuntimeVerificationTask, result controlplane.RuntimeVerificationResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/runtime-verification-tasks/" + task.VerificationID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.VerificationRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("runtime verification result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processDriftTask(ctx context.Context) error {
	task, ok, err := a.nextDriftTask(ctx)
	if err != nil || !ok {
		return err
	}
	baselineTask := controlplane.BaselineTask{
		DeploymentID: task.BaselineDeploymentID, DeploymentRev: task.ScanRevision,
		Action: "PLAN", BaselineID: task.BaselineID, BaselineVersion: task.BaselineVersion,
		TargetNamespace: task.TargetNamespace, DesiredDigest: task.DesiredDigest, Resources: task.Resources,
	}
	result := controlplane.DriftTaskResult{ClusterID: a.clusterID}
	if err = validateBaselineTask(baselineTask); err != nil {
		result.Error = err.Error()
		return a.reportDriftTask(ctx, task, result)
	}
	planned := a.planBaseline(ctx, baselineTask)
	result.Success = planned.Success
	result.ObservedDigest = planned.ObservedDigest
	result.Changes = planned.Changes
	if task.Git != nil {
		result.GitObservedDigest = a.currentGitOpsRevisionDigest(ctx)
	}
	result.Error = planned.Error
	return a.reportDriftTask(ctx, task, result)
}

func (a *agent) currentGitOpsRevisionDigest(ctx context.Context) string {
	var obj map[string]any
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/namespaces/platform-system/configmaps/platform-gitops-revision", nil, &obj); err != nil {
		return ""
	}
	data, _ := obj["data"].(map[string]any)
	value, _ := data["revisionDigest"].(string)
	return strings.TrimSpace(value)
}

func (a *agent) nextDriftTask(ctx context.Context) (controlplane.DriftTask, bool, error) {
	var task controlplane.DriftTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/drift-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("drift task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) reportDriftTask(ctx context.Context, task controlplane.DriftTask, result controlplane.DriftTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/drift-tasks/" + task.ScanID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.ScanRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("drift result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processTenantTask(ctx context.Context) error {
	task, ok, err := a.nextTenantTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.executeTenantTask(execCtx, task)
	return a.reportTenantTask(ctx, task, result)
}
func (a *agent) nextTenantTask(ctx context.Context) (controlplane.TenantTask, bool, error) {
	var task controlplane.TenantTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/tenant-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("tenant task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}
func validateTenantTask(task controlplane.TenantTask) error {
	if task.TenantID == "" || task.TenantRevision < 1 || task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || !strings.HasPrefix(task.Namespace, "tenant-") || len(task.Namespace) > 63 {
		return fmt.Errorf("tenant task identity or namespace is invalid")
	}
	switch task.Action {
	case "PROVISION", "SUSPEND", "RESUME", "RESIZE":
		if !strings.HasPrefix(task.DesiredDigest, "sha256:") || len(task.Resources) != 7 {
			return fmt.Errorf("tenant desired state is incomplete")
		}
	case "DELETE":
		if len(task.Resources) != 0 {
			return fmt.Errorf("delete tenant task must not contain resources")
		}
	default:
		return fmt.Errorf("tenant task action is not allowed")
	}
	if task.Action != "DELETE" && (task.StoragePolicy.StorageClass == "" || task.StoragePolicy.RequestQuota == "" || task.StoragePolicy.MaxPVCSize == "" || task.BackupPolicy.Provider != "velero" || task.BackupPolicy.Schedule == "" || task.BackupPolicy.Retention == "" || task.SecurityPolicy.PodSecurityLevel != "restricted" || !task.SecurityPolicy.DefaultDenyIngress || !task.SecurityPolicy.DefaultDenyEgress || !task.SecurityPolicy.AllowDNS) {
		return fmt.Errorf("tenant storage/backup/security policy contract is incomplete")
	}
	allowed := map[string]string{
		"Namespace/" + task.Namespace:                                      "",
		"ResourceQuota/tenant-quota":                                       task.Namespace,
		"LimitRange/tenant-default-limits":                                 task.Namespace,
		"NetworkPolicy/tenant-default-deny-all":                            task.Namespace,
		"NetworkPolicy/tenant-allow-dns-egress":                            task.Namespace,
		"Schedule/" + controlplane.TenantBackupScheduleName(task.TenantID): "velero",
		"ConfigMap/tenant-platform-state":                                  task.Namespace,
	}
	for _, r := range task.Resources {
		ns, ok := allowed[r.Kind+"/"+r.Name]
		if !ok || ns != r.Namespace {
			return fmt.Errorf("tenant resource %s/%s is outside the allowlist", r.Kind, r.Name)
		}
		meta, _ := r.Object["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		namespace, _ := meta["namespace"].(string)
		if name != r.Name || (r.Kind != "Namespace" && namespace != ns) {
			return fmt.Errorf("tenant resource metadata mismatch")
		}
	}
	return nil
}
func tenantResourcePath(r controlplane.BaselineTaskResource) string {
	switch r.Kind {
	case "Namespace":
		return "/api/v1/namespaces/" + r.Name
	case "ResourceQuota":
		return "/api/v1/namespaces/" + r.Namespace + "/resourcequotas/" + r.Name
	case "LimitRange":
		return "/api/v1/namespaces/" + r.Namespace + "/limitranges/" + r.Name
	case "NetworkPolicy":
		return "/apis/networking.k8s.io/v1/namespaces/" + r.Namespace + "/networkpolicies/" + r.Name
	case "Schedule":
		return "/apis/velero.io/v1/namespaces/" + r.Namespace + "/schedules/" + r.Name
	case "ConfigMap":
		return "/api/v1/namespaces/" + r.Namespace + "/configmaps/" + r.Name
	default:
		return ""
	}
}
func tenantEvidenceDigest(items []controlplane.TenantEvidenceArtifact) string {
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func tenantObjectEvidence(key, resource string, object map[string]any) controlplane.TenantEvidenceArtifact {
	raw, _ := json.Marshal(object)
	sum := sha256.Sum256(raw)
	return controlplane.TenantEvidenceArtifact{Key: key, Authority: "KUBERNETES_API_READBACK_V1", Resource: resource, Status: "PASS", Digest: "sha256:" + hex.EncodeToString(sum[:])}
}

type tenantPodSummary struct {
	Name       string
	UID        string
	Controlled bool
}

type tenantPodList struct {
	Items []struct {
		Metadata struct {
			Name            string `json:"name"`
			UID             string `json:"uid"`
			OwnerReferences []struct {
				UID        string `json:"uid"`
				Controller *bool  `json:"controller"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
	} `json:"items"`
}

func (a *agent) listTenantPods(ctx context.Context, namespace string) ([]tenantPodSummary, error) {
	var list tenantPodList
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods", nil, &list); err != nil {
		return nil, err
	}
	out := make([]tenantPodSummary, 0, len(list.Items))
	for _, item := range list.Items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" {
			return nil, fmt.Errorf("tenant pod list contains unnamed pod")
		}
		controlled := false
		for _, owner := range item.Metadata.OwnerReferences {
			if owner.Controller != nil && *owner.Controller {
				controlled = true
				break
			}
		}
		uid := strings.TrimSpace(item.Metadata.UID)
		if uid == "" {
			return nil, fmt.Errorf("tenant pod %s has no Kubernetes UID", name)
		}
		out = append(out, tenantPodSummary{Name: name, UID: uid, Controlled: controlled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (a *agent) validateSuspendableTenantPods(ctx context.Context, task controlplane.TenantTask) error {
	pods, err := a.listTenantPods(ctx, task.Namespace)
	if err != nil {
		return fmt.Errorf("list tenant pods before suspend: %w", err)
	}
	for _, pod := range pods {
		if !pod.Controlled {
			return fmt.Errorf("tenant suspend requires controller-managed workloads; standalone pod %s cannot be durably resumed", pod.Name)
		}
	}
	return nil
}

func (a *agent) suspendTenantPods(ctx context.Context, task controlplane.TenantTask) (controlplane.TenantEvidenceArtifact, error) {
	pods, err := a.listTenantPods(ctx, task.Namespace)
	if err != nil {
		return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("list tenant pods for suspend: %w", err)
	}
	deleted := make([]string, 0, len(pods))
	for _, pod := range pods {
		if !pod.Controlled {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("standalone pod %s appeared during suspend and cannot be durably resumed", pod.Name)
		}
		podPath := "/api/v1/namespaces/" + task.Namespace + "/pods/" + pod.Name
		current, found, getErr := a.getKubeObject(ctx, podPath)
		if getErr != nil {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("re-read tenant pod %s before suspend: %w", pod.Name, getErr)
		}
		if !found {
			continue
		}
		currentUID, uidErr := kubeObjectUID(current)
		if uidErr != nil || currentUID != pod.UID {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("tenant pod %s was replaced before suspend", pod.Name)
		}
		currentMeta, _ := current["metadata"].(map[string]any)
		ownerRefs, _ := currentMeta["ownerReferences"].([]any)
		stillControlled := false
		for _, rawOwner := range ownerRefs {
			owner, _ := rawOwner.(map[string]any)
			if controller, _ := owner["controller"].(bool); controller {
				stillControlled = true
				break
			}
		}
		if !stillControlled {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("tenant pod %s lost controller ownership before suspend", pod.Name)
		}
		rv, rvErr := kubeObjectResourceVersion(current)
		if rvErr != nil {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("tenant pod %s resourceVersion: %w", pod.Name, rvErr)
		}
		if _, delErr := a.requestKubeObjectDeletionWithPreconditions(ctx, podPath, currentUID, rv); delErr != nil {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("delete tenant pod %s for suspend: %w", pod.Name, delErr)
		}
		deleted = append(deleted, pod.Name)
	}
	for {
		remaining, err := a.listTenantPods(ctx, task.Namespace)
		if err != nil {
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("verify tenant pods suspended: %w", err)
		}
		if len(remaining) == 0 {
			payload := map[string]any{"namespace": task.Namespace, "remainingPods": 0, "deletedControllerManagedPods": deleted}
			raw, _ := json.Marshal(payload)
			sum := sha256.Sum256(raw)
			return controlplane.TenantEvidenceArtifact{Key: "suspension/no-running-pods", Authority: "KUBERNETES_API_READBACK_V1", Resource: "PodList/" + task.Namespace, Status: "PASS", Digest: "sha256:" + hex.EncodeToString(sum[:]), Detail: fmt.Sprintf("verified zero tenant pods after suspending %d controller-managed pods", len(deleted))}, nil
		}
		select {
		case <-ctx.Done():
			return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("verify tenant pods suspended: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func tenantStringSliceHas(v any, wanted string) bool {
	items, _ := v.([]any)
	for _, item := range items {
		if s, _ := item.(string); s == wanted {
			return true
		}
	}
	return false
}

func verifyTenantPolicyReadback(task controlplane.TenantTask, r controlplane.BaselineTaskResource, object map[string]any) error {
	meta, _ := object["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels["platform.4so.io/tenant-id"] != task.TenantID {
		return fmt.Errorf("tenant ownership label mismatch")
	}
	switch r.Kind + "/" + r.Name {
	case "Namespace/" + task.Namespace:
		if labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["pod-security.kubernetes.io/audit"] != "restricted" || labels["pod-security.kubernetes.io/warn"] != "restricted" {
			return fmt.Errorf("Pod Security Admission restricted labels are missing")
		}
	case "ResourceQuota/tenant-quota":
		spec, _ := object["spec"].(map[string]any)
		hard, _ := spec["hard"].(map[string]any)
		if fmt.Sprint(hard["requests.storage"]) != task.StoragePolicy.RequestQuota || fmt.Sprint(hard[task.StoragePolicy.StorageClass+".storageclass.storage.k8s.io/requests.storage"]) != task.StoragePolicy.RequestQuota {
			return fmt.Errorf("storage quota policy mismatch")
		}
		if task.Action == "SUSPEND" && fmt.Sprint(hard["pods"]) != "0" {
			return fmt.Errorf("tenant suspend admission barrier pods=0 is missing")
		}
	case "NetworkPolicy/tenant-default-deny-all":
		spec, _ := object["spec"].(map[string]any)
		if !tenantStringSliceHas(spec["policyTypes"], "Ingress") || !tenantStringSliceHas(spec["policyTypes"], "Egress") {
			return fmt.Errorf("default deny must cover ingress and egress")
		}
	case "NetworkPolicy/tenant-allow-dns-egress":
		spec, _ := object["spec"].(map[string]any)
		if !tenantStringSliceHas(spec["policyTypes"], "Egress") {
			return fmt.Errorf("DNS exception must be egress-only")
		}
	case "Schedule/" + controlplane.TenantBackupScheduleName(task.TenantID):
		spec, _ := object["spec"].(map[string]any)
		template, _ := spec["template"].(map[string]any)
		if fmt.Sprint(spec["schedule"]) != task.BackupPolicy.Schedule || fmt.Sprint(template["ttl"]) != task.BackupPolicy.Retention {
			return fmt.Errorf("Velero backup schedule/retention mismatch")
		}
		included, _ := template["includedNamespaces"].([]any)
		ok := false
		for _, x := range included {
			if fmt.Sprint(x) == task.Namespace {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("Velero backup does not include tenant namespace")
		}
	}
	return nil
}

func (a *agent) tenantPodSecurityAdmissionEvidence(ctx context.Context, task controlplane.TenantTask) (controlplane.TenantEvidenceArtifact, error) {
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "4so-tenant-psa-negative", "namespace": task.Namespace}, "spec": map[string]any{"restartPolicy": "Never", "containers": []any{map[string]any{"name": "negative", "image": "invalid.local/never-run@sha256:" + strings.Repeat("0", 64), "securityContext": map[string]any{"privileged": true, "allowPrivilegeEscalation": true, "runAsNonRoot": false}}}}}
	raw, _ := json.Marshal(pod)
	path := "/api/v1/namespaces/" + task.Namespace + "/pods/4so-tenant-psa-negative?fieldManager=4so-platform-agent-tenant-policy&force=false&dryRun=All&fieldValidation=Strict"
	req, err := a.kubeRequest(ctx, http.MethodPatch, path, bytes.NewReader(raw), "application/apply-patch+yaml")
	if err != nil {
		return controlplane.TenantEvidenceArtifact{}, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return controlplane.TenantEvidenceArtifact{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	detail := fmt.Sprintf("HTTP %d privileged pod dry-run rejected", res.StatusCode)
	if res.StatusCode/100 == 2 {
		return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("Pod Security Admission accepted privileged negative probe")
	}
	lower := strings.ToLower(string(body))
	if res.StatusCode < 400 || res.StatusCode >= 500 || (!strings.Contains(lower, "podsecurity") && !strings.Contains(lower, "restricted") && !strings.Contains(lower, "privileged")) {
		return controlplane.TenantEvidenceArtifact{}, fmt.Errorf("Pod Security negative proof was not authoritative: status=%d body=%s", res.StatusCode, string(body))
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", res.StatusCode, string(body))))
	return controlplane.TenantEvidenceArtifact{Key: "security/pod-security-admission-negative", Authority: "KUBERNETES_POD_SECURITY_ADMISSION_V1", Status: "PASS", Digest: "sha256:" + hex.EncodeToString(sum[:]), Detail: detail}, nil
}

func tenantObjectOwnedByTask(object map[string]any, task controlplane.TenantTask) bool {
	meta, _ := object["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	return labels["platform.4so.io/tenant-id"] == task.TenantID && labels["platform.4so.io/managed"] == "true"
}

func legacyTenantBackupScheduleTargetsTask(object map[string]any, task controlplane.TenantTask) bool {
	spec, _ := object["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	included, _ := template["includedNamespaces"].([]any)
	for _, item := range included {
		if fmt.Sprint(item) == task.Namespace {
			return true
		}
	}
	return false
}

func (a *agent) cleanupLegacyTenantBackupSchedule(ctx context.Context, task controlplane.TenantTask) error {
	const legacyName = "tenant-platform-backup"
	path := "/apis/velero.io/v1/namespaces/velero/schedules/" + legacyName
	object, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("inspect legacy tenant backup schedule: %w", err)
	}
	if !found || !tenantObjectOwnedByTask(object, task) {
		return nil
	}
	if !legacyTenantBackupScheduleTargetsTask(object, task) {
		return fmt.Errorf("legacy tenant backup schedule ownership is ambiguous")
	}
	uid, err := kubeObjectUID(object)
	if err != nil {
		return fmt.Errorf("legacy tenant backup schedule UID: %w", err)
	}
	resourceVersion, err := kubeObjectResourceVersion(object)
	if err != nil {
		return fmt.Errorf("legacy tenant backup schedule resourceVersion: %w", err)
	}
	if err := a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, path, uid, resourceVersion, 10*time.Second); err != nil {
		return fmt.Errorf("delete owned legacy tenant backup schedule: %w", err)
	}
	return nil
}

func tenantProtectedCollectionPath(r controlplane.BaselineTaskResource) string {
	switch r.Kind {
	case "Namespace":
		return "/api/v1/namespaces"
	case "ResourceQuota":
		return "/api/v1/namespaces/" + r.Namespace + "/resourcequotas"
	case "LimitRange":
		return "/api/v1/namespaces/" + r.Namespace + "/limitranges"
	case "NetworkPolicy":
		return "/apis/networking.k8s.io/v1/namespaces/" + r.Namespace + "/networkpolicies"
	case "Schedule":
		return "/apis/velero.io/v1/namespaces/" + r.Namespace + "/schedules"
	case "ConfigMap":
		return "/api/v1/namespaces/" + r.Namespace + "/configmaps"
	default:
		return ""
	}
}

func (a *agent) applyTenantResource(ctx context.Context, task controlplane.TenantTask, r controlplane.BaselineTaskResource) error {
	path := tenantResourcePath(r)
	collectionPath := tenantProtectedCollectionPath(r)
	if path == "" || collectionPath == "" {
		return fmt.Errorf("unsupported tenant resource %s/%s", r.Kind, r.Name)
	}
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("inspect tenant %s/%s before apply: %w", r.Kind, r.Name, err)
	}
	if found {
		if !tenantObjectOwnedByTask(current, task) {
			return fmt.Errorf("refusing to mutate tenant %s/%s not owned by this tenant", r.Kind, r.Name)
		}
		return a.serverSideApplyConditional(ctx, path, r.Object, current)
	}
	created, conflict, err := a.createKubeObject(ctx, collectionPath, r.Object)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	if !conflict {
		return fmt.Errorf("tenant %s/%s create returned no result", r.Kind, r.Name)
	}
	// A 409 means the resource appeared after our read. Re-read ownership before
	// any mutation so a concurrent creator cannot be force-adopted by SSA.
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("verify concurrent tenant %s/%s create: %w", r.Kind, r.Name, err)
	}
	if !found || !tenantObjectOwnedByTask(current, task) {
		return fmt.Errorf("refusing to adopt concurrently created tenant %s/%s", r.Kind, r.Name)
	}
	return a.serverSideApplyConditional(ctx, path, r.Object, current)
}

func (a *agent) deleteTenantResources(ctx context.Context, task controlplane.TenantTask) (bool, error) {
	if err := a.cleanupLegacyTenantBackupSchedule(ctx, task); err != nil {
		return false, err
	}
	namespacePath := "/api/v1/namespaces/" + task.Namespace
	schedulePath := "/apis/velero.io/v1/namespaces/velero/schedules/" + controlplane.TenantBackupScheduleName(task.TenantID)

	namespace, namespaceFound, err := a.getKubeObject(ctx, namespacePath)
	if err != nil {
		return false, fmt.Errorf("verify tenant namespace ownership: %w", err)
	}
	if namespaceFound && !tenantObjectOwnedByTask(namespace, task) {
		return false, fmt.Errorf("refusing to delete a namespace not owned by this tenant")
	}
	schedule, scheduleFound, err := a.getKubeObject(ctx, schedulePath)
	if err != nil {
		return false, fmt.Errorf("verify tenant backup schedule ownership: %w", err)
	}
	if scheduleFound && !tenantObjectOwnedByTask(schedule, task) {
		return false, fmt.Errorf("refusing to delete a backup schedule not owned by this tenant")
	}

	// Delete the cluster-external tenant resource first. This prevents declaring
	// the Tenant deleted while an active Schedule remains in the shared Velero
	// namespace and keeps deletion retryable until both authorities agree.
	if scheduleFound {
		uid, uidErr := kubeObjectUID(schedule)
		if uidErr != nil {
			return false, fmt.Errorf("tenant backup schedule UID: %w", uidErr)
		}
		resourceVersion, rvErr := kubeObjectResourceVersion(schedule)
		if rvErr != nil {
			return false, fmt.Errorf("tenant backup schedule resourceVersion: %w", rvErr)
		}
		alreadyAbsent, deleteErr := a.requestKubeObjectDeletionWithPreconditions(ctx, schedulePath, uid, resourceVersion)
		if deleteErr != nil {
			return false, fmt.Errorf("delete tenant backup schedule: %w", deleteErr)
		}
		if !alreadyAbsent {
			current, stillFound, verifyErr := a.getKubeObject(ctx, schedulePath)
			if verifyErr != nil {
				return false, fmt.Errorf("verify tenant backup schedule deletion: %w", verifyErr)
			}
			if stillFound {
				currentUID, currentErr := kubeObjectUID(current)
				if currentErr != nil {
					return false, fmt.Errorf("verify tenant backup schedule deletion: %w", currentErr)
				}
				if currentUID != uid {
					return false, fmt.Errorf("tenant backup schedule was replaced during deletion")
				}
				return false, nil
			}
		}
	}

	if namespaceFound {
		uid, uidErr := kubeObjectUID(namespace)
		if uidErr != nil {
			return false, fmt.Errorf("tenant namespace UID: %w", uidErr)
		}
		resourceVersion, rvErr := kubeObjectResourceVersion(namespace)
		if rvErr != nil {
			return false, fmt.Errorf("tenant namespace resourceVersion: %w", rvErr)
		}
		alreadyAbsent, deleteErr := a.requestKubeObjectDeletionWithPreconditions(ctx, namespacePath, uid, resourceVersion)
		if deleteErr != nil {
			return false, fmt.Errorf("delete tenant namespace: %w", deleteErr)
		}
		if !alreadyAbsent {
			current, stillFound, verifyErr := a.getKubeObject(ctx, namespacePath)
			if verifyErr != nil {
				return false, fmt.Errorf("verify tenant namespace deletion: %w", verifyErr)
			}
			if stillFound {
				currentUID, currentErr := kubeObjectUID(current)
				if currentErr != nil {
					return false, fmt.Errorf("verify tenant namespace deletion: %w", currentErr)
				}
				if currentUID != uid {
					return false, fmt.Errorf("tenant namespace was replaced during deletion")
				}
				return false, nil
			}
		}
	}
	return true, nil
}

func (a *agent) verifyTenantNamespaceOwnership(ctx context.Context, task controlplane.TenantTask, allowMissing bool) error {
	path := "/api/v1/namespaces/" + task.Namespace
	namespace, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("verify tenant namespace ownership: %w", err)
	}
	if !found {
		if allowMissing {
			return nil
		}
		return fmt.Errorf("tenant namespace %s does not exist", task.Namespace)
	}
	if !tenantObjectOwnedByTask(namespace, task) {
		return fmt.Errorf("refusing to mutate a namespace not owned by this tenant")
	}
	return nil
}

func (a *agent) executeTenantTask(ctx context.Context, task controlplane.TenantTask) controlplane.TenantTaskResult {
	result := controlplane.TenantTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	if err := validateTenantTask(task); err != nil {
		result.Error = err.Error()
		return result
	}
	if task.Action != "DELETE" {
		if err := a.verifyTenantNamespaceOwnership(ctx, task, task.Action == "PROVISION"); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	if task.Action == "DELETE" {
		deleted, err := a.deleteTenantResources(ctx, task)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Success = true
		result.Deleted = deleted
		return result
	}
	if task.Action == "SUSPEND" {
		if err := a.validateSuspendableTenantPods(ctx, task); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	for _, r := range task.Resources {
		if err := a.applyTenantResource(ctx, task, r); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	evidence := make([]controlplane.TenantEvidenceArtifact, 0, len(task.Resources)+1)
	for _, resource := range task.Resources {
		object, found, err := a.getKubeObject(ctx, tenantResourcePath(resource))
		if err != nil || !found {
			result.Error = fmt.Sprintf("verify tenant resource %s/%s: %v", resource.Kind, resource.Name, err)
			return result
		}
		meta, _ := object["metadata"].(map[string]any)
		annotations, _ := meta["annotations"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if annotations["platform.4so.io/desired-digest"] != task.DesiredDigest || labels["platform.4so.io/tenant-id"] != task.TenantID {
			result.Error = fmt.Sprintf("tenant resource %s/%s ownership or digest mismatch", resource.Kind, resource.Name)
			return result
		}
		if err := verifyTenantPolicyReadback(task, resource, object); err != nil {
			result.Error = fmt.Sprintf("tenant policy read-back %s/%s: %v", resource.Kind, resource.Name, err)
			return result
		}
		evidence = append(evidence, tenantObjectEvidence("resource/"+resource.Kind+"/"+resource.Name, resource.Kind+"/"+resource.Name, object))
	}
	if task.Action == "SUSPEND" {
		suspensionEvidence, err := a.suspendTenantPods(ctx, task)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		evidence = append(evidence, suspensionEvidence)
	}
	marker, found, err := a.getKubeObject(ctx, "/api/v1/namespaces/"+task.Namespace+"/configmaps/tenant-platform-state")
	if err != nil || !found {
		result.Error = fmt.Sprintf("verify tenant marker: %v", err)
		return result
	}
	data, _ := marker["data"].(map[string]any)
	observed, _ := data["desiredDigest"].(string)
	if observed != task.DesiredDigest {
		result.Error = "tenant desired/observed digest mismatch"
		result.ObservedDigest = observed
		return result
	}
	psaEvidence, err := a.tenantPodSecurityAdmissionEvidence(ctx, task)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	evidence = append(evidence, psaEvidence)
	if err := a.cleanupLegacyTenantBackupSchedule(ctx, task); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.ObservedDigest = observed
	result.Evidence = evidence
	result.EvidenceDigest = tenantEvidenceDigest(evidence)
	return result
}
func (a *agent) reportTenantTask(ctx context.Context, task controlplane.TenantTask, result controlplane.TenantTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/tenant-tasks/" + task.TenantID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.TenantRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("tenant result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processProviderProfileTask(ctx context.Context) error {
	task, ok, err := a.nextProviderProfileTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.executeProviderProfileTask(execCtx, task)
	return a.reportProviderProfileTask(ctx, task, result)
}

func (a *agent) nextProviderProfileTask(ctx context.Context) (controlplane.ProviderProfileTask, bool, error) {
	var task controlplane.ProviderProfileTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/provider-profile-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("provider profile task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func validateProviderProfileTask(task controlplane.ProviderProfileTask) error {
	if task.ProfileID == "" || task.ProfileRevision < 1 || task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || task.Namespace != "4so-provider-system" {
		return fmt.Errorf("provider profile task identity or namespace is invalid")
	}
	for _, name := range []string{task.ClusterClassName, task.WorkerClassName} {
		if name == "" || len(name) > 63 || strings.ContainsAny(name, "/ \t\r\n") {
			return fmt.Errorf("provider profile class name is invalid")
		}
	}
	switch strings.TrimSpace(task.InfrastructureProvider) {
	case "", "unspecified", "vmware":
	default:
		return fmt.Errorf("provider profile infrastructure provider is invalid")
	}
	return nil
}

func stableObjectDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func providerTemplateRef(value any) (group, kind, name string) {
	m, _ := value.(map[string]any)
	ref, _ := m["templateRef"].(map[string]any)
	apiVersion, _ := ref["apiVersion"].(string)
	kind, _ = ref["kind"].(string)
	name, _ = ref["name"].(string)
	apiVersion = strings.TrimSpace(apiVersion)
	if slash := strings.IndexByte(apiVersion, '/'); slash > 0 && slash < len(apiVersion)-1 {
		group = apiVersion[:slash]
	}
	return strings.TrimSpace(group), strings.TrimSpace(kind), strings.TrimSpace(name)
}

func validateVMwareClusterClass(spec map[string]any, workerClass string) error {
	group, kind, name := providerTemplateRef(spec["infrastructure"])
	if group != "infrastructure.cluster.x-k8s.io" || kind != "VSphereClusterTemplate" || name == "" {
		return fmt.Errorf("VMware provider ClusterClass requires v1beta2 infrastructure.templateRef to infrastructure.cluster.x-k8s.io VSphereClusterTemplate")
	}
	workers, _ := spec["workers"].(map[string]any)
	machineDeployments, _ := workers["machineDeployments"].([]any)
	for _, item := range machineDeployments {
		entry, _ := item.(map[string]any)
		if entry["class"] != workerClass {
			continue
		}
		group, kind, name = providerTemplateRef(entry["infrastructure"])
		if group != "infrastructure.cluster.x-k8s.io" || kind != "VSphereMachineTemplate" || name == "" {
			return fmt.Errorf("VMware provider worker class requires v1beta2 infrastructure.templateRef to infrastructure.cluster.x-k8s.io VSphereMachineTemplate")
		}
		return nil
	}
	return fmt.Errorf("the admitted worker class is not present in ClusterClass")
}

func (a *agent) executeProviderProfileTask(ctx context.Context, task controlplane.ProviderProfileTask) controlplane.ProviderProfileTaskResult {
	result := controlplane.ProviderProfileTaskResult{TaskFenceToken: task.TaskFenceToken}
	if err := validateProviderProfileTask(task); err != nil {
		result.Error = err.Error()
		return result
	}
	path := "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + task.Namespace + "/clusterclasses/" + task.ClusterClassName
	object, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.Error = "read ClusterClass: " + err.Error()
		return result
	}
	if !found {
		result.Error = "ClusterClass was not found in the admitted namespace"
		return result
	}
	if object["apiVersion"] != "cluster.x-k8s.io/v1beta2" || object["kind"] != "ClusterClass" {
		result.Error = "ClusterClass uses an unsupported API version or kind"
		return result
	}
	metadata, _ := object["metadata"].(map[string]any)
	if metadata["name"] != task.ClusterClassName || metadata["namespace"] != task.Namespace {
		result.Error = "ClusterClass metadata does not match the provider profile"
		return result
	}
	spec, _ := object["spec"].(map[string]any)
	if task.InfrastructureProvider == "vmware" {
		if err := validateVMwareClusterClass(spec, task.WorkerClassName); err != nil {
			result.Error = err.Error()
			return result
		}
	} else {
		workers, _ := spec["workers"].(map[string]any)
		machineDeployments, _ := workers["machineDeployments"].([]any)
		workerClassFound := false
		for _, item := range machineDeployments {
			entry, _ := item.(map[string]any)
			if entry["class"] == task.WorkerClassName {
				workerClassFound = true
				break
			}
		}
		if !workerClassFound {
			result.Error = "the admitted worker class is not present in ClusterClass"
			return result
		}
	}
	result.Success = true
	result.ObservedVersion = "cluster.x-k8s.io/v1beta2"
	result.ObservedDigest = stableObjectDigest(map[string]any{"apiVersion": object["apiVersion"], "kind": object["kind"], "name": metadata["name"], "namespace": metadata["namespace"], "spec": spec})
	return result
}

func (a *agent) reportProviderProfileTask(ctx context.Context, task controlplane.ProviderProfileTask, result controlplane.ProviderProfileTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/provider-profile-tasks/" + task.ProfileID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.ProfileRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("provider profile result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processProviderClusterTask(ctx context.Context) error {
	task, ok, err := a.nextProviderClusterTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.executeProviderClusterTask(execCtx, task)
	return a.reportProviderClusterTask(ctx, task, result)
}

func (a *agent) nextProviderClusterTask(ctx context.Context) (controlplane.ProviderClusterTask, bool, error) {
	var task controlplane.ProviderClusterTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/provider-cluster-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("provider cluster task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

const targetNodeMutationRecoveryAnnotation = "platform.4so.io/target-node-mutation-recovery"

func (a *agent) listKubeObjects(ctx context.Context, path string) ([]map[string]any, error) {
	req, err := a.kubeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("list Kubernetes resources %s: %s", res.Status, string(raw))
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Items, nil
}

func (a *agent) mergePatchKubeObject(ctx context.Context, path string, patch map[string]any) error {
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := a.kubeRequest(ctx, http.MethodPatch, path, bytes.NewReader(raw), "application/merge-patch+json")
	if err != nil {
		return err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("merge patch %s: status=%d body=%s", path, res.StatusCode, string(body))
	}
	return nil
}

func machineNodeIdentity(object map[string]any) (name, uid string) {
	status, _ := object["status"].(map[string]any)
	ref, _ := status["nodeRef"].(map[string]any)
	name, _ = ref["name"].(string)
	uid, _ = ref["uid"].(string)
	return strings.TrimSpace(name), strings.TrimSpace(uid)
}
func machineReady(object map[string]any) bool {
	status, _ := object["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	for _, raw := range conditions {
		c, _ := raw.(map[string]any)
		if c["type"] == "Ready" && c["status"] == "True" {
			return true
		}
	}
	return false
}

func (a *agent) targetNodeMutationRecovery(ctx context.Context, task controlplane.ProviderClusterTask) (controlplane.TargetNodeProviderMutation, bool, error) {
	cluster, found, err := a.getKubeObject(ctx, providerClusterPath(task))
	if err != nil || !found {
		return controlplane.TargetNodeProviderMutation{}, false, err
	}
	metadata, _ := cluster["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	raw, _ := annotations[targetNodeMutationRecoveryAnnotation].(string)
	if strings.TrimSpace(raw) == "" {
		return controlplane.TargetNodeProviderMutation{}, false, nil
	}
	var m controlplane.TargetNodeProviderMutation
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return m, false, fmt.Errorf("decode target-node recovery evidence: %w", err)
	}
	want := task.TargetNodeMutation
	if m.Authority != controlplane.TargetNodeProviderMachineLifecycleAuthority || m.Action != want.Action || m.TargetClusterID != want.TargetClusterID || m.NodeName != want.NodeName || m.NodeUID != want.NodeUID || m.InventoryDigest != want.InventoryDigest || m.WindowID != want.WindowID {
		return m, false, fmt.Errorf("target-node recovery evidence does not match task fence")
	}
	return m, true, nil
}

func (a *agent) persistTargetNodeMutationRecovery(ctx context.Context, task controlplane.ProviderClusterTask, m controlplane.TargetNodeProviderMutation) error {
	cluster, found, err := a.getKubeObject(ctx, providerClusterPath(task))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("provider Cluster missing before target-node mutation")
	}
	rv, err := kubeObjectResourceVersion(cluster)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(m)
	return a.mergePatchKubeObject(ctx, providerClusterPath(task), map[string]any{"metadata": map[string]any{"resourceVersion": rv, "annotations": map[string]any{targetNodeMutationRecoveryAnnotation: string(raw)}}})
}
func (a *agent) clearTargetNodeMutationRecovery(ctx context.Context, task controlplane.ProviderClusterTask) error {
	cluster, found, err := a.getKubeObject(ctx, providerClusterPath(task))
	if err != nil || !found {
		return err
	}
	rv, err := kubeObjectResourceVersion(cluster)
	if err != nil {
		return err
	}
	return a.mergePatchKubeObject(ctx, providerClusterPath(task), map[string]any{"metadata": map[string]any{"resourceVersion": rv, "annotations": map[string]any{targetNodeMutationRecoveryAnnotation: nil}}})
}

func (a *agent) resolveExactTargetMachine(ctx context.Context, task controlplane.ProviderClusterTask) (controlplane.TargetNodeProviderMutation, error) {
	if recovered, ok, err := a.targetNodeMutationRecovery(ctx, task); err != nil {
		return recovered, err
	} else if ok {
		return recovered, nil
	}
	m := task.TargetNodeMutation
	selector := url.QueryEscape("cluster.x-k8s.io/cluster-name=" + task.ResourceName)
	items, err := a.listKubeObjects(ctx, "/apis/cluster.x-k8s.io/v1beta1/namespaces/"+task.Namespace+"/machines?labelSelector="+selector)
	if err != nil {
		return m, err
	}
	matches := []map[string]any{}
	for _, obj := range items {
		metadata, _ := obj["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		if _, cp := labels["cluster.x-k8s.io/control-plane"]; cp {
			continue
		}
		nodeName, nodeUID := machineNodeIdentity(obj)
		if nodeName == m.NodeName && nodeUID == m.NodeUID {
			matches = append(matches, obj)
		}
	}
	if len(matches) != 1 {
		return m, fmt.Errorf("exact worker Machine resolution requires exactly one nodeRef match; got %d", len(matches))
	}
	obj := matches[0]
	metadata, _ := obj["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	name, _ := metadata["name"].(string)
	uid, err := kubeObjectUID(obj)
	if err != nil {
		return m, err
	}
	rv, err := kubeObjectResourceVersion(obj)
	if err != nil {
		return m, err
	}
	ms, _ := labels["cluster.x-k8s.io/set-name"].(string)
	md, _ := labels["cluster.x-k8s.io/deployment-name"].(string)
	if strings.TrimSpace(ms) == "" || strings.TrimSpace(md) == "" {
		return m, fmt.Errorf("exact worker Machine lacks MachineSet/MachineDeployment ownership labels")
	}
	m.MachineName, m.MachineUID, m.MachineResourceVersion, m.MachineSetName, m.MachineDeploymentName = strings.TrimSpace(name), uid, rv, strings.TrimSpace(ms), strings.TrimSpace(md)
	m.EvidenceDigest = ""
	m.EvidenceDigest = stableObjectDigest(m)
	if err = a.persistTargetNodeMutationRecovery(ctx, task, m); err != nil {
		return m, err
	}
	return m, nil
}

func (a *agent) exactMachinePath(task controlplane.ProviderClusterTask, m controlplane.TargetNodeProviderMutation) string {
	return "/apis/cluster.x-k8s.io/v1beta1/namespaces/" + task.Namespace + "/machines/" + url.PathEscape(m.MachineName)
}

func (a *agent) applyTargetNodeProviderMutation(ctx context.Context, task controlplane.ProviderClusterTask) (controlplane.TargetNodeProviderMutation, error) {
	m, err := a.resolveExactTargetMachine(ctx, task)
	if err != nil {
		return m, err
	}
	path := a.exactMachinePath(task, m)
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return m, err
	}
	if found {
		uid, err := kubeObjectUID(current)
		if err != nil {
			return m, err
		}
		if uid != m.MachineUID {
			return m, fmt.Errorf("exact Machine UID changed after recovery fence")
		}
		rv, err := kubeObjectResourceVersion(current)
		if err != nil {
			return m, err
		}
		if m.Action == controlplane.TargetNodeActionRemove {
			if err = a.mergePatchKubeObject(ctx, path, map[string]any{"metadata": map[string]any{"resourceVersion": rv, "annotations": map[string]any{"cluster.x-k8s.io/delete-machine": "", "platform.4so.io/target-node-mutation-evidence": m.EvidenceDigest}}}); err != nil {
				return m, err
			}
		} else {
			_, err = a.requestKubeObjectDeletionWithPreconditions(ctx, path, m.MachineUID, rv)
			if err != nil {
				return m, err
			}
		}
	}
	if m.Action == controlplane.TargetNodeActionRemove {
		if err = a.applyProviderClusterResource(ctx, task); err != nil {
			return m, err
		}
	}
	return m, nil
}

func (a *agent) inspectTargetNodeProviderMutation(ctx context.Context, task controlplane.ProviderClusterTask) (bool, error) {
	m := task.TargetNodeMutation
	if strings.TrimSpace(m.MachineName) == "" || strings.TrimSpace(m.MachineUID) == "" {
		return false, fmt.Errorf("target-node mutation identity evidence missing during inspect")
	}
	old, found, err := a.getKubeObject(ctx, a.exactMachinePath(task, m))
	if err != nil {
		return false, err
	}
	if found {
		uid, _ := kubeObjectUID(old)
		if uid == m.MachineUID {
			return false, nil
		}
	}
	if controlplane.IsTargetNodeProviderReplacementAction(m.Action) {
		selector := url.QueryEscape("cluster.x-k8s.io/deployment-name=" + m.MachineDeploymentName + ",cluster.x-k8s.io/cluster-name=" + task.ResourceName)
		items, err := a.listKubeObjects(ctx, "/apis/cluster.x-k8s.io/v1beta1/namespaces/"+task.Namespace+"/machines?labelSelector="+selector)
		if err != nil {
			return false, err
		}
		readyReplacement := false
		for _, obj := range items {
			uid, _ := kubeObjectUID(obj)
			if uid != m.MachineUID && machineReady(obj) {
				readyReplacement = true
				break
			}
		}
		if !readyReplacement {
			return false, nil
		}
	}
	return true, nil
}

func validateProviderClusterTask(task controlplane.ProviderClusterTask) error {
	if task.ProviderClusterID == "" || task.ClusterRevision < 1 || task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || task.Namespace != "4so-provider-system" || !strings.HasPrefix(task.ResourceName, "pf-") || len(task.ResourceName) > 63 {
		return fmt.Errorf("provider cluster task identity or target is invalid")
	}
	if task.TargetNodeMutation.Authority != "" {
		m := task.TargetNodeMutation
		if m.Authority != controlplane.TargetNodeProviderMachineLifecycleAuthority || (m.Action != controlplane.TargetNodeActionRemove && m.Action != controlplane.TargetNodeActionReplace && m.Action != controlplane.TargetNodeActionCertificateRenewal && m.Action != controlplane.TargetNodeActionRemediate) || m.TargetClusterID == "" || m.NodeName == "" || m.NodeUID == "" || !strings.HasPrefix(m.InventoryDigest, "sha256:") || m.WindowID == "" || m.WindowEndsAt.IsZero() {
			return fmt.Errorf("provider target-node mutation envelope is invalid")
		}
	}
	switch task.Action {
	case "APPLY":
		if !strings.HasPrefix(task.DesiredDigest, "sha256:") || len(task.Resource) == 0 {
			return fmt.Errorf("provider APPLY task is incomplete")
		}
		if task.Resource["apiVersion"] != "cluster.x-k8s.io/v1beta2" || task.Resource["kind"] != "Cluster" {
			return fmt.Errorf("provider task can only apply a Cluster API v1beta2 Cluster")
		}
		metadata, _ := task.Resource["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		if metadata["name"] != task.ResourceName || metadata["namespace"] != task.Namespace || labels["platform.4so.io/provider-cluster-id"] != task.ProviderClusterID || labels["platform.4so.io/managed"] != "true" || annotations["platform.4so.io/desired-digest"] != task.DesiredDigest {
			return fmt.Errorf("provider Cluster metadata, ownership or digest is invalid")
		}
	case "INSPECT", "DELETE":
		if len(task.Resource) != 0 {
			return fmt.Errorf("provider inspect/delete task must not include a resource")
		}
	default:
		return fmt.Errorf("provider cluster task action is not allowed")
	}
	return nil
}

func providerClusterPath(task controlplane.ProviderClusterTask) string {
	return "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + task.Namespace + "/clusters/" + task.ResourceName
}

func providerClusterCollectionPath(task controlplane.ProviderClusterTask) string {
	return "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + task.Namespace + "/clusters"
}

func providerClusterOwnership(object map[string]any, task controlplane.ProviderClusterTask) (string, error) {
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	if metadata["name"] != task.ResourceName || metadata["namespace"] != task.Namespace || labels["platform.4so.io/provider-cluster-id"] != task.ProviderClusterID || labels["platform.4so.io/managed"] != "true" {
		return "", fmt.Errorf("refusing to operate a Cluster not owned by this provider cluster")
	}
	digest, _ := annotations["platform.4so.io/desired-digest"].(string)
	return digest, nil
}

func (a *agent) applyProviderClusterResource(ctx context.Context, task controlplane.ProviderClusterTask) error {
	path := providerClusterPath(task)
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("inspect provider Cluster before apply: %w", err)
	}
	if found {
		if _, err := providerClusterOwnership(current, task); err != nil {
			return err
		}
		return a.serverSideApplyConditional(ctx, path, task.Resource, current)
	}
	created, conflict, err := a.createKubeObject(ctx, providerClusterCollectionPath(task), task.Resource)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	if !conflict {
		return fmt.Errorf("provider Cluster create returned no result")
	}
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil {
		return fmt.Errorf("verify concurrent provider Cluster create: %w", err)
	}
	if !found {
		return fmt.Errorf("provider Cluster create conflicted but the object is absent")
	}
	if _, err := providerClusterOwnership(current, task); err != nil {
		return fmt.Errorf("refusing to adopt concurrently created provider Cluster: %w", err)
	}
	return a.serverSideApplyConditional(ctx, path, task.Resource, current)
}

func providerClusterReady(object map[string]any) (bool, string) {
	status, _ := object["status"].(map[string]any)
	phase, _ := status["phase"].(string)
	conditions, _ := status["conditions"].([]any)
	for _, item := range conditions {
		condition, _ := item.(map[string]any)
		if condition["type"] == "Ready" && condition["status"] == "True" {
			return true, phase
		}
	}
	return false, phase
}

func (a *agent) executeProviderClusterTask(ctx context.Context, task controlplane.ProviderClusterTask) controlplane.ProviderClusterTaskResult {
	result := controlplane.ProviderClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	if err := validateProviderClusterTask(task); err != nil {
		result.Error = err.Error()
		return result
	}
	path := providerClusterPath(task)
	switch task.Action {
	case "APPLY":
		if task.TargetNodeMutation.Authority != "" {
			m, err := a.applyTargetNodeProviderMutation(ctx, task)
			if err != nil {
				result.Error = err.Error()
				return result
			}
			result.TargetNodeMutation = m
			task.TargetNodeMutation = m
		} else if err := a.applyProviderClusterResource(ctx, task); err != nil {
			result.Error = err.Error()
			return result
		}
		object, found, err := a.getKubeObject(ctx, path)
		if err != nil || !found {
			result.Error = fmt.Sprintf("verify provider Cluster after apply: %v", err)
			return result
		}
		digest, err := providerClusterOwnership(object, task)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Success = digest == task.DesiredDigest
		result.ObservedDigest = digest
		result.Ready, result.Phase = providerClusterReady(object)
		if !result.Success {
			result.Error = "provider Cluster desired/observed digest mismatch after apply"
		}
		return result
	case "INSPECT":
		if task.TargetNodeMutation.Authority != "" {
			ready, err := a.inspectTargetNodeProviderMutation(ctx, task)
			if err != nil {
				result.Error = err.Error()
				return result
			}
			result.TargetNodeMutation = task.TargetNodeMutation
			if !ready {
				result.Success = true
				result.Ready = false
				result.ObservedDigest = task.DesiredDigest
				result.Phase = "TargetNodeMutationReconciling"
				return result
			}
		}
		object, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		if !found {
			result.Error = "provider Cluster disappeared while reconciling"
			return result
		}
		digest, err := providerClusterOwnership(object, task)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Success = true
		result.ObservedDigest = digest
		result.Ready, result.Phase = providerClusterReady(object)
		if result.Ready && task.TargetNodeMutation.Authority != "" {
			if err := a.clearTargetNodeMutationRecovery(ctx, task); err != nil {
				result.Success = false
				result.Ready = false
				result.Error = "clear target-node recovery evidence: " + err.Error()
			}
		}
		return result
	case "DELETE":
		object, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		if !found {
			result.Success, result.Deleted, result.Phase = true, true, "Deleted"
			return result
		}
		if _, err = providerClusterOwnership(object, task); err != nil {
			result.Error = err.Error()
			return result
		}
		uid, uidErr := kubeObjectUID(object)
		if uidErr != nil {
			result.Error = "provider Cluster UID: " + uidErr.Error()
			return result
		}
		resourceVersion, rvErr := kubeObjectResourceVersion(object)
		if rvErr != nil {
			result.Error = "provider Cluster resourceVersion: " + rvErr.Error()
			return result
		}
		alreadyAbsent, deleteErr := a.requestKubeObjectDeletionWithPreconditions(ctx, path, uid, resourceVersion)
		if deleteErr != nil {
			result.Error = deleteErr.Error()
			return result
		}
		current, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			result.Error = "verify provider Cluster deletion: " + err.Error()
			return result
		}
		if alreadyAbsent {
			found = false
		}
		if found {
			currentUID, currentErr := kubeObjectUID(current)
			if currentErr != nil {
				result.Error = "verify provider Cluster deletion: " + currentErr.Error()
				return result
			}
			if currentUID != uid {
				result.Error = "provider Cluster was replaced during deletion"
				return result
			}
		}
		result.Success = true
		result.Deleted = !found
		result.Phase = "Deleting"
		if result.Deleted {
			result.Phase = "Deleted"
		}
		return result
	}
	result.Error = "provider cluster action was not executed"
	return result
}

func (a *agent) reportProviderClusterTask(ctx context.Context, task controlplane.ProviderClusterTask, result controlplane.ProviderClusterTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/provider-cluster-tasks/" + task.ProviderClusterID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.ClusterRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("provider cluster result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processClusterMaintenanceTask(ctx context.Context) error {
	task, ok, err := a.nextClusterMaintenanceTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.executeClusterMaintenanceTask(execCtx, task)
	return a.reportClusterMaintenanceTask(ctx, task, result)
}

func (a *agent) nextClusterMaintenanceTask(ctx context.Context) (controlplane.ClusterMaintenanceTask, bool, error) {
	var task controlplane.ClusterMaintenanceTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/maintenance-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return task, false, fmt.Errorf("maintenance task API %s: %s", res.Status, string(body))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func maintenanceTaskAction(task controlplane.ClusterMaintenanceTask) controlplane.TargetNodeLifecycleAction {
	if task.Action == "" {
		return controlplane.TargetNodeActionDrain
	}
	return task.Action
}

func validateClusterMaintenanceTask(task controlplane.ClusterMaintenanceTask) error {
	action := maintenanceTaskAction(task)
	if action != controlplane.TargetNodeActionDrain && action != controlplane.TargetNodeActionOSPatch {
		return fmt.Errorf("unsupported cluster maintenance action %s", action)
	}
	if action == controlplane.TargetNodeActionOSPatch && (task.HostActionTimeoutSeconds < 60 || task.HostActionTimeoutSeconds > 7200) {
		return fmt.Errorf("invalid OS patch host action timeout")
	}
	if task.Method != controlplane.ClusterMaintenanceAuthorityMethod || strings.TrimSpace(task.RunID) == "" || task.RunRevision <= 0 || strings.TrimSpace(task.OperationID) == "" || task.OperationFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) || strings.TrimSpace(task.ClusterID) == "" || len(task.NodeNames) == 0 || !strings.HasPrefix(task.InventoryDigest, "sha256:") || task.DrainTimeoutSeconds < 30 || task.DrainTimeoutSeconds > 3600 {
		return fmt.Errorf("invalid cluster maintenance task contract")
	}
	seen := map[string]bool{}
	for _, raw := range task.NodeNames {
		n := strings.TrimSpace(raw)
		if n == "" || seen[n] {
			return fmt.Errorf("maintenance node names must be unique")
		}
		uid := strings.TrimSpace(task.NodeUIDs[n])
		if uid == "" {
			return fmt.Errorf("maintenance node UID is required for %s", n)
		}
		seen[n] = true
	}
	if len(task.NodeUIDs) != len(seen) {
		return fmt.Errorf("maintenance node UID set must match node names")
	}
	return nil
}

type maintenanceNodeView struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
}
type maintenancePodList struct {
	Items []maintenancePod `json:"items"`
}
type maintenancePod struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []struct {
			Kind       string `json:"kind"`
			Controller *bool  `json:"controller,omitempty"`
		} `json:"ownerReferences"`
		DeletionTimestamp *time.Time `json:"deletionTimestamp,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Volumes []struct {
			Name     string         `json:"name"`
			EmptyDir map[string]any `json:"emptyDir,omitempty"`
		} `json:"volumes"`
	} `json:"spec"`
}

func maintenancePodKey(p maintenancePod) string { return p.Metadata.Namespace + "/" + p.Metadata.Name }
func skipMaintenancePod(p maintenancePod) bool {
	if strings.TrimSpace(p.Metadata.Annotations["kubernetes.io/config.mirror"]) != "" {
		return true
	}
	for _, owner := range p.Metadata.OwnerReferences {
		if strings.EqualFold(owner.Kind, "DaemonSet") && owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

func maintenancePodSafetyError(p maintenancePod) error {
	if strings.TrimSpace(p.Metadata.UID) == "" || strings.TrimSpace(p.Metadata.ResourceVersion) == "" {
		return fmt.Errorf("pod %s is missing UID/resourceVersion identity", maintenancePodKey(p))
	}
	hasController := false
	for _, owner := range p.Metadata.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			hasController = true
			break
		}
	}
	if !hasController {
		return fmt.Errorf("unmanaged pod %s has no controller owner; explicit force semantics are required", maintenancePodKey(p))
	}
	for _, volume := range p.Spec.Volumes {
		if volume.EmptyDir != nil {
			return fmt.Errorf("pod %s uses emptyDir volume %s; explicit ephemeral-data-loss approval is required", maintenancePodKey(p), volume.Name)
		}
	}
	return nil
}

func (a *agent) setNodeUnschedulable(ctx context.Context, node, expectedUID string, value bool) error {
	path := "/api/v1/nodes/" + url.PathEscape(node)
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": expectedUID},
		{"op": "add", "path": "/spec/unschedulable", "value": value},
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := a.kubeRequest(ctx, http.MethodPatch, path, bytes.NewReader(raw), "application/json-patch+json")
	if err != nil {
		return err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("fenced node patch %s: %s: %s", node, res.Status, string(body))
	}
	return nil
}
func (a *agent) maintenancePodsOnNode(ctx context.Context, node string) ([]maintenancePod, error) {
	var list maintenancePodList
	path := "/api/v1/pods?fieldSelector=" + url.QueryEscape("spec.nodeName="+node)
	if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}
func (a *agent) evictMaintenancePod(ctx context.Context, p maintenancePod) (bool, bool, error) {
	path := "/api/v1/namespaces/" + url.PathEscape(p.Metadata.Namespace) + "/pods/" + url.PathEscape(p.Metadata.Name) + "/eviction"
	body := map[string]any{
		"apiVersion": "policy/v1",
		"kind":       "Eviction",
		"metadata":   map[string]any{"name": p.Metadata.Name, "namespace": p.Metadata.Namespace},
		"deleteOptions": map[string]any{
			"preconditions": map[string]any{"uid": p.Metadata.UID, "resourceVersion": p.Metadata.ResourceVersion},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return false, false, err
	}
	req, err := a.kubeRequest(ctx, http.MethodPost, path, bytes.NewReader(raw), "application/json")
	if err != nil {
		return false, false, err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return false, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode/100 == 2 {
		return true, false, nil
	}
	if res.StatusCode == http.StatusTooManyRequests {
		io.Copy(io.Discard, io.LimitReader(res.Body, 2048))
		return false, true, nil
	}
	if res.StatusCode == http.StatusConflict {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return false, false, fmt.Errorf("evict %s identity/resourceVersion conflict: %s", maintenancePodKey(p), string(b))
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return false, false, fmt.Errorf("evict %s: %s: %s", maintenancePodKey(p), res.Status, string(b))
}

func (a *agent) drainMaintenanceNode(ctx context.Context, node string, timeout time.Duration, result *controlplane.NodeMaintenanceResult) error {
	deadline := time.Now().Add(timeout)
	evicted := map[string]bool{}
	blocked := map[string]bool{}
	skipped := map[string]bool{}
	for {
		pods, err := a.maintenancePodsOnNode(ctx, node)
		if err != nil {
			return err
		}
		// Admission must complete for the entire current Pod set before any eviction.
		// Otherwise list ordering could evict safe Pods before a later unmanaged or
		// emptyDir-backed Pod forces the drain to fail closed.
		for _, p := range pods {
			if skipMaintenancePod(p) || p.Metadata.DeletionTimestamp != nil {
				continue
			}
			if err := maintenancePodSafetyError(p); err != nil {
				return err
			}
		}
		remaining := 0
		for _, p := range pods {
			key := maintenancePodKey(p)
			if skipMaintenancePod(p) {
				skipped[key] = true
				continue
			}
			if p.Metadata.DeletionTimestamp != nil {
				remaining++
				continue
			}
			remaining++
			ok, pdbBlocked, evictErr := a.evictMaintenancePod(ctx, p)
			if evictErr != nil {
				return evictErr
			}
			if ok {
				evicted[key] = true
			}
			if pdbBlocked {
				blocked[key] = true
			}
		}
		if remaining == 0 {
			for k := range evicted {
				result.EvictedPods = append(result.EvictedPods, k)
			}
			for k := range skipped {
				result.SkippedPods = append(result.SkippedPods, k)
			}
			for k := range blocked {
				result.PDBBlockedPods = append(result.PDBBlockedPods, k)
			}
			sort.Strings(result.EvictedPods)
			sort.Strings(result.SkippedPods)
			sort.Strings(result.PDBBlockedPods)
			return nil
		}
		if !time.Now().Before(deadline) {
			for k := range evicted {
				result.EvictedPods = append(result.EvictedPods, k)
			}
			for k := range skipped {
				result.SkippedPods = append(result.SkippedPods, k)
			}
			for k := range blocked {
				result.PDBBlockedPods = append(result.PDBBlockedPods, k)
			}
			sort.Strings(result.EvictedPods)
			sort.Strings(result.SkippedPods)
			sort.Strings(result.PDBBlockedPods)
			if len(result.PDBBlockedPods) > 0 {
				return fmt.Errorf("drain timeout: PodDisruptionBudget blocked %s", strings.Join(result.PDBBlockedPods, ","))
			}
			return fmt.Errorf("drain timeout waiting for %d pod(s)", remaining)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(maintenancePollInterval):
		}
	}
}

func (a *agent) maintainNode(ctx context.Context, node, expectedUID string, timeout time.Duration) controlplane.NodeMaintenanceResult {
	return a.maintainNodeTask(ctx, controlplane.ClusterMaintenanceTask{Action: controlplane.TargetNodeActionDrain}, node, expectedUID, timeout)
}

func (a *agent) maintainNodeTask(ctx context.Context, task controlplane.ClusterMaintenanceTask, node, expectedUID string, timeout time.Duration) controlplane.NodeMaintenanceResult {
	result := controlplane.NodeMaintenanceResult{NodeName: node}
	var view maintenanceNodeView
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/nodes/"+url.PathEscape(node), nil, &view); err != nil {
		result.Error = err.Error()
		return result
	}
	if strings.TrimSpace(view.Metadata.UID) == "" || view.Metadata.UID != expectedUID {
		result.Error = "node UID no longer matches the approved inventory identity"
		return result
	}
	if view.Spec.Unschedulable {
		result.Error = "node was already unschedulable before this maintenance run; ownership is ambiguous"
		return result
	}
	if err := a.setNodeUnschedulable(ctx, node, expectedUID, true); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Cordoned = true
	result.DrainAttempted = true
	drainErr := a.drainMaintenanceNode(ctx, node, timeout, &result)
	if drainErr == nil {
		result.Drained = true
	}
	var hostErr error
	if drainErr == nil && maintenanceTaskAction(task) == controlplane.TargetNodeActionOSPatch {
		result.HostActionAttempted = true
		hostTimeout := time.Duration(task.HostActionTimeoutSeconds) * time.Second
		hostCtx, cancel := context.WithTimeout(ctx, hostTimeout)
		hostResult, evidence, err := a.executeOSPatchJob(hostCtx, task, node, expectedUID)
		cancel()
		if err != nil {
			hostErr = err
		} else {
			result.HostActionSucceeded = true
			result.HostActionAuthority = hostResult.Authority
			result.HostActionEvidence = evidence
			result.RebootRequired = hostResult.RebootRequired
		}
	}
	uncordonErr := a.setNodeUnschedulable(ctx, node, expectedUID, false)
	if uncordonErr == nil {
		result.Uncordoned = true
	}
	parts := []string{}
	if drainErr != nil {
		parts = append(parts, drainErr.Error())
	}
	if hostErr != nil {
		parts = append(parts, "host action failed: "+hostErr.Error())
	}
	if uncordonErr != nil {
		parts = append(parts, "uncordon failed: "+uncordonErr.Error())
	}
	if len(parts) > 0 {
		result.Error = strings.Join(parts, "; ")
	}
	return result
}

func (a *agent) executeClusterMaintenanceTask(ctx context.Context, task controlplane.ClusterMaintenanceTask) controlplane.ClusterMaintenanceTaskResult {
	result := controlplane.ClusterMaintenanceTaskResult{OperationFenceToken: task.OperationFenceToken}
	if err := validateClusterMaintenanceTask(task); err != nil {
		result.Error = err.Error()
		return result
	}
	if task.Action == "" {
		task.Action = controlplane.TargetNodeActionDrain
	}
	for _, node := range task.NodeNames {
		nr := a.maintainNodeTask(ctx, task, node, task.NodeUIDs[node], time.Duration(task.DrainTimeoutSeconds)*time.Second)
		result.Results = append(result.Results, nr)
		if nr.Error != "" {
			result.Error = "node " + node + ": " + nr.Error
			return result
		}
	}
	result.Success = true
	return result
}

func (a *agent) reportClusterMaintenanceTask(ctx context.Context, task controlplane.ClusterMaintenanceTask, result controlplane.ClusterMaintenanceTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/maintenance-tasks/" + task.RunID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.RunRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("maintenance result API %s: %s", res.Status, string(b))
	}
	return nil
}
