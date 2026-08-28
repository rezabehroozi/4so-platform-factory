package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"platform.4so.io/factory/internal/buildinfo"
	"strings"
	"sync"
	"syscall"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/disasterrecovery"
	"platform.4so.io/factory/internal/fielddiagnostics"
	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/installeraccess"
	"platform.4so.io/factory/internal/lifecycle"
)

var version = buildinfo.Version

//go:embed static/*
var staticFiles embed.FS

func handleCommandLine(args []string, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return true, nil
	}
	if len(args) != 1 {
		return false, fmt.Errorf("platform-installer accepts no daemon arguments; use --help for usage")
	}
	switch args[0] {
	case "--version", "version":
		fmt.Fprintln(output, version)
		return false, nil
	case "--help", "-h", "help":
		fmt.Fprintln(output, "Usage: platform-installer [--help|--version]")
		fmt.Fprintln(output, "Run with no arguments to start the installer service; runtime configuration is supplied through PLATFORM_INSTALLER_* environment variables.")
		return false, nil
	default:
		return false, fmt.Errorf("unknown platform-installer argument %q; use --help for usage", args[0])
	}
}

type installerServer struct {
	runner           *bootstrap.Runner
	access           *installeraccess.Manager
	transport        installeraccess.TransportStatus
	executionEnabled bool
	logger           *slog.Logger
	lifecycle        *lifecycle.Manager
	disasterRecovery *disasterrecovery.Manager
	mutationMu       sync.Mutex
	bootstrapActive  bool
}

func main() {
	run, err := handleCommandLine(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !run {
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	bundleDir := getenv("PLATFORM_INSTALLER_BUNDLE_DIR", "/opt/4so-platform-factory/bundle")
	stateDir := getenv("PLATFORM_INSTALLER_STATE_DIR", "/var/lib/4so-platform-installer")
	listen := getenv("PLATFORM_INSTALLER_LISTEN", "127.0.0.1:9080")
	simulation := strings.EqualFold(os.Getenv("PLATFORM_INSTALLER_SIMULATION"), "true")
	executionEnabled := strings.EqualFold(os.Getenv("PLATFORM_INSTALLER_ALLOW_EXECUTION"), "true")
	tlsCertFile := strings.TrimSpace(os.Getenv("PLATFORM_INSTALLER_TLS_CERT_FILE"))
	tlsKeyFile := strings.TrimSpace(os.Getenv("PLATFORM_INSTALLER_TLS_KEY_FILE"))
	allowInsecureHTTP := strings.EqualFold(os.Getenv("PLATFORM_INSTALLER_ALLOW_INSECURE_HTTP"), "true")
	transport, err := installeraccess.ValidateTransport(listen, tlsCertFile, tlsKeyFile, allowInsecureHTTP, time.Now())
	if err != nil {
		logger.Error("installer transport validation failed", "error", err)
		os.Exit(1)
	}
	access, loaded, err := installeraccess.LoadOrCreate(stateDir, strings.TrimSpace(os.Getenv("PLATFORM_INSTALLER_BOOTSTRAP_TOKEN")), time.Now())
	if err != nil {
		logger.Error("bootstrap token initialization failed", "error", err)
		os.Exit(1)
	}
	logger.Info("installer access initialized", "token_file", loaded.Status.TokenFile, "token_source", loaded.Status.Source, "token_fingerprint", loaded.Status.Fingerprint, "generated", loaded.Generated, "transport_mode", transport.Mode)
	if transport.InsecureOverride {
		logger.Warn("installer is using explicit insecure HTTP override", "listen", transport.Listen)
	}
	system := bootstrap.System(bootstrap.LocalSystem{})
	if simulation {
		simulationRoot := getenv("PLATFORM_INSTALLER_SIMULATION_ROOT", "/tmp/4so-platform-installer-simulation")
		system = &bootstrap.SimulatedSystem{Root: simulationRoot}
	}
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: version, BundleDir: bundleDir, StateDir: stateDir, Simulation: simulation, RequireBundleLock: true, System: system})
	if err != nil {
		logger.Error("create bootstrap runner", "error", err)
		os.Exit(1)
	}
	lifecycleManager, err := lifecycle.New(lifecycle.Options{StateDir: stateDir, BundleDir: bundleDir, Simulation: simulation, RequireBundleLock: true, System: system})
	if err != nil {
		logger.Error("create lifecycle manager", "error", err)
		os.Exit(1)
	}
	drManager, err := disasterrecovery.New(disasterrecovery.Options{StateDir: stateDir, BundleDir: bundleDir, Simulation: simulation, RequireBundleLock: true, System: system})
	if err != nil {
		logger.Error("create disaster recovery manager", "error", err)
		os.Exit(1)
	}
	currentBootstrap, statusErr := runner.Status()
	if statusErr != nil {
		logger.Error("load durable bootstrap status", "error", statusErr)
		os.Exit(1)
	}
	bootstrapInterrupted := currentBootstrap != nil && currentBootstrap.State != bootstrap.RunSucceeded
	if executionEnabled {
		if err := validateExclusiveDurableOperations(bootstrapInterrupted, lifecycleManager.HasActive(), drManager.HasActive()); err != nil {
			logger.Error("conflicting durable mutations require operator recovery", "error", err)
			os.Exit(1)
		}
		currentRequest := installation.InstallRequest{}
		if currentBootstrap != nil {
			currentRequest = currentBootstrap.Request
		}
		lifecycleResumed := lifecycleManager.Reconcile(context.Background())
		drResumed := drManager.Reconcile(context.Background(), currentRequest)
		if lifecycleResumed > 0 || drResumed > 0 {
			logger.Info("durable operation reconciliation started", "lifecycle_runs", lifecycleResumed, "disaster_recovery_runs", drResumed)
		}
	}
	application := &installerServer{runner: runner, access: access, transport: transport, executionEnabled: executionEnabled, logger: logger, lifecycle: lifecycleManager, disasterRecovery: drManager}
	mux := http.NewServeMux()
	application.routes(mux)
	srv := &http.Server{Addr: listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	logger.Info("bootstrap installer started", "listen", listen, "version", version, "execution_enabled", executionEnabled, "simulation", simulation, "transport_mode", transport.Mode)
	if transport.Mode == "https" {
		err = srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("bootstrap installer failed", "error", err)
		os.Exit(1)
	}
}

func (s *installerServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
	})
	mux.Handle("GET /api/v1/status", s.auth(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/v1/access/status", s.auth(http.HandlerFunc(s.accessStatus)))
	mux.Handle("POST /api/v1/access/token/rotate", s.auth(http.HandlerFunc(s.rotateAccessToken)))
	mux.Handle("GET /api/v1/profiles", s.auth(http.HandlerFunc(s.profiles)))
	mux.Handle("GET /api/v1/integrations", s.auth(http.HandlerFunc(s.integrations)))
	mux.Handle("GET /api/v1/tls/ca", s.auth(http.HandlerFunc(s.tlsCA)))
	mux.Handle("GET /api/v1/gitops/status", s.auth(http.HandlerFunc(s.gitOpsStatus)))
	mux.Handle("GET /api/v1/ha/status", s.auth(http.HandlerFunc(s.haStatus)))
	mux.Handle("GET /api/v1/airgap/status", s.auth(http.HandlerFunc(s.airgapStatus)))
	mux.Handle("GET /api/v1/bundle/status", s.auth(http.HandlerFunc(s.bundleStatus)))
	mux.Handle("GET /api/v1/preflight", s.auth(http.HandlerFunc(s.preflightStatus)))
	mux.Handle("POST /api/v1/preflight", s.auth(http.HandlerFunc(s.preflight)))
	mux.Handle("GET /api/v1/field-evidence/report", s.auth(http.HandlerFunc(s.fieldEvidenceReport)))
	mux.Handle("POST /api/v1/field-evidence/verify", s.auth(http.HandlerFunc(s.verifyFieldEvidence)))
	mux.Handle("GET /api/v1/diagnostics/report", s.auth(http.HandlerFunc(s.diagnosticsReport)))
	mux.Handle("POST /api/v1/diagnostics/verify", s.auth(http.HandlerFunc(s.verifyDiagnostics)))
	mux.Handle("GET /api/v1/ssh/trust/status", s.auth(http.HandlerFunc(s.sshTrustStatus)))
	mux.Handle("POST /api/v1/secrets/ssh-private-key", s.auth(http.HandlerFunc(s.storeSSHPrivateKey)))
	mux.Handle("POST /api/v1/secrets/ssh-known-hosts", s.auth(http.HandlerFunc(s.storeSSHKnownHosts)))
	mux.Handle("GET /api/v1/disaster-recovery/runs", s.auth(http.HandlerFunc(s.disasterRecoveryRuns)))
	mux.Handle("POST /api/v1/disaster-recovery/backup", s.auth(http.HandlerFunc(s.disasterRecoveryBackup)))
	mux.Handle("POST /api/v1/disaster-recovery/restore", s.auth(http.HandlerFunc(s.disasterRecoveryRestore)))
	mux.Handle("POST /api/v1/plan", s.auth(http.HandlerFunc(s.plan)))
	mux.Handle("POST /api/v1/start", s.auth(http.HandlerFunc(s.start)))
	mux.Handle("POST /api/v1/resume", s.auth(http.HandlerFunc(s.resume)))
	mux.Handle("GET /api/v1/lifecycle/runs", s.auth(http.HandlerFunc(s.lifecycleRuns)))
	mux.Handle("GET /api/v1/lifecycle/backups/{service}", s.auth(http.HandlerFunc(s.lifecycleBackups)))
	mux.Handle("POST /api/v1/lifecycle/backup", s.auth(http.HandlerFunc(s.lifecycleBackup)))
	mux.Handle("POST /api/v1/lifecycle/restore", s.auth(http.HandlerFunc(s.lifecycleRestore)))
	mux.Handle("POST /api/v1/lifecycle/upgrade", s.auth(http.HandlerFunc(s.lifecycleUpgrade)))
	mux.Handle("POST /api/v1/lifecycle/upgrade-recovery", s.auth(http.HandlerFunc(s.lifecycleUpgradeRecovery)))
	content, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(content)))
}

func (s *installerServer) haStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := s.runner.HAStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "HA_STATUS_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}
func (s *installerServer) bundleStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := s.runner.BundleStatus()
	if err != nil {
		writeError(w, http.StatusConflict, "BUNDLE_ADMISSION_FAILED", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}

func (s *installerServer) preflightStatus(w http.ResponseWriter, _ *http.Request) {
	report, err := s.runner.PreflightStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "PREFLIGHT_STATUS_FAILED", err.Error())
		return
	}
	if report == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "NOT_RUN"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *installerServer) preflight(w http.ResponseWriter, r *http.Request) {
	var request bootstrap.StartRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.mutationMu.Lock()
	if s.bootstrapActive {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "PREFLIGHT_CONFLICT", "bootstrap execution is active")
		return
	}
	report, err := s.runner.Preflight(r.Context(), request.Installation)
	s.mutationMu.Unlock()
	if err != nil {
		if errors.Is(err, bootstrap.ErrBootstrapExecutionActive) || errors.Is(err, bootstrap.ErrPreflightEvidenceOwned) {
			writeError(w, http.StatusConflict, "PREFLIGHT_CONFLICT", err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "PREFLIGHT_FAILED", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *installerServer) collectRuntimeSnapshots() (fieldevidence.Snapshots, error) {
	var empty fieldevidence.Snapshots
	bundle, err := s.runner.BundleStatus()
	if err != nil {
		return empty, fmt.Errorf("bundle admission: %w", err)
	}
	preflight, err := s.runner.PreflightStatus()
	if err != nil {
		return empty, fmt.Errorf("preflight status: %w", err)
	}
	if preflight == nil {
		return empty, errors.New("preflight has not been run")
	}
	run, err := s.runner.Status()
	if err != nil {
		return empty, fmt.Errorf("installation status: %w", err)
	}
	if run == nil {
		return empty, errors.New("installation has not started")
	}
	gitops, err := s.runner.GitOpsStatus()
	if errors.Is(err, os.ErrNotExist) {
		gitops = bootstrap.GitOpsHandoverStatus{State: "NOT_STARTED"}
	} else if err != nil {
		return empty, fmt.Errorf("GitOps status: %w", err)
	}
	ha, err := s.runner.HAStatus()
	if err != nil {
		return empty, fmt.Errorf("HA status: %w", err)
	}
	airgap, err := s.runner.AirgapStatus()
	if err != nil {
		return empty, fmt.Errorf("air-gap status: %w", err)
	}
	return fieldevidence.Snapshots{
		BundleAdmission: bundle, Preflight: *preflight, InstallationRun: *run, GitOpsStatus: gitops,
		HAStatus: ha, AirgapStatus: airgap, LifecycleRuns: s.lifecycle.List(), DisasterRecoveryRuns: s.disasterRecovery.List(),
	}, nil
}

func (s *installerServer) buildFieldEvidenceReport() (fieldevidence.Report, error) {
	var empty fieldevidence.Report
	snapshots, err := s.collectRuntimeSnapshots()
	if err != nil {
		return empty, err
	}
	return fieldevidence.Build(version, snapshots, time.Now())
}

func (s *installerServer) fieldEvidenceReport(w http.ResponseWriter, _ *http.Request) {
	report, err := s.buildFieldEvidenceReport()
	if err != nil {
		writeError(w, http.StatusConflict, "FIELD_EVIDENCE_NOT_READY", err.Error())
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=field-execution-evidence-"+report.Metadata.ID+".json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, report)
}

func (s *installerServer) verifyFieldEvidence(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "FIELD_EVIDENCE_READ_FAILED", err.Error())
		return
	}
	result, err := fieldevidence.Verify(raw)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "FIELD_EVIDENCE_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *installerServer) diagnosticsReport(w http.ResponseWriter, _ *http.Request) {
	snapshots, err := s.collectRuntimeSnapshots()
	if err != nil {
		writeError(w, http.StatusConflict, "DIAGNOSTICS_NOT_READY", err.Error())
		return
	}
	report, err := fielddiagnostics.Build(version, snapshots, time.Now())
	if err != nil {
		writeError(w, http.StatusConflict, "DIAGNOSTICS_BUILD_FAILED", err.Error())
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=field-diagnostic-"+report.Metadata.ID+".json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, report)
}

func (s *installerServer) verifyDiagnostics(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "DIAGNOSTICS_READ_FAILED", err.Error())
		return
	}
	result, err := fielddiagnostics.Verify(raw)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DIAGNOSTICS_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *installerServer) airgapStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := s.runner.AirgapStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "AIRGAP_STATUS_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}
func (s *installerServer) storeSSHPrivateKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PrivateKey string `json:"privateKey"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.mutationMu.Lock()
	if s.bootstrapActive {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", "bootstrap execution is active")
		return
	}
	err := s.runner.StoreSSHPrivateKey([]byte(request.PrivateKey))
	s.mutationMu.Unlock()
	if err != nil {
		if errors.Is(err, bootstrap.ErrBootstrapExecutionActive) {
			writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		} else {
			writeError(w, http.StatusBadRequest, "SSH_KEY_REJECTED", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"stored": true, "credentialRef": "secret://installer/ssh-private-key"})
}
func (s *installerServer) sshTrustStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := s.runner.SSHTrustStatus()
	if err != nil {
		writeError(w, http.StatusConflict, "SSH_TRUST_INVALID", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}

func (s *installerServer) storeSSHKnownHosts(w http.ResponseWriter, r *http.Request) {
	var request struct {
		KnownHosts string `json:"knownHosts"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.mutationMu.Lock()
	if s.bootstrapActive {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", "bootstrap execution is active")
		return
	}
	status, err := s.runner.StoreSSHKnownHosts([]byte(request.KnownHosts))
	s.mutationMu.Unlock()
	if err != nil {
		if errors.Is(err, bootstrap.ErrBootstrapExecutionActive) {
			writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		} else {
			writeError(w, http.StatusBadRequest, "SSH_KNOWN_HOSTS_REJECTED", err.Error())
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, status)
}
func validateExclusiveDurableOperations(bootstrapActive, lifecycleActive, disasterRecoveryActive bool) error {
	active := 0
	if bootstrapActive {
		active++
	}
	if lifecycleActive {
		active++
	}
	if disasterRecoveryActive {
		active++
	}
	if active > 1 {
		return errors.New("bootstrap, lifecycle and disaster-recovery mutations must be mutually exclusive")
	}
	return nil
}

func (s *installerServer) bootstrapInterrupted() bool {
	if s.runner == nil {
		return false
	}
	run, err := s.runner.Status()
	return err == nil && run != nil && run.State != bootstrap.RunSucceeded
}

func (s *installerServer) bootstrapExecutionActiveLocked() bool {
	if !s.bootstrapActive {
		return false
	}
	if s.runner == nil {
		return true
	}
	run, err := s.runner.Status()
	if err != nil || run == nil {
		return true
	}
	// Runner terminal state is persisted only after all bootstrap steps have
	// completed. The goroutine clears bootstrapActive immediately afterwards,
	// but API clients can observe the durable terminal state in that tiny
	// interval. Treat the durable terminal state as authoritative so a caller
	// that observed SUCCEEDED is not rejected by stale in-memory activity.
	return run.State != bootstrap.RunSucceeded && run.State != bootstrap.RunFailed
}

func (s *installerServer) mutationConflictLocked(target string) error {
	if target != "bootstrap" && (s.bootstrapExecutionActiveLocked() || s.bootstrapInterrupted()) {
		return errors.New("bootstrap mutation is active or requires resume")
	}
	if s.lifecycle != nil && s.lifecycle.HasActive() && target != "lifecycle" {
		return errors.New("service lifecycle mutation is active")
	}
	if s.disasterRecovery != nil && s.disasterRecovery.HasActive() && target != "disaster-recovery" {
		return errors.New("disaster-recovery mutation is active")
	}
	return nil
}

func (s *installerServer) disasterRecoveryRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.disasterRecovery.List())
}
func (s *installerServer) currentInstallRequest() (installation.InstallRequest, error) {
	run, err := s.runner.Status()
	if err != nil {
		return installation.InstallRequest{}, err
	}
	if run == nil {
		return installation.InstallRequest{}, errors.New("installation has not started")
	}
	if run.State != bootstrap.RunSucceeded {
		return installation.InstallRequest{}, fmt.Errorf("installation must be SUCCEEDED before lifecycle or disaster recovery; current state is %s", run.State)
	}
	return run.Request, nil
}
func (s *installerServer) disasterRecoveryBackup(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("disaster-recovery"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	req, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	run, err := s.disasterRecovery.StartBackup(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusConflict, "DR_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}
func (s *installerServer) disasterRecoveryRestore(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("disaster-recovery"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	var request disasterrecovery.RestoreRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	request.BackupID = strings.TrimSpace(request.BackupID)
	if request.BackupID == "" || strings.TrimSpace(r.Header.Get("X-Confirm-Restore")) != "restore:"+request.BackupID {
		writeError(w, http.StatusPreconditionRequired, "RESTORE_CONFIRMATION_REQUIRED", "X-Confirm-Restore must bind the exact backup id")
		return
	}
	req, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	run, err := s.disasterRecovery.StartRestore(r.Context(), req, request.BackupID)
	if err != nil {
		writeError(w, http.StatusConflict, "DR_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *installerServer) gitOpsStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := s.runner.GitOpsStatus()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusOK, map[string]string{"state": "NOT_STARTED"})
			return
		}
		writeError(w, http.StatusInternalServerError, "GITOPS_STATUS_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *installerServer) lifecycleRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.lifecycle.List())
}

func (s *installerServer) lifecycleBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := s.lifecycle.Backups(r.PathValue("service"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, backups)
}

func (s *installerServer) lifecycleBackup(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("lifecycle"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	installRequest, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	var request lifecycle.BackupRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	run, err := s.lifecycle.StartBackup(r.Context(), request.Service, installRequest.ProfileID)
	if err != nil {
		writeError(w, http.StatusConflict, "LIFECYCLE_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *installerServer) lifecycleRestore(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("lifecycle"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	var request lifecycle.RestoreRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	request.Service = strings.TrimSpace(request.Service)
	request.BackupID = strings.TrimSpace(request.BackupID)
	if request.Service == "" || request.BackupID == "" || strings.TrimSpace(r.Header.Get("X-Confirm-Restore")) != "restore:"+request.Service+":"+request.BackupID {
		writeError(w, http.StatusPreconditionRequired, "RESTORE_CONFIRMATION_REQUIRED", "X-Confirm-Restore must bind the exact service and backup id")
		return
	}
	installRequest, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	run, err := s.lifecycle.StartRestore(r.Context(), request, installRequest.ProfileID)
	if err != nil {
		writeError(w, http.StatusConflict, "LIFECYCLE_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *installerServer) lifecycleUpgrade(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("lifecycle"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	installRequest, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	var request lifecycle.UpgradeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	run, err := s.lifecycle.StartUpgrade(r.Context(), request, installRequest.ProfileID)
	if err != nil {
		writeError(w, http.StatusConflict, "LIFECYCLE_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *installerServer) lifecycleUpgradeRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationConflictLocked("lifecycle"); err != nil {
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	var request lifecycle.UpgradeRecoveryRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	request.UpgradeRunID = strings.TrimSpace(request.UpgradeRunID)
	if request.UpgradeRunID == "" || strings.TrimSpace(r.Header.Get("X-Confirm-Upgrade-Recovery")) != "recover:"+request.UpgradeRunID {
		writeError(w, http.StatusPreconditionRequired, "UPGRADE_RECOVERY_CONFIRMATION_REQUIRED", "X-Confirm-Upgrade-Recovery must bind the exact failed upgrade run as recover:<upgradeRunId>")
		return
	}
	installRequest, err := s.currentInstallRequest()
	if err != nil {
		writeError(w, http.StatusConflict, "INSTALLATION_REQUIRED", err.Error())
		return
	}
	run, err := s.lifecycle.StartUpgradeRecovery(r.Context(), request, installRequest.ProfileID)
	if err != nil {
		writeError(w, http.StatusConflict, "LIFECYCLE_RECOVERY_START_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *installerServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.access.VerifyAuthorization(r.Header.Get("Authorization")) {
			writeError(w, http.StatusUnauthorized, "BOOTSTRAP_TOKEN_REQUIRED", "a valid bootstrap token is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type rotateAccessTokenRequest struct {
	Confirmation string `json:"confirmation"`
	NewToken     string `json:"newToken"`
}

func (s *installerServer) accessStatus(w http.ResponseWriter, _ *http.Request) {
	digest, err := fieldevidence.CurrentExecutableDigest()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INSTALLER_IDENTITY_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, installeraccess.AccessStatus{ProductVersion: version, InstallerBinaryDigest: digest, Transport: s.transport, Token: s.access.Status()})
}

func (s *installerServer) rotateAccessToken(w http.ResponseWriter, r *http.Request) {
	var request rotateAccessTokenRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	status, err := s.access.Rotate(request.NewToken, request.Confirmation, time.Now())
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "TOKEN_ROTATION_REJECTED", err.Error())
		return
	}
	s.logger.Info("bootstrap token rotated", "token_fingerprint", status.Fingerprint, "rotated_at", status.RotatedAt)
	writeJSON(w, http.StatusOK, map[string]any{"rotated": true, "token": status})
}

func (s *installerServer) status(w http.ResponseWriter, _ *http.Request) {
	run, err := s.runner.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STATUS_FAILED", err.Error())
		return
	}
	s.mutationMu.Lock()
	bootstrapActive := s.bootstrapActive
	s.mutationMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"executionEnabled": s.executionEnabled, "bootstrapActive": bootstrapActive, "run": run})
}

func (s *installerServer) profiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, installation.BootstrapProfiles())
}

func (s *installerServer) integrations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, installation.BootstrapIntegrations())
}

func (s *installerServer) tlsCA(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.runner.CACertificate()
	if err != nil {
		writeError(w, http.StatusNotFound, "TLS_CA_NOT_READY", "bootstrap CA is generated during host preparation")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=4so-platform-bootstrap-ca.crt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *installerServer) plan(w http.ResponseWriter, r *http.Request) {
	var request bootstrap.StartRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	plan, bundleDigest, err := s.runner.Plan(request.Installation)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PLAN_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "bundleDigest": bundleDigest, "executionEnabled": s.executionEnabled})
}

func (s *installerServer) start(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "set PLATFORM_INSTALLER_ALLOW_EXECUTION=true after reviewing the plan")
		return
	}
	var request bootstrap.StartRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	plan, _, err := s.runner.Plan(request.Installation)
	if err != nil || !plan.Executable {
		if err == nil {
			err = fmt.Errorf("plan is not executable: %s", strings.Join(plan.Blockers, "; "))
		}
		writeError(w, http.StatusUnprocessableEntity, "PLAN_NOT_EXECUTABLE", err.Error())
		return
	}
	s.mutationMu.Lock()
	if err := s.mutationConflictLocked("bootstrap"); err != nil {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	if s.bootstrapExecutionActiveLocked() || s.bootstrapInterrupted() {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", "bootstrap mutation is active or requires resume")
		return
	}
	s.bootstrapActive = true
	s.mutationMu.Unlock()
	go func() {
		defer func() { s.mutationMu.Lock(); s.bootstrapActive = false; s.mutationMu.Unlock() }()
		run, runErr := s.runner.Start(context.Background(), request.Installation)
		if runErr != nil {
			s.logger.Error("bootstrap run failed", "run_id", run.ID, "error", runErr)
			return
		}
		s.logger.Info("bootstrap run completed", "run_id", run.ID, "state", run.State)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "message": "bootstrap execution started"})
}

func (s *installerServer) resume(w http.ResponseWriter, _ *http.Request) {
	if !s.executionEnabled {
		writeError(w, http.StatusForbidden, "EXECUTION_DISABLED", "execution is disabled")
		return
	}
	s.mutationMu.Lock()
	if err := s.mutationConflictLocked("bootstrap"); err != nil {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", err.Error())
		return
	}
	if s.bootstrapExecutionActiveLocked() {
		s.mutationMu.Unlock()
		writeError(w, http.StatusConflict, "MUTATION_CONFLICT", "bootstrap mutation is already active")
		return
	}
	s.bootstrapActive = true
	s.mutationMu.Unlock()
	go func() {
		defer func() { s.mutationMu.Lock(); s.bootstrapActive = false; s.mutationMu.Unlock() }()
		run, err := s.runner.Resume(context.Background())
		if err != nil {
			s.logger.Error("bootstrap resume failed", "run_id", run.ID, "error", err)
			return
		}
		s.logger.Info("bootstrap resume completed", "run_id", run.ID, "state", run.State)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "message": "bootstrap resume started"})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	if strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
