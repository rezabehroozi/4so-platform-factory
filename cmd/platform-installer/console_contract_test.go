package main

import (
	"bytes"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installeraccess"
)

func TestInstallerConsoleJourneyContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(staticFiles, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(staticFiles, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssBytes, err := fs.ReadFile(staticFiles, "static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	html, js, css := string(htmlBytes), string(jsBytes), string(cssBytes)
	for _, page := range []string{"overview", "installation", "progress", "health", "recovery", "lifecycle"} {
		if !strings.Contains(html, `id="`+page+`"`) || !strings.Contains(html, `data-page="`+page+`"`) {
			t.Fatalf("installer page %q is not reachable", page)
		}
	}
	for _, route := range []string{
		"/api/v1/status", "/api/v1/access/status", "/api/v1/ssh/trust/status", "/api/v1/secrets/ssh-known-hosts", "/api/v1/profiles", "/api/v1/integrations", "/api/v1/plan", "/api/v1/preflight", "/api/v1/start", "/api/v1/resume",
		"/api/v1/bundle/status", "/api/v1/field-evidence/report", "/api/v1/field-evidence/verify", "/api/v1/diagnostics/report", "/api/v1/diagnostics/verify", "/api/v1/gitops/status", "/api/v1/ha/status", "/api/v1/airgap/status", "/api/v1/disaster-recovery/backup",
		"/api/v1/disaster-recovery/restore", "/api/v1/lifecycle/backup", "/api/v1/lifecycle/restore", "/api/v1/lifecycle/upgrade", "/api/v1/lifecycle/upgrade-recovery",
	} {
		if !strings.Contains(js, route) {
			t.Fatalf("installer route %q has no UI journey", route)
		}
	}
	for _, forbidden := range []string{"const sample", "haSample", "example.test", "localStorage", "load-sample"} {
		if strings.Contains(html+js, forbidden) {
			t.Fatalf("installer contains forbidden sample/raw-output pattern %q", forbidden)
		}
	}
	if strings.Contains(css, ".top-actions .secondary{display:none}") {
		t.Fatal("mobile installer hides the language control")
	}
	if strings.Contains(html, `option value="existing-kubernetes"`) {
		t.Fatal("executable installer advertises planning-only existing-kubernetes infrastructure")
	}
	if strings.Contains(html, `id="admin-email"`) {
		t.Fatal("installer exposes a duplicate bootstrap administrator email field outside the identity service authority")
	}
	for _, identityEmailContract := range []string{"fields:['issuerUrl','clientId','credentialRef','adminEmail']", "kind === 'identity' && name === 'adminEmail'", "spec.adminEmail = value('adminEmail')"} {
		if !strings.Contains(js, identityEmailContract) {
			t.Fatalf("identity service admin-email authority missing %q", identityEmailContract)
		}
	}
	for _, networkContract := range []string{`id="cluster-nodes"`, `id="cluster-interface"`} {
		if !strings.Contains(html, networkContract) {
			t.Fatalf("installer HA east-west field missing %q", networkContract)
		}
	}
	for _, networkContract := range []string{"clusterNodeAddresses:", "clusterInterface:", "installer never assigns IPs"} {
		if !strings.Contains(js, networkContract) && !strings.Contains(html, networkContract) {
			t.Fatalf("installer HA east-west journey missing %q", networkContract)
		}
	}
	for _, interruptedResumeContract := range []string{
		"const interrupted = run.state==='RUNNING' && status.bootstrapActive !== true",
		"run.state==='FAILED' || interrupted",
		"Resume interrupted run",
	} {
		if !strings.Contains(js, interruptedResumeContract) {
			t.Fatalf("installer console cannot safely resume an orphaned RUNNING journal: missing %q", interruptedResumeContract)
		}
	}
	assertInstallerDOMReferencesExist(t, html, js)
}

func TestInstallerConsoleDesignSystemContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(staticFiles, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(staticFiles, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssBytes, err := fs.ReadFile(staticFiles, "static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	html, js, css := string(htmlBytes), string(jsBytes), string(cssBytes)
	for _, contract := range []string{`id="nav-scrim"`, `aria-controls="sidebar"`, `aria-expanded="false"`, `aria-current="page"`, `meta name="theme-color"`, `aria-labelledby="connect-dialog-title"`, `aria-labelledby="ssh-dialog-title"`, `aria-labelledby="confirm-title"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("installer accessibility/design contract missing %q", contract)
		}
	}

	for _, contract := range []string{`id="icon-menu"`, `id="icon-close"`, `id="menu-toggle" class="icon-button"`, `aria-label="Close"><svg`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("installer action-icon contract missing %q", contract)
		}
	}
	for _, contract := range []string{"setInstallerMenu", "installerNavFocusable", "aria-current", "event.key==='Escape'", "syncInstallerMenuAccessibility", "sidebar.inert", "coordinatedRequest", "scheduleInstallerPoll", "AbortController"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("installer mobile-navigation contract missing %q", contract)
		}
	}
	for _, contract := range []string{"min-height:44px", "@media(prefers-reduced-motion:reduce)", ".nav-scrim:not([hidden])", "@media(prefers-color-scheme:dark)", "--success-fg:", "--warning-fg:", "--danger-fg:", "--focus-ring:", "--focus-halo:"} {
		if !strings.Contains(css, contract) {
			t.Fatalf("installer design-system contract missing %q", contract)
		}
	}
}

func TestInstallerHandlerServesFaviconWithout404(t *testing.T) {
	server := &installerServer{}
	mux := http.NewServeMux()
	server.routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("favicon status=%d want=%d body=%s", res.Code, http.StatusNoContent, res.Body.String())
	}
}

func TestInstallerIntegrationsRoute(t *testing.T) {
	authValue := "test-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), authValue, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{access: access}
	mux := http.NewServeMux()
	server.routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations", nil)
	req.Header.Set("Authorization", "Bearer "+authValue)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", res.Code, res.Body.String())
	}
	for _, service := range []string{"git", "registry", "database", "identity", "objectStorage"} {
		if !strings.Contains(res.Body.String(), `"`+service+`"`) {
			t.Fatalf("integration response missing %q", service)
		}
	}
	for _, deadEnd := range []string{"external-gitlab", "external-harbor", "external-postgresql", "external-oidc"} {
		if strings.Contains(res.Body.String(), `"`+deadEnd+`"`) {
			t.Fatalf("installer exposed planning-only integration %q", deadEnd)
		}
	}
	if !strings.Contains(res.Body.String(), `"external-s3-compatible"`) {
		t.Fatal("installer hid executable S3 backup integration")
	}
}

func TestInstallerStatusExposesBootstrapWorkerOwnership(t *testing.T) {
	authValue := "test-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), authValue, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: "test", BundleDir: t.TempDir(), StateDir: t.TempDir(), Simulation: true})
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{access: access, runner: runner, executionEnabled: true, bootstrapActive: true}
	mux := http.NewServeMux()
	server.routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+authValue)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"bootstrapActive":true`) {
		t.Fatalf("status omitted live bootstrap worker ownership: %s", res.Body.String())
	}
}

func assertInstallerDOMReferencesExist(t *testing.T, html, js string) {
	idPattern := regexp.MustCompile(`\bid=["']([A-Za-z0-9_-]+)["']`)
	refPattern := regexp.MustCompile(`(?:getElementById\(["']|\$\(["']#)([A-Za-z0-9_-]+)`)
	ids := map[string]bool{}
	for _, match := range idPattern.FindAllStringSubmatch(html, -1) {
		if ids[match[1]] {
			t.Fatalf("duplicate DOM id %q", match[1])
		}
		ids[match[1]] = true
	}
	for _, match := range refPattern.FindAllStringSubmatch(js, -1) {
		if !ids[match[1]] {
			t.Fatalf("JavaScript references missing DOM id %q", match[1])
		}
	}
}

func TestInstallerSSHTrustRoutesDoNotReturnRawHostKeys(t *testing.T) {
	authValue := "test-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), authValue, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: "0.0.56", BundleDir: t.TempDir(), StateDir: t.TempDir(), Simulation: true})
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{access: access, runner: runner}
	mux := http.NewServeMux()
	server.routes(mux)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	payload := []byte(`{"knownHosts":"10.0.0.12 ssh-ed25519 ` + key + `\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/ssh-known-hosts", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+authValue)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("store known_hosts status=%d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), key) || !strings.Contains(res.Body.String(), "SHA256:") {
		t.Fatalf("known_hosts response leaked raw key or omitted fingerprint: %s", res.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ssh/trust/status", nil)
	req.Header.Set("Authorization", "Bearer "+authValue)
	res = httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), key) || !strings.Contains(res.Body.String(), `"knownHostsStored":true`) {
		t.Fatalf("SSH trust status invalid: status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestRestoreActionsRequireServerSideExactConfirmation(t *testing.T) {
	server := &installerServer{executionEnabled: true}
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/disaster-recovery/restore", `{"backupId":"backup-a"}`},
		{"/api/v1/lifecycle/restore", `{"service":"forgejo","backupId":"backup-a"}`},
		{"/api/v1/lifecycle/upgrade-recovery", `{"upgradeRunId":"lifecycle-zot-upgrade-1"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		switch tc.path {
		case "/api/v1/disaster-recovery/restore":
			server.disasterRecoveryRestore(res, req)
		case "/api/v1/lifecycle/restore":
			server.lifecycleRestore(res, req)
		case "/api/v1/lifecycle/upgrade-recovery":
			server.lifecycleUpgradeRecovery(res, req)
		}
		if res.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s status=%d body=%s", tc.path, res.Code, res.Body.String())
		}
		if tc.path == "/api/v1/lifecycle/upgrade-recovery" {
			if !strings.Contains(res.Body.String(), "UPGRADE_RECOVERY_CONFIRMATION_REQUIRED") {
				t.Fatalf("%s body=%s", tc.path, res.Body.String())
			}
		} else if !strings.Contains(res.Body.String(), "RESTORE_CONFIRMATION_REQUIRED") {
			t.Fatalf("%s body=%s", tc.path, res.Body.String())
		}
	}
}

func TestInstallerPersianLocalFontContract(t *testing.T) {
	cssBytes, err := fs.ReadFile(staticFiles, "static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	for _, contract := range []string{`font-family: "Vazirmatn Local"`, `src: local("Vazirmatn"), local("Vazirmatn Regular")`, `--font-fa:`, `html[lang="fa"]`} {
		if !strings.Contains(css, contract) {
			t.Fatalf("Persian local-font contract missing %q", contract)
		}
	}
	for _, remote := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net"} {
		if strings.Contains(css, remote) {
			t.Fatalf("Persian font must not depend on remote runtime font source %q", remote)
		}
	}
}
