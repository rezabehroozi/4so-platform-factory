package webconsole

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestOperatorConsoleJourneyContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, js := string(htmlBytes), string(jsBytes)
	for _, page := range []string{"overview", "workspace", "installation", "clusters", "providers", "blueprints", "marketplace", "baselines", "verification", "fleet", "tenants", "operations", "ai", "lab", "notifications", "services", "catalog", "validator"} {
		if !strings.Contains(html, `id="`+page+`"`) {
			t.Fatalf("page %q is missing from the operator console", page)
		}
		reachable := strings.Contains(html, `data-page="`+page+`"`) || strings.Contains(html, `data-section-home="`+page+`"`) || strings.Contains(html, `data-navigate="`+page+`"`)
		if !reachable {
			t.Fatalf("page %q is not reachable from the domain/context navigation model", page)
		}
	}
	for _, section := range []string{"home", "infrastructure", "delivery", "fleet", "operations", "administration"} {
		if !strings.Contains(html, `data-section="`+section+`"`) {
			t.Fatalf("primary operator domain %q is missing", section)
		}
	}
	if !strings.Contains(html, `id="section-nav"`) {
		t.Fatal("contextual section navigation is missing")
	}
	for _, route := range []string{
		"/api/v1/access/context", "/api/v1/lab/guide", "/api/v1/ai/policy", "/api/v1/ai/diagnose", "/api/v1/ai/runs", "/api/v1/target-architecture-model", "/api/v1/compatibility/evaluate", "/api/v1/organizations", "/memberships", "/api/v1/projects", "/api/v1/installations/integrations", "/api/v1/cluster-imports", "/api/v1/clusters/", "/revoke",
		"/api/v1/provider-profiles", "/api/v1/provider-clusters", "/api/v1/blueprint-releases", "/api/v1/blueprint-overlays", "/api/v1/blueprints/authoring-roundtrip", "/api/v1/blueprints/resolve", "/api/v1/catalog-governance/signing-identity", "/api/v1/catalog-trust-keys", "/api/v1/catalog-releases", "/api/v1/marketplace/installations",
		"/api/v1/baseline-deployments", "/api/v1/runtime-verifications", "/api/v1/runtime-closure-campaigns", "/api/v1/runtime-closure-reports/verify",
		"/api/v1/fleet-groups", "/api/v1/drift-scans", "/api/v1/upgrade-campaigns", "/api/v1/tenants", "/maintenance-profile", "/maintenance-windows", "/maintenance-runs",
		"/api/v1/support-bundles", "/api/v1/notification-destinations", "/api/v1/notification-routes", "/api/v1/notification-events", "/api/v1/notification-deliveries",
		"/api/v1/system-services/git/repositories", "/api/v1/system-services/git/revisions", "/api/v1/git-credentials", "/api/v1/git-providers",
	} {
		if !strings.Contains(js, route) {
			t.Fatalf("operator route %q has no console journey", route)
		}
	}
	if strings.Contains(js, "fillSelect(") {
		t.Fatal("console AI journey references undefined fillSelect helper")
	}
	for _, forbidden := range []string{"load-sample", "example.test", "dummy data", "X-Actor-Role", "sampleData"} {
		if strings.Contains(strings.ToLower(html+js), strings.ToLower(forbidden)) {
			t.Fatalf("console contains forbidden synthetic or browser-authority pattern %q", forbidden)
		}
	}
	for _, contract := range []string{"approvalControl", "canApprove", "read-only-session", "Revoke agent access", "organizationMembershipFor", "canManageOrganization", "revoke-organization-membership", "drift-git-organization", "drift-git-repository", "drift-git-branch", "adopt-git", "Adopt trusted Git state", "currentTrusted", "classification", "KUBERNETES_NODE_MAINTENANCE_V1", "softApi", "livePages", "scheduleAutoRefresh", "data-notification-destination-action=\"edit\"", "data-notification-route-action=\"edit\"", "git-credential-create-form", "git-provider-create-form", "sessionExpired", "hasUnsavedChanges", "dirtyWithin", "confirmDiscardDirty", "interactionHoldUntil", "details[open]", "blueprintEditorHasUnsavedChanges", "maintenanceLoadGeneration", "beforeunload", "mobileNavFocusable", "operation-diagnostics", "data-operation-bundle", "compatibility-form", "renderCompatibilityResult"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("console authorization/journey contract %q missing", contract)
		}
	}

	for _, page := range []string{"marketplace", "tenants", "ai"} {
		if !strings.Contains(js, "const livePages=new Set([") || !strings.Contains(js, "'"+page+"'") {
			t.Fatalf("live async page %q is missing from auto-refresh contract", page)
		}
	}
	if !strings.Contains(js, "/api/v1/operations?limit=200") {
		t.Fatal("operator console must use the bounded operations collection path")
	}
	if !strings.Contains(js, "if (error.sessionExpired || error.status === 401) throw error") {
		t.Fatal("softApi must propagate session expiry instead of degrading it")
	}
	if !strings.Contains(js, "if (error?.name === 'AbortError') throw error") {
		t.Fatal("softApi must propagate cancellation instead of degrading it")
	}
	if !strings.Contains(html, `data-viewer-safe="true" id="installation-form"`) {
		t.Fatal("viewer-safe installation planning form must remain usable for read-only sessions")
	}
	if !strings.Contains(js, `data-closure-action="verify" data-viewer-safe="true"`) {
		t.Fatal("viewer-safe closure evidence verification must remain usable for read-only sessions")
	}
	if !strings.Contains(js, "button.dataset.viewerSafe==='true' || button.closest('form')?.dataset.viewerSafe==='true'") {
		t.Fatal("permission surface must honor explicit viewer-safe control/form metadata")
	}
	if !strings.Contains(js, "const loaded = await loadPage(page)") || !strings.Contains(js, "if (!loaded || state.currentPage !== page) return false") {
		t.Fatal("superseded navigation must not complete route announcement/focus")
	}
	for _, contract := range []string{"Cluster authority unavailable", "Authority unavailable; retry before acting.", "Overview unavailable"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("overview authority-truth contract missing %q", contract)
		}
	}
	if !strings.Contains(js, "$('#blueprint-release-form').dataset.dirty='true'") {
		t.Fatal("Blueprint JSON import must mark the visual editor dirty")
	}
	for _, contract := range []string{"target-architecture-summary", "renderTargetArchitectureSummary", "programRoadmap", "capabilityResolver", "ai-policy-summary", "ai-runtime-details", "ai-mcp-access", "ai-usage-summary", "ai-diagnosis-form", "ai-run-project-filter", "data-ai-run-inspect", "renderAIRuntimeAndAccess", "renderAIUsageSummary", "renderAIRunHistory", "inspectAIRun", "loadAI", "lab-server-tiers", "lab-matrix", "loadLab", "LAB_CERTIFICATION_MATRIX_V1"} {
		if !strings.Contains(html+js, contract) {
			t.Fatalf("target architecture console authority contract missing %q", contract)
		}
	}
	for _, viewerSafe := range []string{"/api/v1/blueprints/authoring-roundtrip", "/api/v1/blueprints/resolve", "/api/v1/compatibility/evaluate"} {
		if !strings.Contains(js, viewerSafe) {
			t.Fatalf("viewer-safe planning endpoint %q missing from console contract", viewerSafe)
		}
	}
	assertDOMReferencesExist(t, html, js)
}

func TestOperatorConsoleDesignSystemContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssBytes, err := fs.ReadFile(content, "static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	html, js, css := string(htmlBytes), string(jsBytes), string(cssBytes)
	if got := strings.Count(html, `class="nav-icon"`); got != 6 {
		t.Fatalf("primary navigation must expose one consistent SVG icon per operator domain: got %d", got)
	}
	for _, contract := range []string{`id="section-nav"`, `data-section="infrastructure"`, `data-section="delivery"`, `data-section="administration"`, `class="action-console"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("operator information-architecture contract missing %q", contract)
		}
	}
	for _, contract := range []string{`class="skip-link"`, `name="theme-color"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("operator accessibility/design contract missing %q", contract)
		}
	}

	for _, contract := range []string{`id="icon-menu"`, `id="icon-close"`, `id="mobile-nav-toggle" type="button"><svg`, `aria-label="Close" class="icon-button" value="close"><svg`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("operator action-icon contract missing %q", contract)
		}
	}
	if !strings.Contains(js, "aria-current") {
		t.Fatal("operator navigation must expose aria-current from runtime navigation state")
	}
	for _, contract := range []string{"syncMobileNavAccessibility", "sidebar.inert", "pageLoadController", "AbortController", "route-announcer", "aria-busy", "hasActiveWork(state.currentPage)"} {
		if !strings.Contains(js+html, contract) {
			t.Fatalf("operator production-hardening contract missing %q", contract)
		}
	}
	for _, contract := range []string{`aria-labelledby="confirm-title"`, `aria-labelledby="detail-title"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("operator dialog accessible-name contract missing %q", contract)
		}
	}
	if strings.Count(js, "dataTable(") < 10 {
		t.Fatalf("high-cardinality resource collections must use semantic data tables; got %d table render sites", strings.Count(js, "dataTable("))
	}
	for _, contract := range []string{"explicitMutationKeys", "operationCancel", "membershipRevoke", "oidcMappingRevoke", "gitLkgRollback", "notificationRetryDeadLetter"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("read-only mutation intent contract missing %q", contract)
		}
	}
	for _, contract := range []string{"data-record-row", "tableRecords", "role=\"region\"", "scope=\"col\"", "data-table-sort-index", "aria-sort", "data-sort-value", "data-table-key", "tableSortPreferences", "restoreDataTableSortPreferences", "sourceUnavailable", "data-retry-current"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("operator data-workspace contract missing %q", contract)
		}
	}
	if !strings.Contains(css, ".metric-card strong") || !strings.Contains(css, "overflow-wrap:anywhere") {
		t.Fatal("metric identifiers must wrap instead of causing mobile document overflow")
	}
	for _, contract := range []string{
		"min-height: 44px", "@media (prefers-reduced-motion: reduce)", "border-inline-start: 4px solid var(--accent)", "grid-template-columns: repeat(auto-fit",
		"--success-fg:", "--warning-fg:", "--danger-fg:", "--focus-ring:", "--focus-halo:", ".badge.technical { white-space: normal", ".data-table", ".data-table-shell", ".data-table-sort", ".unavailable-state",
	} {
		if !strings.Contains(css, contract) {
			t.Fatalf("operator design-system contract missing %q", contract)
		}
	}
}

func assertDOMReferencesExist(t *testing.T, html, js string) {
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
