package webconsole

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
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
	for _, page := range []string{"overview", "workspace", "installation", "clusters", "providers", "blueprints", "templates", "marketplace", "baselines", "verification", "fleet", "workspaces", "tenants", "operations", "ai", "lab", "notifications", "services", "catalog", "validator"} {
		if !strings.Contains(html, `id="`+page+`"`) {
			t.Fatalf("page %q is missing from the operator console", page)
		}
		reachable := strings.Contains(html, `data-page="`+page+`"`) || strings.Contains(html, `data-section-home="`+page+`"`) || strings.Contains(html, `data-navigate="`+page+`"`) || strings.Contains(js, `'`+page+`'`)
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
		"/api/v1/access/context", "/api/v1/lab/guide", "/api/v1/ai/policy", "/api/v1/ai/diagnose", "/api/v1/ai/runs", "/api/v1/target-architecture-model", "/api/v1/compatibility/evaluate", "/api/v1/organizations", "/memberships", "/api/v1/projects", "/api/v1/installations/integrations", "/api/v1/cluster-imports", "/api/v1/managed-okd-installs", "/api/v1/clusters/", "/revoke",
		"/api/v1/provider-profiles", "/api/v1/provider-clusters", "/api/v1/blueprint-releases", "/api/v1/blueprint-overlays", "/api/v1/variable-schemas", "/api/v1/platform-policy-sets", "/api/v1/platform-templates", "/api/v1/blueprints/authoring-roundtrip", "/api/v1/blueprints/resolve", "/api/v1/catalog-governance/signing-identity", "/api/v1/catalog-trust-keys", "/api/v1/catalog-releases", "/api/v1/marketplace/installations",
		"/api/v1/baseline-deployments", "/api/v1/runtime-verifications", "/api/v1/runtime-closure-campaigns", "/api/v1/runtime-closure-reports/verify",
		"/api/v1/fleet-groups", "/api/v1/drift-scans", "/api/v1/upgrade-campaigns", "/api/v1/workspaces", "/bindings", "/api/v1/tenants", "/maintenance-profile", "/maintenance-windows", "/maintenance-runs",
		"/api/v1/support-bundles", "/api/v1/notification-destinations", "/api/v1/notification-routes", "/api/v1/notification-routing/preview", "/api/v1/notification-events", "/api/v1/notification-deliveries",
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
	for _, previewContract := range []string{`id="notification-preview-form"`, `id="notification-preview-result"`, `id="notification-preview-organization"`, `id="notification-preview-project"`, `id="notification-preview-event-type"`, `No event or delivery is created.`} {
		if !strings.Contains(html, previewContract) {
			t.Fatalf("notification routing preview DOM contract missing %q", previewContract)
		}
	}
	for _, previewContract := range []string{"renderNotificationRoutingPreview", "notificationRoutingPreview", "/api/v1/notification-routing/preview", "deliveryCreated", "sideEffects"} {
		if !strings.Contains(js, previewContract) {
			t.Fatalf("notification routing preview behavior contract missing %q", previewContract)
		}
	}
	for _, contract := range []string{"approvalControl", "canApprove", "read-only-session", "Revoke agent access", "organizationMembershipFor", "canManageOrganization", "revoke-organization-membership", "drift-git-organization", "drift-git-repository", "drift-git-branch", "adopt-git", "Adopt trusted Git state", "currentTrusted", "classification", "KUBERNETES_NODE_MAINTENANCE_V1", "softApi", "livePages", "scheduleAutoRefresh", "data-notification-destination-action=\"edit\"", "data-notification-route-action=\"edit\"", "git-credential-create-form", "git-provider-create-form", "sessionExpired", "hasUnsavedChanges", "dirtyWithin", "confirmDiscardDirty", "interactionHoldUntil", "details[open]", "blueprintEditorHasUnsavedChanges", "maintenanceLoadGeneration", "beforeunload", "mobileNavFocusable", "operation-diagnostics", "data-operation-bundle", "compatibility-form", "renderCompatibilityResult"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("console authorization/journey contract %q missing", contract)
		}
	}

	for _, contract := range []string{
		`id="global-scope"`, `id="global-organization-scope"`, `id="global-project-scope"`, `id="global-scope-status"`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("global scope DOM contract missing %q", contract)
		}
	}
	for _, contract := range []string{
		"refreshGlobalScopeDirectory", "changeGlobalScope", "scopedRequestPath", "assertGlobalScopeRequest", "projectBelongsToGlobalScope",
		"platformScopeOrganization", "platformScopeProject", "confirmDiscardDirty", "pageLoadController?.abort()", "scopeTransitioning",
		"/api/v1/control-plane/summary", "/api/v1/operations", "/api/v1/audit-events", "GLOBAL_SCOPE_MISMATCH",
	} {
		if !strings.Contains(js, contract) {
			t.Fatalf("global scope authority contract missing %q", contract)
		}
	}
	for _, page := range []string{"marketplace", "tenants", "ai"} {
		if !strings.Contains(js, "const livePages=new Set([") || !strings.Contains(js, "'"+page+"'") {
			t.Fatalf("live async page %q is missing from auto-refresh contract", page)
		}
	}
	if !strings.Contains(js, "/api/v1/operations?limit=20") {
		t.Fatal("overview must use the bounded operations collection path")
	}
	if !strings.Contains(js, "/api/v1/control-plane/attention?limit=9") {
		t.Fatal("overview must use the bounded operator-attention authority")
	}
	for _, forbiddenOverviewCollection := range []string{"softApi('/api/v1/baseline-deployments'", "softApi('/api/v1/runtime-verifications'", "softApi('/api/v1/runtime-closure-campaigns'", "softApi('/api/v1/tenants'", "softApi('/api/v1/provider-profiles'", "softApi('/api/v1/provider-clusters'"} {
		if strings.Contains(js[jsIndex(js, "async function loadOverview()", t):jsIndex(js, "function organizationMembershipFor", t)], forbiddenOverviewCollection) {
			t.Fatalf("overview must not materialize full collection %q", forbiddenOverviewCollection)
		}
	}
	for _, contract := range []string{"summary.connectedClusters", "summary.successfulBaselineDeployments", "summary.successfulRuntimeVerifications", "summary.successfulRuntimeClosureCampaigns", "summary.failedProductWorkflows"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("overview must use bounded summary authority %q", contract)
		}
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
	for _, contract := range []string{"Summary authority unavailable", "Authority unavailable; retry before acting.", "Overview unavailable"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("overview authority-truth contract missing %q", contract)
		}
	}
	if !strings.Contains(js, "$('#blueprint-release-form').dataset.dirty='true'") {
		t.Fatal("Blueprint JSON import must mark the visual editor dirty")
	}
	for _, contract := range []string{`id="platform-start"`, `data-platform-path="import"`, `data-platform-path="provider"`, `data-platform-path="okd"`, `id="managed-okd-form"`, `data-managed-okd-stage="1"`, `data-managed-okd-stage="2"`, `data-managed-okd-stage="3"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("task-first platform journey DOM contract missing %q", contract)
		}
	}
	for _, contract := range []string{"pageGuidance", "renderPageGuidance", "managedOKDStage", "canonicalSHA256Input", "/api/v1/managed-okd-installs", "body.install?.operation", "data-managed-okd-approval", "Approve managed OKD install"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("task-first platform journey behavior contract missing %q", contract)
		}
	}
	if strings.Contains(js, "['Blueprints','Component catalog']") {
		t.Fatal("marketplace must not be mislabeled as the component catalog in operator navigation")
	}
	for _, contract := range []string{"target-architecture-summary", "renderTargetArchitectureSummary", "programRoadmap", "capabilityResolver", "ai-policy-summary", "ai-runtime-details", "ai-mcp-access", "ai-usage-summary", "ai-diagnosis-form", "ai-run-project-filter", "data-ai-run-inspect", "renderAIRuntimeAndAccess", "renderAIUsageSummary", "renderAIRunHistory", "inspectAIRun", "loadAI", "lab-server-tiers", "lab-matrix", "loadLab", "LAB_CERTIFICATION_MATRIX_V2"} {
		if !strings.Contains(html+js, contract) {
			t.Fatalf("target architecture console authority contract missing %q", contract)
		}
	}
	for _, viewerSafe := range []string{"/api/v1/blueprints/authoring-roundtrip", "/api/v1/blueprints/resolve", "/api/v1/compatibility/evaluate", "/deployment-plan"} {
		if !strings.Contains(js, viewerSafe) {
			t.Fatalf("viewer-safe planning endpoint %q missing from console contract", viewerSafe)
		}
	}
	for _, contract := range []string{
		"resumeApplicationDeploymentForBinding",
		"/api/v1/application-platform/environment-bindings/",
		"application deployment history",
		"RECOVERY_REQUIRED",
		"RECOVERED_READY",
		"EVIDENCE_MISSING",
		"recoveryEvidenceDigest",
		"evidencePresent",
		"read-only recovery resolution",
	} {
		if !strings.Contains(js, contract) {
			t.Fatalf("application deployment durable/recovery console contract missing %q", contract)
		}
	}
	if !strings.Contains(html, "Durable status is resumed for this binding after reload.") || !strings.Contains(html, "read-only target recovery evidence") {
		t.Fatal("application deployment recovery guidance is missing from the operator console")
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
	if got := strings.Count(html, `class="nav-icon"`); got != 7 {
		t.Fatalf("primary navigation must expose one consistent SVG icon per operator domain: got %d", got)
	}
	for _, contract := range []string{`id="section-nav"`, `data-section="infrastructure"`, `data-section="delivery"`, `data-section="assurance"`, `data-section="administration"`, `class="action-console"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("operator information-architecture contract missing %q", contract)
		}
	}
	for _, contract := range []string{
		`data-en="Overview">نمای کلی</span>`, `data-en="Platforms">پلتفرم‌ها</span>`, `data-en="Delivery">تحویل</span>`, `data-en="Fleet &amp; Workspaces">ناوگان و فضاهای کاری</span>`, `data-en="Assurance">اطمینان و شواهد</span>`, `data-en="Admin">مدیریت</span>`,
		`class="product-flow"`, `data-navigate="blueprints"`, `data-navigate="clusters"`, `data-navigate="fleet"`, `data-navigate="operations"`,
		`data-section="delivery" data-section-home="blueprints"`, `data-section="assurance" data-section-home="verification"`, `Runtime assurance`, `Supply-chain releases`, `Physical certification`, `Organizations &amp; projects`, `AI Operator`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Operator Horizon V4 information-architecture contract missing %q", contract)
		}
	}
	if strings.Contains(html, `<nav id="primary-nav"><button`) && (strings.Contains(html, `<span>Configurations</span>`) || strings.Contains(html, `<span>Governance</span>`)) {
		t.Fatal("legacy implementation-oriented labels must not remain in the primary operator navigation")
	}
	for _, contract := range []string{`id="workspace"`, `Organizations &amp; projects`, `id="workspaces"`, `WORKSPACE_AUTHORITY_V1`, `Reference-only authority.`, `Workspace records`, `Namespace bindings`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Workspace information-architecture contract missing %q", contract)
		}
	}
	for _, contract := range []string{"loadWorkspaces", "workspaceBindings", "virtualClusters", "/api/v1/workspaces", "/virtual-clusters", "virtual-cluster-form", "Idempotency-Key", "REQUESTED is not Running or Ready", "Lifecycle state is durable and executor-backed.", "data-virtual-cluster-action=\"suspend\"", "data-virtual-cluster-action=\"resume\"", "delete-virtual-cluster", "Task fence token", "FinOps attribution", "Derived from referenced cluster", "does not delete the namespace or workloads"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("Workspace truthful-console runtime contract missing %q", contract)
		}
	}
	for _, contract := range []string{`data-page="templates"`, `id="templates"`, `data-page="applications"`, `id="applications"`, `data-page="dapr"`, `id="dapr"`, `TARGET PREVIEW REQUIRED`, `No direct deploy from a template.`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("PlatformTemplate truthful-console contract missing %q", contract)
		}
	}
	for _, contract := range []string{"loadPlatformTemplates", "platformTemplates", "adoptionReady", "source admission"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("PlatformTemplate console runtime contract missing %q", contract)
		}
	}
	for _, contract := range []string{`id="application-composition-library"`, `id="application-library-picker"`, `data-application-library-open="workload"`, `data-application-library-open="resource"`, `data-application-library-task="workload"`, `data-application-library-task="profile"`, `data-application-library-task="trait"`, `data-application-library-task="resource"`, `id="application-workload-create-form"`, `id="application-trait-create-form"`, `id="application-resource-create-form"`, `id="application-profile-create-form"`, `id="application-delivery-prerequisite"`, `id="application-composition-panel"`, `id="application-delivery-journey"`, `data-application-step="release"`, `data-application-step="observed"`, `id="application-release-workflow"`, `id="application-binding-workflow"`, `id="application-deployment-workflow"`, `id="application-advanced-workflow"`, `id="application-resolution-form"`, `id="application-promotion-form"`, `id="application-release-create-form"`, `id="application-release-image"`, `id="application-binding-create-form"`, `id="application-binding-workspace-binding"`, `data-viewer-safe="true" id="application-deployment-plan-form"`, `id="application-deployment-binding"`, `id="application-deployment-plan-result"`, `id="application-deployment-request"`, `data-viewer-safe="true" id="application-deployment-refresh"`, `id="application-deployment-approve"`, "Authority boundary:", "Advanced composition &amp; promotion", "immutable release", "does not deploy an application", "Deterministic desired state only", "ambiguous target mutation becomes Recovery Required"} {
		if !strings.Contains(html, contract) {
			t.Fatalf("J8 application composition console contract missing %q", contract)
		}
	}
	for _, contract := range []string{`id="dapr-prerequisite"`, `id="dapr-runtime-workflow"`, `id="dapr-lifecycle-workflow"`, `id="dapr-workload-workflow"`, `data-viewer-safe="true" id="dapr-assessment-form"`, `data-viewer-safe="true" id="dapr-workload-form"`, `id="dapr-lifecycle-form"`, `id="dapr-workload-trait"`, `id="dapr-workload-image"`, `id="dapr-workload-admit"`, `id="dapr-workload-refresh"`, "Dapr workload policy &amp; admission", "target-native Dapr is consumed rather than duplicated", "durable READ_ONLY verification job"} {
		if !strings.Contains(html, contract) {
			t.Fatalf("J8 Dapr workload admission console contract missing %q", contract)
		}
	}
	for _, contract := range []string{"applicationWorkloadTypes", "applicationCapabilityTraits", "applicationResourceTypes", "applicationWorkspaceProfiles", "selectApplicationLibraryTask", "renderApplicationLibraryOptions", "parseManagedResourceOutputs", "loadApplicationDelivery", "emptyDisclosureState", "application-composition-library", "application-binding-workflow", "/api/v1/application-platform/workload-types", "/api/v1/application-platform/capability-traits", "/api/v1/application-platform/resource-types", "/api/v1/application-platform/workspace-profiles", "applicationReleases", "applicationEnvironmentBindings", "applicationWorkspaceBindings", "applicationDeploymentPlan", "applicationDeploymentRun", "/api/v1/application-platform/releases", "/api/v1/application-platform/environment-bindings", "/deployment-plan", "/deployments", "/approve", "/api/v1/application-platform/resolve", "/application-platform/environment-bindings/", "/api/v1/workspaces/", "workloadImageReference", "renderApplicationDeploymentPlan", "renderApplicationDeliveryJourney", "aria-disabled", "blockedReasons", "data.blockedReason", "openApplicationDeliveryStep", "scheduleApplicationDeploymentStatusRefresh", "applicationDeploymentIsActive", "refreshApplicationDeployment", "updatedReplicas", "availableReplicas", "Create an approval-gated deployment", "Application deployment approved and queued; target convergence is still pending.", "lastFailureClass==='UNKNOWN'", "RECOVERY_REQUIRED", "target agent performs read-only recovery readback", "Mutation outcome is ambiguous; automatic replay is blocked", "Deterministic application deployment plan rendered; no target mutation occurred.", "viewerSafePostPath.startsWith('/api/v1/application-platform/environment-bindings/')", "Immutable application release requires an exact digest-pinned workload image.", "Desired environment binding created. No runtime deployment has been inferred.", "createdId=created?.id", "automatic status refresh temporarily failed", "Legacy releases without an artifact remain readable but are not deployable.", "promotionCandidates", "item.name===currentRelease.name", "item.workloadTypeDigest===currentRelease.workloadTypeDigest", "If-Match", "Preview only. No target", "Runtime convergence and Physical certification remain separate"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("J8 application composition runtime contract missing %q", contract)
		}
	}
	for _, contract := range []string{"loadDaprRuntimePage", "renderDaprRuntimePrerequisite", "assessAndResumeDaprRuntime", "latestOperation", "data-dapr-prerequisite-kind", "selectApplicationLibraryTask('trait')", "dapr-lifecycle-workflow", "dapr-workload-workflow", "application-runtime.dapr", "dapr:loadDaprRuntimePage", "daprWorkloadPlan", "daprWorkloadAdmission", "setScopedAccess($('#dapr-lifecycle-form')", "setScopedAccess($('#dapr-lifecycle-approve')", "/api/v1/application-platform/dapr/assessment", "/api/v1/application-platform/dapr/workload-plan", "/api/v1/application-platform/dapr/workload-admissions", "configurationProjection", "componentScopeDigest", "Target admission requires an exact digest-pinned workload image", "Admission proves current policy/scopes and server-side injection only"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("J8 Dapr workload admission runtime contract missing %q", contract)
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
	for _, contract := range []string{"syncMobileNavAccessibility", "sidebar.inert", "pageLoadController", "AbortController", "route-announcer", "aria-busy", "hasActiveWork(state.currentPage)", "applicationDeploymentStatusGeneration", "page-action-availability", "renderActionAvailability", "scheduleActionAvailability", "button:disabled[title]", "No admitted executable offer is published in this release", "const changed=await navigate(destination)", "scrollIntoView({block:'nearest',inline:'nearest'})", "Fleet & Workspaces", "ناوگان و فضاهای کاری", "service-provider-setup", "Release A", "Release B"} {
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
	for _, contract := range []string{"operationalActionStateReason", "actionStateUnavailable", "statefulMutationActionKeys", "actionContractHandled=true", "Action-state contract is unavailable", "Cancellation is already requested", "Revalidation is available only between waves", "operationAction", "Start recovery", "/compensation/start", "mutationOutcomeCandidate", "captureMutationOutcome", "Request accepted; terminal success is not implied.", "mutation-outcome-view"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("C3 action/workflow/evidence contract missing %q", contract)
		}
	}
	if !strings.Contains(html, `id="mutation-outcome"`) {
		t.Fatal("C3 authoritative mutation outcome rail is missing")
	}
	for _, actionKey := range []string{
		"importAction", "providerProfileAction", "providerClusterAction", "marketplaceAction", "baselineAction", "verificationAction", "certificationAction", "closureAction", "recoveryAction", "upgradeAction", "tenantAction",
		"serviceAccountAction", "apiTokenAction", "notificationDestinationAction", "notificationRouteAction", "gitProviderAction", "gitCredentialAction", "blueprintAction", "catalogAction", "gitPrAction",
		"clusterAction", "agentCertificateAction", "maintenanceWindowAction", "maintenanceRunAction", "driftAction", "fleetAction", "workspaceBindingAction", "catalogTrustAction",
	} {
		if !strings.Contains(js, `"`+actionKey+`"`) && !strings.Contains(js, `'`+actionKey+`'`) {
			t.Fatalf("C3 action-state registry missing %q", actionKey)
		}
	}
	for _, contract := range []string{"membershipRevoke", "oidcMappingRevoke", "notificationRetryDeadLetter", "Organization membership is no longer", "OIDC group mapping is no longer", "Notification delivery is no longer", "maintenance window", "maintenance run", "Workspace binding is no longer", "Catalog trust key is no longer", "Drift finding is no longer present"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("C3 remaining action-family guard missing %q", contract)
		}
	}
	for _, contract := range []string{"Create OIDC group mapping", "Change organization access", "Issue API token", "Rotate API token", "Review upgrade campaign"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("C3 impact/review convergence missing %q", contract)
		}
	}
	for _, contract := range []string{"Support & diagnostics", "Drift details", "Recovery checkpoints", "Configure routing", "Provider setup &amp; credentials", "Repository &amp; publishing actions", "Catalog governance actions", `data-blueprint-step="1"`, `data-blueprint-step="4"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("C3 workflow-density convergence missing %q", contract)
		}
	}
	for _, contract := range []string{"explicitMutationKeys", "operationCancel", "membershipRevoke", "oidcMappingRevoke", "gitLkgRollback", "notificationRetryDeadLetter"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("read-only mutation intent contract missing %q", contract)
		}
	}
	for _, contract := range []string{"data-record-row", "tableRecords", "role=\"region\"", "scope=\"col\"", "data-table-sort-index", "aria-sort", "data-sort-value", "data-table-key", "tableSortPreferences", "restoreDataTableSortPreferences", "sourceUnavailable", "pageLoadFailure", "Data still visible on this page may be stale", "data-retry-current"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("operator data-workspace contract missing %q", contract)
		}
	}
	if !strings.Contains(css, ".metric-card strong") || !strings.Contains(css, "overflow-wrap:anywhere") {
		t.Fatal("metric identifiers must wrap instead of causing mobile document overflow")
	}
	for _, contract := range []string{
		"Operator Horizon V4", ".product-flow", "grid-template-columns:repeat(4,minmax(0,1fr))",
		"min-height: 44px", "@media (prefers-reduced-motion: reduce)", "border-inline-start: 4px solid var(--accent)", "grid-template-columns: repeat(auto-fit",
		"--success-fg:", "--warning-fg:", "--danger-fg:", "--focus-ring:", "--focus-halo:", ".badge.technical { white-space: normal", ".application-library-picker", ".application-delivery-journey", "button[data-state=\"current\"]", ".application-delivery-guidance", ".data-table", ".data-table-shell", ".data-table-sort", ".unavailable-state",
	} {
		if !strings.Contains(css, contract) {
			t.Fatalf("operator design-system contract missing %q", contract)
		}
	}
}


func TestOperatorConsoleLiveProgressRefreshContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	js := string(jsBytes)
	for _, marker := range []string{
		"const livePages=new Set(['overview','clusters','providers','marketplace','baselines','verification','fleet','workspaces'",
		"workspaces:[state.virtualClusters]",
		"clusters:[state.imports,state.clusterMaintenanceRuns]",
		"RESTORING|RECONCILING|RECOVERING",
		"focused||hasUnsavedChanges()||recentInteraction",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("live progress refresh contract missing %q", marker) }
	}
	if strings.Contains(js, "const expanded=!!$('.page.active details[open]')") {
		t.Fatal("open read-only disclosures must not freeze live progress refresh")
	}
}

func TestOperatorConsoleActionableEmptyStateContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, marker := range []string{
		"emptyFocusState",
		"emptyDisclosureState('No maintenance windows'",
		"emptyDisclosureState('No enrollment requests'",
		"emptyFocusState('No recommendations'",
		"emptyFocusState('No files added'",
		"emptyDisclosureState('No overlays'",
		"emptyDisclosureState('No pull requests'",
		"emptyDisclosureState('No backup or restore runs'",
		"emptyState('No fleet health data'",
		"'maintenance-window-name'",
		"'blueprint-project'",
		"'global-organization-scope'",
		"'cluster-import-console'",
		"'marketplace-objective'",
		"'git-file-path'",
		"'blueprint-expert-tools'",
		"'service-publishing-console'",
		"'data-protection-console'",
		"Manage agent identities",
		"renderDaprRuntimePrerequisite",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("actionable empty-state runtime missing %q", marker) }
	}
	for _, id := range []string{"cluster-import-console", "cluster-project", "maintenance-window-name", "blueprint-project", "global-organization-scope", "marketplace-objective", "git-file-path", "blueprint-expert-tools", "service-publishing-console", "data-protection-console", "data-protection-cluster", "dapr-prerequisite"} {
		if !strings.Contains(html, `id="`+id+`"`) { t.Fatalf("actionable empty-state owner target missing %q", id) }
	}
}

func TestOperatorConsoleFormValidationAccessibilityContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	cssBytes, err := fs.ReadFile(content, "static/styles.css")
	if err != nil { t.Fatal(err) }
	js, css := string(jsBytes), string(cssBytes)
	for _, marker := range []string{"function markFieldInvalid", "function clearFieldInvalid", "function updateFormValidationSummary", "function refreshFormValidationFeedback", "form-validation-summary", "aria-describedby", "addEventListener('invalid'", "aria-invalid"} {
		if !strings.Contains(js, marker) { t.Fatalf("form validation accessibility runtime missing %q", marker) }
	}
	for _, marker := range []string{`[aria-invalid="true"]`, ".field-invalid>span", ".field-error", ".form-validation-summary", `label:has(> :where(input,select,textarea)[required])` } {
		if !strings.Contains(css, marker) { t.Fatalf("form validation accessibility style missing %q", marker) }
	}
}

func TestOperatorConsoleApplicationProgressiveStepAdmissionContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	cssBytes, err := fs.ReadFile(content, "static/styles.css")
	if err != nil { t.Fatal(err) }
	js, css := string(jsBytes), string(cssBytes)
	for _, marker := range []string{
		"button.setAttribute('aria-disabled',blocked?'true':'false')",
		"button.dataset.blockedReason=blockedReasons[step]",
		"button?.getAttribute('aria-disabled')==='true'",
		"return false;",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("application progressive-step admission missing %q", marker) }
	}
	if !strings.Contains(css, `.application-delivery-journey button[data-state="blocked"]{opacity:.68;cursor:not-allowed}`) {
		t.Fatal("application blocked journey state must remain visibly non-activatable")
	}
}

func TestOperatorConsolePositionIndependentCopyContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, forbidden := range []string{">Left release<", ">Right release<", "stays above", "form above", "Forgejo below", "evidence below belongs", "operation above", "Use Ctrl/Command to select multiple", "Ctrl/Command to select multiple", "click the button", "tap the button", "hover over"} {
		if strings.Contains(strings.ToLower(html+"\n"+js), strings.ToLower(forbidden)) {
			t.Fatalf("responsive/RTL workflow copy must not depend on physical position: %q", forbidden)
		}
	}
	for _, required := range []string{`data-en="Release A"`, `data-en="Release B"`, `id="service-provider-setup"`} {
		if !strings.Contains(html, required) { t.Fatalf("position-independent workflow contract missing %q", required) }
	}
}

func TestOperatorConsoleHiddenOwnerEmptyStateRecoveryContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, id := range []string{"baseline-deploy-console", "catalog-governance-console", "service-provider-setup"} {
		if !strings.Contains(html, `id="`+id+`"`) { t.Fatalf("hidden owner workflow recovery anchor missing %q", id) }
	}
	for _, marker := range []string{
		"emptyDisclosureState('No baseline deployments'",
		"emptyDisclosureState('No trust keys'",
		"emptyDisclosureState('No governed catalog releases'",
		"emptyDisclosureState('No Git providers'",
		"sourceUnavailable('baseline deployments')?unavailableState",
		"sourceUnavailable('catalog releases')",
		"canAdminister()?emptyDisclosureState('No Git providers'",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("hidden owner empty-state recovery missing %q", marker) }
	}
}

func TestOperatorConsoleApplicationEmptyStateJourneyContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	js := string(jsBytes)
	if strings.Contains(js, "Create WorkloadType authority through Product API or MCP") {
		t.Fatal("application empty state must not send operators to API/MCP when an owner Console workflow exists")
	}
	for _, marker := range []string{
		"emptyDisclosureState",
		"Create workload shape",
		"Create workspace profile",
		"Create environment binding",
		"renderApplicationDeliveryPrerequisite();",
		"syncApplicationDeliveryDisclosure();",
		"Active namespace binding",
		"Bind namespace",
		"library-workload",
		"library-profile",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("application direct empty/prerequisite journey missing %q", marker) }
	}
}

func TestOperatorConsoleCriticalInteractionLocalizationGrammarContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	js := string(jsBytes)
	for _, marker := range []string{
		"faInteractionNouns",
		"faInteractionRules",
		"localizeDynamicInteraction",
		"Approve the sealed Compact-3 install request",
		"Begin the bound compensation plan for",
		"Request cancellation for",
		"Approve this exact application deployment revision for target execution?",
		"Select at least one architecture.",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("critical interaction localization grammar missing %q", marker) }
	}
}

func TestOperatorConsolePersianCriticalInteractionContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, marker := range []string{
		`data-en="Confirm action" data-i18n="shell.confirmTitle"`,
		`data-en="Details" data-i18n="shell.detailsTitle"`,
	} {
		if !strings.Contains(html, marker) { t.Fatalf("Persian critical-dialog bootstrap missing %q", marker) }
	}
	for _, marker := range []string{
		"localizeDynamicText(title)",
		"localizeDynamicText(message)",
		"t('mutation.accepted'",
		"t('mutation.viewOperation'",
		"t('mutation.viewState'",
		"t('mutation.dismiss'",
		"localizeDynamicText(field.label)",
		"localizeDynamicText(option.label)",
	} {
		if !strings.Contains(js, marker) { t.Fatalf("Persian critical-interaction runtime missing %q", marker) }
	}
}

func TestOperatorConsolePersianNativeDesignContract(t *testing.T) {
	cssBytes, err := fs.ReadFile(content, "static/styles.css")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	css, js, html := string(cssBytes), string(jsBytes), string(htmlBytes)
	for _, contract := range []string{
		"Operator Horizon V4 — Persian-native technical shell",
		"--ui-background:var(--bg)", "--ui-radius-control:8px", "--ui-motion:180ms",
		`html[lang="fa"] body{font-size:15px;line-height:var(--ui-line-height-fa);letter-spacing:0}`,
		"--ui-space-2:8px", "--ui-control-hit:44px", "padding-inline-start:8px;padding-inline-end:28px", ".overview-context-strip", ".context-signal[data-tone=\"danger\"]", `html[dir="rtl"] .data-table :where(.technical,[data-ltr="true"])`,
		`html[dir="rtl"] :where(.technical,code,pre,kbd,[data-ltr="true"],input[type="email"],input[type="url"],input[type="tel"])`,
	} {
		if !strings.Contains(css, contract) { t.Fatalf("Persian-native design contract missing %q", contract) }
	}
	for _, contract := range []string{"localStorage.getItem('platformLocale') || 'fa'", "const displayNumber=value=>", "fa-IR-u-nu-arabext", "fa-IR-u-ca-persian-nu-arabext", "count.textContent=displayNumber(records.length)", "state.locale==='fa'?'←':'→'", "renderOverviewContext", "همهٔ محدوده‌های مجاز", "t('shell.leaveDiscard'"} {
		if !strings.Contains(js, contract) { t.Fatalf("Persian-native runtime contract missing %q", contract) }
	}
	if !strings.Contains(html, `<html dir="rtl" lang="fa">`) || !strings.Contains(html, `id="language-toggle" type="button">EN</button>`) || !strings.Contains(html, `data-localized-number="1">۱</span>`) || !strings.Contains(html, `id="overview-context-strip"`) {
		t.Fatal("Persian-first shell bootstrap contract missing")
	}
	if strings.Contains(strings.ReplaceAll(css, " ", ""), "flex-direction:row-reverse") {
		t.Fatal("RTL layout must use logical properties instead of physical row reversal")
	}
	physicalDirection := regexp.MustCompile(`(^|[;{][[:space:]]*)(left|right|margin-left|margin-right|padding-left|padding-right|border-left|border-right)[[:space:]]*:`)
	if match := physicalDirection.FindString(css); match != "" {
		t.Fatalf("RTL layout must use logical CSS properties, found %q", match)
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

func TestOperatorConsolePersianLocalFontContract(t *testing.T) {
	cssBytes, err := fs.ReadFile(content, "static/styles.css")
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

func jsIndex(value, needle string, t *testing.T) int {
	t.Helper()
	idx := strings.Index(value, needle)
	if idx < 0 {
		t.Fatalf("javascript contract marker %q missing", needle)
	}
	return idx
}

func TestOKDImportHealthProfileAndReconnectAreVisibleInClusterDetail(t *testing.T) {
	raw, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(raw)
	for _, contract := range []string{"OKD health & profile", "Reconnect authority", "okdImportAdmitted", "targetProfile", "upgradeBlocked", "Desired / observed component decisions", "Issue mutation access manifest", "Target RBAC cleanup", "/mutation-rbac-manifest", "/revocation-rbac-manifest", "/revocation-rbac-acknowledgement"} {
		if !strings.Contains(app, contract) {
			t.Fatalf("OKD operator-console contract missing %q", contract)
		}
	}
}

func TestOperationsQueueCenterIsScopedBoundedAndReadOnly(t *testing.T) {
	raw, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(raw)
	for _, token := range []string{
		"renderOperationsQueueCenter",
		"OPERATIONS_QUEUE_CENTER_V1",
		"Queue work items",
		"Operation pending",
		"Notification pending",
		"Outbox pending",
		"read-only",
		"scope-before-limit",
		"truncated lanes",
	} {
		if !strings.Contains(app, token) {
			t.Fatalf("operations queue-center contract missing %q", token)
		}
	}
	if strings.Contains(app, "data-operation-claim") || strings.Contains(app, "data-operation-transition") {
		t.Fatal("operator console must not expose raw worker claim/transition controls")
	}
}

func TestInfrastructureProviderConsoleContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, js := string(htmlBytes), string(jsBytes)
	for _, id := range []string{`id="provider-infrastructure-provider"`, `id="provider-infrastructure-endpoint"`, `id="provider-credential-ref"`, `id="provider-managed-fields"`} {
		if !strings.Contains(html, id) {
			t.Fatalf("provider console DOM missing %s", id)
		}
	}
	for _, option := range []string{`value="vmware"`, `value="aws"`, `value="azure"`, `value="gcp"`} {
		if !strings.Contains(html, option) {
			t.Fatalf("provider option missing %s", option)
		}
	}
	for _, contract := range []string{"infrastructureProvider:$('#provider-infrastructure-provider').value", "infrastructureEndpoint:$('#provider-infrastructure-endpoint').value.trim()", "credentialRef:$('#provider-credential-ref').value.trim()", "['vmware','aws','azure','gcp'].includes(provider)", "$('#provider-infrastructure-endpoint').disabled=managed&&!vmware", "$('#provider-credential-ref').required=managed"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("provider console behavior missing %q", contract)
		}
	}
	lower := strings.ToLower(html + js)
	for _, forbidden := range []string{"vcenter password", "vcenter username", "aws access key", "azure client secret", "gcp private key"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("console must not collect raw provider credential field %q", forbidden)
		}
	}
}

func TestOperatorConsoleFailsClosedOnUnknownResourceScope(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(jsBytes)
	for _, contract := range []string{
		"resourceScopeRegistry",
		"/api/v1/access/resource-scopes",
		"assertResourceScopeKnown",
		"RESOURCE_SCOPE_AUTHORITY_UNAVAILABLE",
		"RESOURCE_SCOPE_OWNER_REVIEW_REQUIRED",
	} {
		if !strings.Contains(js, contract) {
			t.Fatalf("resource scope console fail-closed contract missing %q", contract)
		}
	}
}

func TestHandlerServesFaviconWithout404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("favicon status=%d want=%d", w.Code, http.StatusNoContent)
	}
}

func TestFleetReliabilityConsoleContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, js := string(htmlBytes), string(jsBytes)
	for _, id := range []string{"reliability-summary", "reliability-delivery-summary", "reliability-delivery-evidence", "reliability-cluster-grid", "reliability-incident-grid", "reliability-slo-grid", "reliability-incident-form", "reliability-slo-form"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Fatalf("fleet reliability DOM contract missing %q", id)
		}
	}
	for _, route := range []string{"/api/v1/reliability/service-health", "/api/v1/reliability/incidents", "/api/v1/reliability/slo-policies", "/api/v1/reliability/error-budgets", "/api/v1/reliability/delivery-insights"} {
		if !strings.Contains(js, route) {
			t.Fatalf("fleet reliability API journey missing %q", route)
		}
	}
	for _, contract := range []string{"reliabilityCoverageStatus", "UNKNOWN", "data-reliability-incident-action", "If-Match", "reliabilityErrorBudgets", "$('#reliability-incident-form').onsubmit", "$('#reliability-incident-grid').onclick", "$('#reliability-slo-form').onsubmit", "resolutionSummary"} {
		if !strings.Contains(js, contract) {
			t.Fatalf("fleet reliability behavior contract missing %q", contract)
		}
	}
}

func TestEdgeSovereignConsoleContract(t *testing.T) {
	htmlBytes, err := fs.ReadFile(content, "static/index.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := fs.ReadFile(content, "static/app.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, fragment := range []string{`data-page="edge"`, `id="edge"`, `id="edge-policy-form"`, `id="edge-mutation-form"`, `id="edge-reconnect-form"`, `id="edge-boot-form"`, `id="edge-ai-form"`, "Central authority remains canonical.", "they do not execute runtime mutations"} {
		if !strings.Contains(html, fragment) { t.Fatalf("edge sovereign console contract missing %q", fragment) }
	}
	for _, endpoint := range []string{"/api/v1/edge/local-authority/policies/compile", "/api/v1/edge/local-authority/mutations/admit", "/api/v1/edge/local-authority/reconnect/resolve", "/api/v1/edge/boot-attestations/assess", "/api/v1/edge/local-ai/profiles/validate"} {
		if !strings.Contains(js, endpoint) { t.Fatalf("edge sovereign endpoint missing from console %q", endpoint) }
	}
	for _, truth := range []string{"No runtime mutation was executed.", "Execution still requires a durable operation.", "runtime was not started."} {
		if !strings.Contains(js, truth) { t.Fatalf("edge truth boundary missing %q", truth) }
	}
}
