package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/agentpki"
	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/auth"
	bp "platform.4so.io/factory/internal/blueprint"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/integrations"
	"platform.4so.io/factory/internal/managedinstall"
	"platform.4so.io/factory/internal/marketplace"
	"platform.4so.io/factory/internal/virtualcluster"
	"platform.4so.io/factory/internal/plan"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Server struct {
	components                   map[string]catalog.Component
	store                        controlplane.Store
	logger                       *slog.Logger
	mux                          *http.ServeMux
	version                      string
	requestSeq                   atomic.Uint64
	services                     *integrations.Client
	fleetAgentImage              string
	fleetPublicURL               string
	publicCAPEM                  string
	runtimeProbeImage            string
	runtimeClosureReleaseDigest  string
	runtimeClosureProducerDigest string
	marketplaceAdvisor           *marketplace.ControlledAdvisor
	aiRuntime                    *airuntime.Runtime
	agentPKI                     *agentpki.Signer
	agentMTLSRequired            bool
	catalogSigner                ed25519.PrivateKey
	catalogSignerMode            string
	oidcGroupPropagationTTL      time.Duration
	managedOKDInstallExecutor    *managedinstall.Executor
	virtualClusterRuntimeSource  virtualcluster.RuntimeSource
	virtualClusterRuntimeDigest  string
	virtualClusterRuntimeReady   bool
}

func New(version string, components map[string]catalog.Component, logger *slog.Logger, stores ...controlplane.Store) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	var store controlplane.Store = controlplane.NewMemoryStore()
	if len(stores) > 0 && stores[0] != nil {
		store = stores[0]
	}
	s := &Server{components: components, store: store, logger: logger, mux: http.NewServeMux(), version: version}
	s.routes()
	return s
}
func (s *Server) Handler() http.Handler { return s.requestLog(securityHeaders(s.mux)) }

type readinessCounter interface {
	ReadinessCounts(context.Context) (organizations int, operations int, err error)
}

type controlPlaneSummaryCounter interface {
	ControlPlaneSummaryCounts(context.Context, []string, []string, []string, bool, bool) (controlplane.ControlPlaneSummaryCounts, error)
}

type controlPlaneAttentionStore interface {
	ControlPlaneAttention(context.Context, []string, bool, int) ([]controlplane.OperatorAttentionItem, error)
}

type operationPageStore interface {
	ListOperationsPage(context.Context, string, int) ([]controlplane.Operation, error)
}

type operationScopedPageStore interface {
	ListOperationsPageByProjects(context.Context, []string, int) ([]controlplane.Operation, error)
}

type notificationScopedEventPageStore interface {
	ListNotificationEventsPageByScopes(context.Context, []string, []string, int) ([]controlplane.NotificationEvent, error)
}

type notificationScopedDeliveryPageStore interface {
	ListNotificationDeliveriesPageByScopes(context.Context, []string, []string, controlplane.NotificationDeliveryState, int) ([]controlplane.NotificationDelivery, error)
}

type auditScopedPageStore interface {
	ListAuditPageByScopes(context.Context, []string, []string, int) ([]controlplane.AuditEvent, error)
}

func boolSetIDs(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for id, allowed := range values {
		if allowed && strings.TrimSpace(id) != "" {
			out = append(out, id)
		}
	}
	return out
}

func (s *Server) readinessCounts(ctx context.Context) (int, int, error) {
	if counter, ok := s.store.(readinessCounter); ok {
		return counter.ReadinessCounts(ctx)
	}
	organizations, err := s.store.ListOrganizations(ctx)
	if err != nil {
		return 0, 0, err
	}
	operations, err := s.store.ListOperations(ctx, "")
	if err != nil {
		return 0, 0, err
	}
	return len(organizations), len(operations), nil
}

func (s *Server) ConfigureSystemServices(client *integrations.Client) { s.services = client }
func (s *Server) ConfigureMarketplaceAdvisor(advisor *marketplace.ControlledAdvisor) {
	s.marketplaceAdvisor = advisor
}
func (s *Server) ConfigureAIRuntime(runtime *airuntime.Runtime) { s.aiRuntime = runtime }
func (s *Server) ConfigureAgentMTLS(signer *agentpki.Signer, required bool) {
	s.agentPKI = signer
	s.agentMTLSRequired = required
}
func (s *Server) ConfigureCatalogSigner(privateKey ed25519.PrivateKey, mode string) {
	if len(privateKey) != ed25519.PrivateKeySize {
		s.catalogSigner = nil
		s.catalogSignerMode = "disabled"
		return
	}
	s.catalogSigner = append(ed25519.PrivateKey(nil), privateKey...)
	s.catalogSignerMode = strings.TrimSpace(mode)
	if s.catalogSignerMode == "" {
		s.catalogSignerMode = "configured"
	}
}

func (s *Server) ConfigureIdentityAuthority(groupPropagationTTL time.Duration) {
	s.oidcGroupPropagationTTL = groupPropagationTTL
}

func (s *Server) ConfigureManagedOKDInstallExecutor(executor *managedinstall.Executor) {
	s.managedOKDInstallExecutor = executor
}

func (s *Server) ConfigureVirtualClusterRuntimeSource(source virtualcluster.RuntimeSource) error {
	if err := virtualcluster.ValidateRuntimeExecutionSource(source); err != nil {
		return err
	}
	digest, err := virtualcluster.RuntimeSourceDigest(source)
	if err != nil {
		return err
	}
	s.virtualClusterRuntimeSource = source
	s.virtualClusterRuntimeDigest = digest
	s.virtualClusterRuntimeReady = true
	return nil
}

func (s *Server) ConfigureFleetImport(agentImage, runtimeProbeImage, publicURL, publicCAPEM string) {
	s.fleetAgentImage = strings.TrimSpace(agentImage)
	s.runtimeProbeImage = strings.TrimSpace(runtimeProbeImage)
	s.fleetPublicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
	s.publicCAPEM = strings.TrimSpace(publicCAPEM)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Health(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "control-plane store is unavailable")
			return
		}
		organizations, operations, err := s.readinessCounts(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "control-plane store is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "backend": s.store.Backend(), "catalogComponents": len(s.components), "catalogDigest": catalog.Digest(s.components), "organizations": organizations, "operations": operations})
	})
	s.mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"product": "4SO Platform Factory", "version": s.version})
	})
	s.mux.HandleFunc("GET /api/v1/access/context", s.accessContext)
	s.mux.HandleFunc("GET /api/v1/access/resource-scopes", s.resourceScopeRegistry)
	s.mux.HandleFunc("GET /api/v1/reliability/service-health", s.reliabilityServiceHealth)
	s.mux.HandleFunc("GET /api/v1/reliability/incidents", s.listReliabilityIncidents)
	s.mux.HandleFunc("POST /api/v1/reliability/incidents", s.createReliabilityIncident)
	s.mux.HandleFunc("GET /api/v1/reliability/incidents/{id}", s.getReliabilityIncident)
	s.mux.HandleFunc("POST /api/v1/reliability/incidents/{id}/acknowledge", s.acknowledgeReliabilityIncident)
	s.mux.HandleFunc("POST /api/v1/reliability/incidents/{id}/resolve", s.resolveReliabilityIncident)
	s.mux.HandleFunc("GET /api/v1/reliability/slo-policies", s.listReliabilitySLOPolicies)
	s.mux.HandleFunc("POST /api/v1/reliability/slo-policies", s.createReliabilitySLOPolicy)
	s.mux.HandleFunc("GET /api/v1/reliability/error-budgets", s.reliabilityErrorBudgets)
	s.mux.HandleFunc("GET /api/v1/identity/authority", s.identityAuthority)
	s.mux.HandleFunc("POST /api/v1/identity/saml-brokers", s.createSAMLBroker)
	s.mux.HandleFunc("GET /api/v1/identity/saml-brokers", s.listSAMLBrokers)
	s.mux.HandleFunc("PUT /api/v1/identity/saml-brokers/{id}", s.updateSAMLBroker)
	s.mux.HandleFunc("DELETE /api/v1/identity/saml-brokers/{id}", s.deleteSAMLBroker)
	s.mux.HandleFunc("GET /api/v1/identity/admin-jobs", s.listIdentityAdminJobs)
	s.mux.HandleFunc("GET /api/v1/identity/admin-jobs/{id}", s.getIdentityAdminJob)
	s.mux.HandleFunc("POST /api/v1/identity/admin-jobs/{id}/approve", s.approveIdentityAdminJob)
	s.mux.HandleFunc("POST /api/v1/compliance/profiles", s.createComplianceProfile)
	s.mux.HandleFunc("GET /api/v1/compliance/profiles", s.listComplianceProfiles)
	s.mux.HandleFunc("POST /api/v1/compliance/scans", s.createComplianceScan)
	s.mux.HandleFunc("GET /api/v1/compliance/scans", s.listComplianceScans)
	s.mux.HandleFunc("GET /api/v1/compliance/scans/{id}", s.getComplianceScan)
	s.mux.HandleFunc("GET /api/v1/compliance/findings", s.listComplianceFindings)
	s.mux.HandleFunc("POST /api/v1/compliance/findings/{fingerprint}/recheck", s.recheckComplianceFinding)
	s.mux.HandleFunc("POST /api/v1/compliance/waivers", s.createComplianceWaiver)
	s.mux.HandleFunc("POST /api/v1/compliance/waivers/{id}/approve", s.approveComplianceWaiver)
	s.mux.HandleFunc("POST /api/v1/compliance/waivers/{id}/revoke", s.revokeComplianceWaiver)
	s.mux.HandleFunc("POST /api/v1/identity/group-mappings", s.createOIDCGroupMapping)
	s.mux.HandleFunc("GET /api/v1/identity/group-mappings", s.listOIDCGroupMappings)
	s.mux.HandleFunc("POST /api/v1/identity/group-mappings/{id}/revoke", s.revokeOIDCGroupMapping)
	s.mux.HandleFunc("GET /api/v1/security-audit-events", s.listSecurityAudit)
	s.mux.HandleFunc("GET /api/v1/catalog/components", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, catalog.Sorted(s.components))
	})
	s.mux.HandleFunc("GET /api/v1/catalog/summary", s.catalogSummary)
	s.mux.HandleFunc("GET /api/v1/catalog/runtime-certification-authority", s.componentRuntimeCertificationAuthority)
	s.mux.HandleFunc("GET /api/v1/catalog-governance/signing-identity", s.catalogSigningIdentity)
	s.mux.HandleFunc("POST /api/v1/catalog-trust-keys", s.createCatalogTrustKey)
	s.mux.HandleFunc("GET /api/v1/catalog-trust-keys", s.listCatalogTrustKeys)
	s.mux.HandleFunc("GET /api/v1/catalog-trust-keys/{id}/impact", s.getCatalogTrustKeyImpact)
	s.mux.HandleFunc("POST /api/v1/catalog-trust-keys/{id}/revoke", s.revokeCatalogTrustKey)
	s.mux.HandleFunc("POST /api/v1/catalog-releases", s.createCatalogRelease)
	s.mux.HandleFunc("GET /api/v1/catalog-releases", s.listCatalogReleases)
	s.mux.HandleFunc("GET /api/v1/catalog-releases/{id}", s.getCatalogRelease)
	s.mux.HandleFunc("PUT /api/v1/catalog-releases/{id}/draft", s.updateCatalogReleaseDraft)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/review", s.submitCatalogReview)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/request-changes", s.requestCatalogChanges)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/publish", s.publishCatalogRelease)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/deprecate", s.deprecateCatalogRelease)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/revoke", s.revokeCatalogRelease)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/promote", s.promoteCatalogRelease)
	s.mux.HandleFunc("POST /api/v1/catalog-releases/{id}/render", s.renderCatalogRelease)
	s.mux.HandleFunc("GET /api/v1/tenancy/plans", s.tenantPlans)
	s.mux.HandleFunc("GET /api/v1/blueprints/authoring-contract", s.blueprintAuthoringContract)
	s.mux.HandleFunc("POST /api/v1/blueprints/authoring-roundtrip", s.blueprintAuthoringRoundTrip)
	s.mux.HandleFunc("POST /api/v1/blueprints/validate", s.validate)
	s.mux.HandleFunc("POST /api/v1/compatibility/evaluate", s.evaluateCompatibility)
	s.mux.HandleFunc("GET /api/v1/target-architecture-model", s.getTargetArchitectureModel)
	s.mux.HandleFunc("GET /api/v1/mcp/delegation-architecture", s.getMCPDelegationArchitecture)
	s.mux.HandleFunc("POST /api/v1/mcp/trusted-clients", s.createMCPTrustedClient)
	s.mux.HandleFunc("GET /api/v1/mcp/trusted-clients", s.listMCPTrustedClients)
	s.mux.HandleFunc("POST /api/v1/mcp/trusted-clients/{id}/revoke", s.revokeMCPTrustedClient)
	s.mux.HandleFunc("POST /api/v1/mcp/delegation-grants/preview", s.previewMCPDelegation)
	s.mux.HandleFunc("POST /api/v1/mcp/delegation-grants", s.createMCPDelegationGrant)
	s.mux.HandleFunc("GET /api/v1/mcp/delegation-grants", s.listMCPDelegationGrants)
	s.mux.HandleFunc("POST /api/v1/mcp/delegation-grants/{id}/revoke", s.revokeMCPDelegationGrant)
	s.mux.HandleFunc("GET /api/v1/day2-campaign-engine", s.getDay2CampaignEngine)
	s.mux.HandleFunc("GET /api/v1/lab/guide", s.getLabGuide)
	s.mux.HandleFunc("GET /api/v1/ai/policy", s.getAIPolicy)
	s.mux.HandleFunc("GET /api/v1/ai/capabilities", s.aiCapabilities)
	s.mux.HandleFunc("GET /api/v1/ai/persian-writing", s.aiPersianWriting)
	s.mux.HandleFunc("GET /api/v1/ai/control-jobs", s.listAIControlJobs)
	s.mux.HandleFunc("GET /api/v1/ai/control-jobs/{id}", s.getAIControlJob)
	s.mux.HandleFunc("POST /api/v1/ai/control-jobs/{id}/resolve-recovery", s.resolveAIControlJobRecovery)
	s.mux.HandleFunc("POST /api/v1/ai/diagnose", s.diagnoseAI)
	s.mux.HandleFunc("GET /api/v1/ai/runs", s.listAIRuns)
	s.mux.HandleFunc("GET /api/v1/ai/runs/{id}", s.getAIRun)
	s.mux.HandleFunc("POST /mcp", s.mcp)
	s.mux.HandleFunc("POST /api/v1/blueprints/resolve", s.resolveBlueprintPreview)
	s.mux.HandleFunc("POST /api/v1/blueprint-overlays", s.createBlueprintOverlay)
	s.mux.HandleFunc("GET /api/v1/blueprint-overlays", s.listBlueprintOverlays)
	s.mux.HandleFunc("GET /api/v1/blueprint-overlays/{id}", s.getBlueprintOverlay)
	s.mux.HandleFunc("POST /api/v1/variable-schemas", s.createVariableSchema)
	s.mux.HandleFunc("GET /api/v1/variable-schemas", s.listVariableSchemas)
	s.mux.HandleFunc("GET /api/v1/variable-schemas/{id}", s.getVariableSchema)
	s.mux.HandleFunc("POST /api/v1/platform-policy-sets", s.createPlatformPolicySet)
	s.mux.HandleFunc("GET /api/v1/platform-policy-sets", s.listPlatformPolicySets)
	s.mux.HandleFunc("GET /api/v1/platform-policy-sets/{id}", s.getPlatformPolicySet)
	s.mux.HandleFunc("POST /api/v1/platform-templates", s.createPlatformTemplate)
	s.mux.HandleFunc("GET /api/v1/platform-templates", s.listPlatformTemplates)
	s.mux.HandleFunc("GET /api/v1/platform-templates/{id}", s.getPlatformTemplate)
	s.mux.HandleFunc("GET /api/v1/platform-templates/{id}/admission", s.getPlatformTemplateAdmission)
	s.mux.HandleFunc("POST /api/v1/workspaces", s.createWorkspace)
	s.mux.HandleFunc("GET /api/v1/workspaces", s.listWorkspaces)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}", s.getWorkspace)
	s.mux.HandleFunc("POST /api/v1/workspaces/{id}/bindings", s.createWorkspaceBinding)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}/bindings", s.listWorkspaceBindings)
	s.mux.HandleFunc("POST /api/v1/workspaces/{id}/bindings/{bindingId}/revoke", s.revokeWorkspaceBinding)
	s.mux.HandleFunc("POST /api/v1/workspaces/{id}/virtual-clusters", s.createVirtualCluster)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}/virtual-clusters", s.listVirtualClusters)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}", s.getVirtualCluster)
	s.mux.HandleFunc("POST /api/v1/plans", s.createPlan)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases", s.createBlueprintRelease)
	s.mux.HandleFunc("GET /api/v1/blueprint-releases", s.listBlueprintReleases)
	s.mux.HandleFunc("GET /api/v1/blueprint-releases/{id}", s.getBlueprintRelease)
	s.mux.HandleFunc("PUT /api/v1/blueprint-releases/{id}/draft", s.updateBlueprintReleaseDraft)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/review", s.submitBlueprintReview)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/request-changes", s.requestBlueprintChanges)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/publish", s.publishBlueprintRelease)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/deprecate", s.deprecateBlueprintRelease)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/revoke", s.revokeBlueprintRelease)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/{id}/clone", s.cloneBlueprintRelease)
	s.mux.HandleFunc("POST /api/v1/blueprint-releases/compare", s.compareBlueprintReleases)
	s.mux.HandleFunc("GET /api/v1/installations/profiles", s.installationProfiles)
	s.mux.HandleFunc("GET /api/v1/installations/integrations", s.installationIntegrations)
	s.mux.HandleFunc("GET /api/v1/installations/recovery-authority", s.installationRecoveryAuthority)
	s.mux.HandleFunc("GET /api/v1/autopilot/status", s.autopilotStatus)
	s.mux.HandleFunc("POST /api/v1/installations/plans", s.createInstallationPlan)
	s.mux.HandleFunc("GET /api/v1/managed-okd-installs/runtime", s.managedOKDInstallRuntime)
	s.mux.HandleFunc("POST /api/v1/managed-okd-installs", s.createManagedOKDInstall)
	s.mux.HandleFunc("GET /api/v1/managed-okd-installs/{id}", s.getManagedOKDInstall)
	s.mux.HandleFunc("POST /api/v1/managed-okd-installs/{id}/approve", s.approveManagedOKDInstall)
	s.mux.HandleFunc("GET /api/v1/git-authority", s.gitAuthority)
	s.mux.HandleFunc("POST /api/v1/git-credentials", s.createGitCredential)
	s.mux.HandleFunc("GET /api/v1/git-credentials", s.listGitCredentials)
	s.mux.HandleFunc("POST /api/v1/git-credentials/{id}/rotate", s.rotateGitCredential)
	s.mux.HandleFunc("POST /api/v1/git-credentials/{id}/revoke", s.revokeGitCredential)
	s.mux.HandleFunc("POST /api/v1/git-providers", s.createGitProvider)
	s.mux.HandleFunc("GET /api/v1/git-providers", s.listGitProviders)
	s.mux.HandleFunc("PUT /api/v1/git-providers/{id}/credential", s.rebindGitProviderCredential)
	s.mux.HandleFunc("GET /api/v1/system-services", s.systemServices)
	s.mux.HandleFunc("POST /api/v1/system-services/git/repositories", s.ensureGitRepository)
	s.mux.HandleFunc("POST /api/v1/system-services/git/revisions", s.publishGitRevision)
	s.mux.HandleFunc("GET /api/v1/system-services/git/revisions", s.listManagedGitRevisions)
	s.mux.HandleFunc("POST /api/v1/system-services/git/revisions/{id}/observe-sync", s.observeGitRevisionSynchronization)
	s.mux.HandleFunc("GET /api/v1/system-services/git/last-known-good", s.getLastKnownGoodGitRevision)
	s.mux.HandleFunc("POST /api/v1/system-services/git/last-known-good/rollback", s.rollbackLastKnownGoodGitRevision)
	s.mux.HandleFunc("GET /api/v1/system-services/git/pull-requests", s.listGitPullRequests)
	s.mux.HandleFunc("POST /api/v1/system-services/git/pull-requests/{id}/approve", s.approveGitPullRequest)
	s.mux.HandleFunc("POST /api/v1/system-services/git/pull-requests/{id}/merge", s.mergeGitPullRequest)
	s.mux.HandleFunc("POST /api/v1/drift-scans/{id}/adopt-git", s.adoptGitDrift)
	s.mux.HandleFunc("POST /api/v1/drift-scans/{id}/targets/{clusterId}/findings/{fingerprint}/remediate", s.remediateDriftFinding)

	s.mux.HandleFunc("GET /api/v1/control-plane/summary", s.controlPlaneSummary)
	s.mux.HandleFunc("GET /api/v1/operations/queue-center", s.operationsQueueCenter)
	s.mux.HandleFunc("GET /api/v1/logs", s.productLogs)
	s.mux.HandleFunc("GET /api/v1/control-plane/attention", s.controlPlaneAttention)
	s.mux.HandleFunc("POST /api/v1/organizations", s.createOrganization)
	s.mux.HandleFunc("GET /api/v1/organizations", s.listOrganizations)
	s.mux.HandleFunc("GET /api/v1/organizations/{id}", s.getOrganization)
	s.mux.HandleFunc("PUT /api/v1/organizations/{id}", s.updateOrganization)
	s.mux.HandleFunc("GET /api/v1/organizations/{id}/memberships", s.listOrganizationMemberships)
	s.mux.HandleFunc("PUT /api/v1/organizations/{id}/memberships/{subject}", s.upsertOrganizationMembership)
	s.mux.HandleFunc("POST /api/v1/organizations/{id}/memberships/{subject}/revoke", s.revokeOrganizationMembership)
	s.mux.HandleFunc("POST /api/v1/service-accounts", s.createServiceAccount)
	s.mux.HandleFunc("GET /api/v1/service-accounts", s.listServiceAccounts)
	s.mux.HandleFunc("GET /api/v1/service-accounts/{id}", s.getServiceAccount)
	s.mux.HandleFunc("POST /api/v1/service-accounts/{id}/revoke", s.revokeServiceAccount)
	s.mux.HandleFunc("POST /api/v1/service-accounts/{id}/tokens", s.issueAPIToken)
	s.mux.HandleFunc("GET /api/v1/service-accounts/{id}/tokens", s.listAPITokens)
	s.mux.HandleFunc("POST /api/v1/service-accounts/{id}/tokens/{tokenId}/revoke", s.revokeAPIToken)
	s.mux.HandleFunc("POST /api/v1/service-accounts/{id}/tokens/{tokenId}/rotate", s.rotateAPIToken)
	s.mux.HandleFunc("POST /api/v1/projects", s.createProject)
	s.mux.HandleFunc("GET /api/v1/projects", s.listProjects)
	s.mux.HandleFunc("POST /api/v1/operations", s.createOperation)
	s.mux.HandleFunc("GET /api/v1/operations", s.listOperations)
	s.mux.HandleFunc("GET /api/v1/operations/{id}", s.getOperation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/transition", s.transitionOperation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/claim", s.claimOperation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/lease/renew", s.renewOperationLease)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/attempt/start", s.startOperationAttempt)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/attempt/verify", s.beginOperationVerification)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/attempt/failure", s.reportOperationFailure)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/attempt/complete", s.completeOperation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/cancel", s.cancelOperation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/cancel/ack", s.acknowledgeOperationCancellation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/plan", s.setOperationCompensationPlan)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/forward/{stepKey}/complete", s.recordOperationForwardStepCompleted)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/start", s.beginOperationCompensation)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/claim-next", s.claimNextOperationCompensationStep)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/{stepKey}/complete", s.completeOperationCompensationStep)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/compensation/{stepKey}/failure", s.failOperationCompensationStep)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/steps", s.appendOperationStep)
	s.mux.HandleFunc("POST /api/v1/operations/{id}/steps/{phase}/{stepKey}/trace", s.appendOperationStepTrace)
	s.mux.HandleFunc("GET /api/v1/operations/{id}/evidence/{evidenceId}/payload", s.getOperationEvidencePayload)
	s.mux.HandleFunc("GET /api/v1/audit-events", s.listAudit)
	s.mux.HandleFunc("GET /api/v1/notification-event-types", s.notificationEventTypes)
	s.mux.HandleFunc("GET /api/v1/notification-provider-contracts", s.notificationProviderContracts)
	s.mux.HandleFunc("POST /api/v1/notification-routing/preview", s.previewNotificationRouting)
	s.mux.HandleFunc("POST /api/v1/external-registry/admission", s.admitExternalRegistry)
	s.mux.HandleFunc("POST /api/v1/finops/budget-policies", s.createFinOpsBudgetPolicy)
	s.mux.HandleFunc("GET /api/v1/finops/budget-policies", s.listFinOpsBudgetPolicies)
	s.mux.HandleFunc("GET /api/v1/finops/budget-policies/{id}", s.getFinOpsBudgetPolicy)
	s.mux.HandleFunc("GET /api/v1/finops/insights", s.getFinOpsInsights)
	s.mux.HandleFunc("POST /api/v1/finops/rate-cards", s.createFinOpsRateCard)
	s.mux.HandleFunc("GET /api/v1/finops/rate-cards", s.listFinOpsRateCards)
	s.mux.HandleFunc("GET /api/v1/finops/rate-cards/{id}", s.getFinOpsRateCard)
	s.mux.HandleFunc("POST /api/v1/finops/usage-measurements", s.createFinOpsUsageMeasurement)
	s.mux.HandleFunc("GET /api/v1/finops/usage-measurements", s.listFinOpsUsageMeasurements)
	s.mux.HandleFunc("POST /api/v1/finops/capacity-observations", s.createFinOpsCapacityObservation)
	s.mux.HandleFunc("GET /api/v1/finops/capacity-observations", s.listFinOpsCapacityObservations)
	s.mux.HandleFunc("GET /api/v1/finops/showback", s.getFinOpsShowback)
	s.mux.HandleFunc("GET /api/v1/finops/chargeback-export", s.exportFinOpsChargeback)
	s.mux.HandleFunc("POST /api/v1/notification-destinations", s.createNotificationDestination)
	s.mux.HandleFunc("GET /api/v1/notification-destinations", s.listNotificationDestinations)
	s.mux.HandleFunc("GET /api/v1/notification-destinations/{id}", s.getNotificationDestination)
	s.mux.HandleFunc("PUT /api/v1/notification-destinations/{id}", s.updateNotificationDestination)
	s.mux.HandleFunc("POST /api/v1/notification-destinations/{id}/disable", s.disableNotificationDestination)
	s.mux.HandleFunc("POST /api/v1/notification-routes", s.createNotificationRoute)
	s.mux.HandleFunc("GET /api/v1/notification-routes", s.listNotificationRoutes)
	s.mux.HandleFunc("GET /api/v1/notification-routes/{id}", s.getNotificationRoute)
	s.mux.HandleFunc("GET /api/v1/notification-routes/{id}/policy-digest", s.notificationRoutePolicyDigest)
	s.mux.HandleFunc("PUT /api/v1/notification-routes/{id}", s.updateNotificationRoute)
	s.mux.HandleFunc("GET /api/v1/notification-events", s.listNotificationEvents)
	s.mux.HandleFunc("GET /api/v1/notification-events/{id}", s.getNotificationEvent)
	s.mux.HandleFunc("GET /api/v1/notification-deliveries", s.listNotificationDeliveries)
	s.mux.HandleFunc("GET /api/v1/notification-deliveries/{id}", s.getNotificationDelivery)
	s.mux.HandleFunc("POST /api/v1/notification-deliveries/{id}/retry", s.retryNotificationDelivery)
	s.mux.HandleFunc("POST /api/v1/cluster-imports", s.createClusterImport)
	s.mux.HandleFunc("GET /api/v1/cluster-imports", s.listClusterImports)
	s.mux.HandleFunc("GET /api/v1/cluster-imports/{id}", s.getClusterImport)
	s.mux.HandleFunc("POST /api/v1/cluster-imports/{id}/approve", s.approveClusterImport)
	s.mux.HandleFunc("POST /api/v1/cluster-imports/{id}/revoke", s.revokeClusterImport)
	s.mux.HandleFunc("POST /agent/v1/cluster-imports/{id}/claim", s.claimClusterImport)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/certificates/issue", s.issueAgentCertificate)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/certificates/current", s.currentAgentCertificate)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/certificates/rotate", s.rotateAgentCertificate)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/inventory", s.reportClusterInventory)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/heartbeat", s.heartbeatCluster)
	s.mux.HandleFunc("GET /api/v1/clusters", s.listManagedClusters)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}", s.getManagedCluster)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/mutation-rbac-manifest", s.getClusterMutationRBACManifest)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/mutation-rbac-manifest", s.issueClusterMutationRBACManifest)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/revocation-rbac-manifest", s.getClusterRevocationRBACManifest)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/revocation-rbac-acknowledgement", s.acknowledgeClusterTargetRBACRevocation)
	s.mux.HandleFunc("PUT /api/v1/clusters/{id}/maintenance-profile", s.upsertClusterMaintenanceProfile)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/maintenance-profile", s.getClusterMaintenanceProfile)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/node-lifecycle-authority", s.getTargetNodeLifecycleAuthority)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/node-lifecycle-plans", s.planTargetNodeLifecycle)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/provider-binding", s.bindTargetNodeProvider)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/node-lifecycle-actions", s.executeTargetNodeLifecycleAction)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/maintenance-windows", s.createClusterMaintenanceWindow)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/maintenance-windows", s.listClusterMaintenanceWindows)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/maintenance-windows/{windowId}/cancel", s.cancelClusterMaintenanceWindow)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/maintenance-runs", s.createClusterMaintenanceRun)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/maintenance-runs", s.listClusterMaintenanceRuns)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/maintenance-runs/{runId}", s.getClusterMaintenanceRun)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/maintenance-runs/{runId}/approve", s.approveClusterMaintenanceRun)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/maintenance-tasks/next", s.nextClusterMaintenanceTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/maintenance-tasks/{runId}/result", s.reportClusterMaintenanceTask)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/revoke", s.revokeManagedCluster)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/agent-certificates", s.listAgentCertificates)
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/agent-certificates/{certId}/revoke", s.revokeAgentCertificate)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/timeline", s.clusterTimeline)
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/workloads", s.clusterWorkloadExplorer)
	s.mux.HandleFunc("POST /api/v1/workload-log-queries", s.createWorkloadLogQuery)
	s.mux.HandleFunc("GET /api/v1/workload-log-queries/{id}", s.getWorkloadLogQuery)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/workload-log-tasks/next", s.nextWorkloadLogTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/workload-log-tasks/{operationId}/result", s.reportWorkloadLogTask)
	s.mux.HandleFunc("GET /api/v1/search", s.searchProjectionQuery)
	s.mux.HandleFunc("GET /api/v1/search/projection/rebuild", s.searchProjectionRebuild)
	s.mux.HandleFunc("GET /api/v1/fleet/health", s.fleetHealth)
	s.mux.HandleFunc("GET /api/v1/support-bundles/profiles", s.supportBundleProfiles)
	s.mux.HandleFunc("POST /api/v1/support-bundles", s.createSupportBundle)
	s.mux.HandleFunc("POST /api/v1/support-bundle-jobs", s.createSupportBundleJob)
	s.mux.HandleFunc("GET /api/v1/support-bundle-jobs/{id}", s.getSupportBundleJob)
	s.mux.HandleFunc("GET /api/v1/support-bundle-jobs/{id}/download", s.downloadSupportBundleJob)
	s.mux.HandleFunc("GET /api/v1/baselines", s.listBaselines)
	s.mux.HandleFunc("POST /api/v1/baseline-deployments", s.createBaselineDeployment)
	s.mux.HandleFunc("GET /api/v1/baseline-deployments", s.listBaselineDeployments)
	s.mux.HandleFunc("GET /api/v1/baseline-deployments/{id}", s.getBaselineDeployment)
	s.mux.HandleFunc("GET /api/v1/baseline-deployments/{id}/evidence/{key}", s.getBaselineEvidenceArtifact)
	s.mux.HandleFunc("POST /api/v1/baseline-deployments/{id}/approve", s.approveBaselineDeployment)
	s.mux.HandleFunc("POST /api/v1/baseline-deployments/{id}/revalidate", s.revalidateBaselineDeployment)
	s.mux.HandleFunc("POST /api/v1/baseline-deployments/{id}/retry", s.retryBaselineDeployment)
	s.mux.HandleFunc("POST /api/v1/baseline-deployments/{id}/rollback", s.rollbackBaselineDeployment)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/baseline-tasks/next", s.nextBaselineTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/baseline-tasks/{deploymentId}/result", s.reportBaselineTask)
	s.mux.HandleFunc("POST /api/v1/runtime-certifications", s.createRuntimeCertification)
	s.mux.HandleFunc("GET /api/v1/runtime-certifications", s.listRuntimeCertifications)
	s.mux.HandleFunc("GET /api/v1/runtime-certifications/{id}", s.getRuntimeCertification)
	s.mux.HandleFunc("GET /api/v1/runtime-certifications/{id}/report", s.runtimeCertificationReport)
	s.mux.HandleFunc("POST /api/v1/runtime-certifications/{id}/revoke", s.revokeRuntimeCertification)
	s.mux.HandleFunc("POST /api/v1/runtime-verifications", s.createRuntimeVerification)
	s.mux.HandleFunc("GET /api/v1/runtime-verifications", s.listRuntimeVerifications)
	s.mux.HandleFunc("GET /api/v1/runtime-verifications/{id}", s.getRuntimeVerification)
	s.mux.HandleFunc("POST /api/v1/runtime-verifications/{id}/retry", s.retryRuntimeVerification)
	s.mux.HandleFunc("GET /api/v1/runtime-verifications/{id}/report", s.runtimeVerificationReport)
	s.mux.HandleFunc("POST /api/v1/runtime-closure-campaigns", s.createRuntimeClosureCampaign)
	s.mux.HandleFunc("GET /api/v1/runtime-closure-campaigns", s.listRuntimeClosureCampaigns)
	s.mux.HandleFunc("GET /api/v1/runtime-closure-campaigns/{id}", s.getRuntimeClosureCampaign)
	s.mux.HandleFunc("POST /api/v1/runtime-closure-campaigns/{id}/advance", s.advanceRuntimeClosureCampaign)
	s.mux.HandleFunc("POST /api/v1/runtime-closure-campaigns/{id}/retry", s.retryRuntimeClosureCampaign)
	s.mux.HandleFunc("GET /api/v1/runtime-closure-campaigns/{id}/report", s.runtimeClosureCampaignReport)
	s.mux.HandleFunc("POST /api/v1/runtime-closure-reports/verify", s.verifyRuntimeClosureReport)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/runtime-certification-tasks/next", s.nextRuntimeCertificationTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/runtime-certification-tasks/{runId}/result", s.reportRuntimeCertificationTask)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/runtime-verification-tasks/next", s.nextRuntimeVerificationTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/runtime-verification-tasks/{verificationId}/result", s.reportRuntimeVerificationTask)
	s.mux.HandleFunc("POST /api/v1/fleet-groups", s.createFleetGroup)
	s.mux.HandleFunc("GET /api/v1/fleet-groups", s.listFleetGroups)
	s.mux.HandleFunc("GET /api/v1/fleet-groups/{id}", s.getFleetGroup)
	s.mux.HandleFunc("POST /api/v1/drift-scans", s.createDriftScan)
	s.mux.HandleFunc("GET /api/v1/drift-scans", s.listDriftScans)
	s.mux.HandleFunc("GET /api/v1/drift-scans/{id}", s.getDriftScan)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/drift-tasks/next", s.nextDriftTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/drift-tasks/{scanId}/result", s.reportDriftTask)
	s.mux.HandleFunc("POST /api/v1/recovery-checkpoints", s.createRecoveryCheckpoint)
	s.mux.HandleFunc("GET /api/v1/recovery-checkpoints", s.listRecoveryCheckpoints)
	s.mux.HandleFunc("GET /api/v1/recovery-checkpoints/{id}", s.getRecoveryCheckpoint)
	s.mux.HandleFunc("POST /api/v1/recovery-checkpoints/{id}/revoke", s.revokeRecoveryCheckpoint)
	s.mux.HandleFunc("POST /api/v1/backup-policies", s.createBackupPolicy)
	s.mux.HandleFunc("PUT /api/v1/backup-policies/{id}", s.updateBackupPolicy)
	s.mux.HandleFunc("GET /api/v1/backup-policies", s.listBackupPolicies)
	s.mux.HandleFunc("GET /api/v1/backup-policies/{id}", s.getBackupPolicy)
	s.mux.HandleFunc("POST /api/v1/backup-policies/{id}/enable", s.enableBackupPolicy)
	s.mux.HandleFunc("POST /api/v1/backup-policies/{id}/disable", s.disableBackupPolicy)
	s.mux.HandleFunc("POST /api/v1/backup-runs", s.createBackupRun)
	s.mux.HandleFunc("POST /api/v1/restore-runs", s.createRestoreRun)
	s.mux.HandleFunc("POST /api/v1/restore-drills", s.createRestoreDrill)
	s.mux.HandleFunc("GET /api/v1/data-protection-runs", s.listDataProtectionRuns)
	s.mux.HandleFunc("GET /api/v1/data-protection-runs/{id}", s.getDataProtectionRun)
	s.mux.HandleFunc("POST /api/v1/restore-runs/{id}/approve", s.approveRestoreRun)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/compliance-scan-tasks/next", s.nextComplianceScanTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/compliance-scan-tasks/{runId}/result", s.reportComplianceScanTask)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/data-protection-tasks/next", s.nextDataProtectionTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/data-protection-tasks/{runId}/result", s.reportDataProtectionTask)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns", s.createUpgradeCampaign)
	s.mux.HandleFunc("GET /api/v1/upgrade-campaigns", s.listUpgradeCampaigns)
	s.mux.HandleFunc("GET /api/v1/upgrade-campaigns/{id}", s.getUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/approve", s.approveUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/revalidate", s.revalidateUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/pause", s.pauseUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/resume", s.resumeUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/cancel", s.cancelUpgradeCampaign)
	s.mux.HandleFunc("POST /api/v1/upgrade-campaigns/{id}/advance", s.advanceUpgradeCampaign)

	s.mux.HandleFunc("PUT /api/v1/organizations/{id}/entitlement", s.upsertEntitlement)
	s.mux.HandleFunc("GET /api/v1/organizations/{id}/entitlement", s.getEntitlement)
	s.mux.HandleFunc("PUT /api/v1/organizations/{id}/oem-profile", s.upsertOEMProfile)
	s.mux.HandleFunc("GET /api/v1/organizations/{id}/oem-profile", s.getOEMProfile)
	s.mux.HandleFunc("POST /api/v1/tenants", s.createTenant)
	s.mux.HandleFunc("GET /api/v1/tenants", s.listTenants)
	s.mux.HandleFunc("GET /api/v1/tenants/{id}", s.getTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/suspend", s.suspendTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/resume", s.resumeTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/resize", s.resizeTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/approve", s.approveTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/delete", s.deleteTenant)
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/retry", s.retryTenant)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/tenant-tasks/next", s.nextTenantTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/tenant-tasks/{tenantId}/result", s.reportTenantTask)
	s.mux.HandleFunc("POST /api/v1/provider-profiles", s.createProviderProfile)
	s.mux.HandleFunc("GET /api/v1/provider-profiles", s.listProviderProfiles)
	s.mux.HandleFunc("GET /api/v1/provider-profiles/{id}", s.getProviderProfile)
	s.mux.HandleFunc("POST /api/v1/provider-profiles/{id}/retry", s.retryProviderProfile)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/provider-profile-tasks/next", s.nextProviderProfileTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/provider-profile-tasks/{profileId}/result", s.reportProviderProfileTask)
	s.mux.HandleFunc("POST /api/v1/provider-clusters", s.createProviderCluster)
	s.mux.HandleFunc("GET /api/v1/provider-clusters", s.listProviderClusters)
	s.mux.HandleFunc("GET /api/v1/provider-clusters/{id}", s.getProviderCluster)
	s.mux.HandleFunc("POST /api/v1/provider-clusters/{id}/approve", s.approveProviderCluster)
	s.mux.HandleFunc("POST /api/v1/provider-clusters/{id}/scale", s.scaleProviderCluster)
	s.mux.HandleFunc("POST /api/v1/provider-clusters/{id}/upgrade", s.upgradeProviderCluster)
	s.mux.HandleFunc("POST /api/v1/provider-clusters/{id}/delete", s.deleteProviderCluster)
	s.mux.HandleFunc("POST /api/v1/provider-clusters/{id}/retry", s.retryProviderCluster)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/provider-cluster-tasks/next", s.nextProviderClusterTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/provider-cluster-tasks/{providerClusterId}/result", s.reportProviderClusterTask)
	s.mux.HandleFunc("GET /agent/v1/clusters/{id}/virtual-cluster-tasks/next", s.nextVirtualClusterTask)
	s.mux.HandleFunc("POST /agent/v1/clusters/{id}/virtual-cluster-tasks/{virtualClusterId}/result", s.reportVirtualClusterTask)
	s.mux.HandleFunc("GET /api/v1/marketplace/offers", s.listMarketplaceOffers)
	s.mux.HandleFunc("POST /api/v1/marketplace/installations", s.createMarketplaceInstallation)
	s.mux.HandleFunc("GET /api/v1/marketplace/installations", s.listMarketplaceInstallations)
	s.mux.HandleFunc("GET /api/v1/marketplace/installations/{id}", s.getMarketplaceInstallation)
	s.mux.HandleFunc("POST /api/v1/marketplace/installations/{id}/approve", s.approveMarketplaceInstallation)
	s.mux.HandleFunc("POST /api/v1/marketplace/installations/{id}/uninstall", s.uninstallMarketplaceInstallation)
	s.mux.HandleFunc("POST /api/v1/marketplace/installations/{id}/retry", s.retryMarketplaceInstallation)
	s.mux.HandleFunc("POST /api/v1/marketplace/recommendations", s.createMarketplaceRecommendation)
	s.mux.HandleFunc("GET /api/v1/marketplace/recommendations", s.listMarketplaceRecommendations)
	s.mux.HandleFunc("GET /api/v1/marketplace/recommendations/{id}", s.getMarketplaceRecommendation)
}

func (s *Server) installationProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, installation.Profiles())
}

func (s *Server) installationIntegrations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, installation.Integrations())
}

func (s *Server) installationRecoveryAuthority(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, installation.RecoveryConsoleModel())
}

func (s *Server) createInstallationPlan(w http.ResponseWriter, r *http.Request) {
	var request installation.InstallRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result, err := installation.CreatePlan(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INSTALLATION_PLAN_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) systemServices(w http.ResponseWriter, r *http.Request) {
	if s.services == nil {
		writeJSON(w, http.StatusOK, []integrations.ServiceStatus{
			{Name: "git", Provider: "forgejo", Configured: false},
			{Name: "registry", Provider: "zot", Configured: false},
			{Name: "identity", Provider: "keycloak", Configured: false},
			{Name: "gitops", Provider: "argocd", Configured: false},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.services.Status(r.Context()))
}

func (s *Server) ensureGitRepository(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	if s.services == nil || !s.services.RepositoryBootstrapEnabled() {
		writeError(w, http.StatusForbidden, "INTERNAL_GIT_BOOTSTRAP_DISABLED", "internal Git repository bootstrap is disabled")
		return
	}
	var input integrations.RepositoryRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result, err := s.services.EnsureRepository(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadGateway, "INTERNAL_GIT_OPERATION_FAILED", err.Error())
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, result)
}

func (s *Server) publishGitRevision(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	if s.services == nil || !s.services.RepositoryBootstrapEnabled() {
		writeError(w, http.StatusForbidden, "INTERNAL_GIT_BOOTSTRAP_DISABLED", "internal Git revision publishing is disabled")
		return
	}
	var input integrations.RevisionRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	mode := strings.ToUpper(strings.TrimSpace(input.DeliveryMode))
	if mode == "" {
		mode = string(controlplane.GitDeliveryDirectCommit)
	}
	if mode == string(controlplane.GitDeliveryPullRequest) {
		fingerprint, err := integrations.ValidatePullRequestRevisionIntent(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_SIGNED_GIT_REVISION", err.Error())
			return
		}
		repo, err := s.services.EnsureRepository(r.Context(), integrations.RepositoryRequest{Organization: input.Organization, Name: input.Repository, Description: "Managed platform desired state", Private: true})
		if err != nil {
			writeError(w, http.StatusBadGateway, "INTERNAL_GIT_REPOSITORY_FAILED", err.Error())
			return
		}
		baseCommit, err := s.services.BranchCommit(r.Context(), input.Organization, input.Repository, "main")
		if err != nil {
			writeError(w, http.StatusBadGateway, "INTERNAL_GIT_BASE_SNAPSHOT_FAILED", err.Error())
			return
		}
		// Pull-request delivery must start from the same exact managed authority
		// as direct delivery. Otherwise unmanaged content already present on main
		// is inherited by the candidate branch and can be promoted without ever
		// appearing in the base-to-head changed-file allowlist.
		expectedBase := baseCommit
		latest, latestErr := s.store.GetLatestManagedGitRevision(r.Context(), input.Organization, input.Repository, "main")
		if latestErr == nil {
			if baseCommit != latest.CommitSHA {
				writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "managed Git branch changed since the latest recorded authority; run drift reconciliation before pull-request delivery")
				return
			}
			base, inspectErr := s.services.InspectGitRevision(r.Context(), input.Organization, input.Repository, "main", "", latest.PublicKeyFingerprint)
			if inspectErr != nil || !base.Trusted || base.CommitSHA != latest.CommitSHA || base.RevisionID != latest.RevisionID || base.Digest != latest.Digest {
				writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "live Git branch no longer matches the latest managed authority")
				return
			}
			if treeErr := s.services.ValidateManagedRepositoryTree(r.Context(), input.Organization, input.Repository, latest.CommitSHA); treeErr != nil {
				writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", treeErr.Error())
				return
			}
			expectedBase = latest.CommitSHA
		} else if !errors.Is(latestErr, controlplane.ErrNotFound) {
			writeStoreError(w, latestErr)
			return
		} else if !repo.Created {
			bootstrapBase, baseErr := s.services.BootstrapRepositoryBaseCommit(r.Context(), input.Organization, input.Repository)
			if baseErr != nil || bootstrapBase != baseCommit {
				writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_REQUIRED", "pull-request delivery without prior managed revision requires the exact product-managed bootstrap repository seed")
				return
			}
			expectedBase = bootstrapBase
		}
		head := integrations.PullRequestHeadBranch(input.RevisionID)
		pr, err := s.store.CreateGitPullRequest(r.Context(), controlplane.GitPullRequest{Organization: input.Organization, Repository: input.Repository, BaseBranch: "main", BaseCommitSHA: expectedBase, HeadBranch: head, RevisionID: input.RevisionID, Digest: input.Digest, PublicKeyFingerprint: fingerprint, State: controlplane.GitPullRequestRequested}, actor)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if pr.State == controlplane.GitPullRequestRequested {
			result, e := s.services.CreatePullRequestRevision(r.Context(), input, pr.BaseCommitSHA)
			if e != nil {
				writeError(w, http.StatusBadGateway, "INTERNAL_GIT_PULL_REQUEST_FAILED", e.Error())
				return
			}
			pr, err = s.store.FinalizeGitPullRequest(r.Context(), pr.ID, pr.Revision, result.ExternalNumber, result.ExternalURL, result.CommitSHA, actor)
			if err != nil {
				writeStoreError(w, err)
				return
			}
		}
		if pr.State == controlplane.GitPullRequestOpen || pr.State == controlplane.GitPullRequestApproved {
			if _, err = s.services.ValidatePullRequestCandidate(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber, pr.BaseBranch, pr.HeadBranch, pr.BaseCommitSHA, pr.CandidateCommitSHA, pr.RevisionID, pr.Digest, pr.PublicKeyFingerprint, false); err != nil {
				writeError(w, http.StatusConflict, "GIT_PULL_REQUEST_AUTHORITY_CHANGED", err.Error())
				return
			}
		}
		setRevisionETag(w, pr.Revision)
		writeJSON(w, http.StatusAccepted, map[string]any{"deliveryMode": mode, "pullRequest": pr, "candidateCommitSha": pr.CandidateCommitSHA})
		return
	}
	if mode != string(controlplane.GitDeliveryDirectCommit) {
		writeError(w, 400, "INVALID_DELIVERY_MODE", "deliveryMode must be DIRECT_COMMIT or PULL_REQUEST")
		return
	}
	fingerprint, err := integrations.ValidatePullRequestRevisionIntent(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SIGNED_GIT_REVISION", err.Error())
		return
	}
	repo, err := s.services.EnsureRepository(r.Context(), integrations.RepositoryRequest{Organization: input.Organization, Name: input.Repository, Description: "Managed platform desired state", Private: true})
	if err != nil {
		writeError(w, http.StatusBadGateway, "INTERNAL_GIT_REPOSITORY_FAILED", err.Error())
		return
	}
	currentCommit, err := s.services.BranchCommit(r.Context(), input.Organization, input.Repository, "main")
	if err != nil {
		writeError(w, http.StatusBadGateway, "INTERNAL_GIT_BASE_SNAPSHOT_FAILED", err.Error())
		return
	}
	// Crash/response-loss reconciliation: if main already is the exact signed
	// revision requested, do not create a second commit. Local authority recording
	// below is idempotent by immutable commit identity.
	if current, inspectErr := s.services.InspectGitRevision(r.Context(), input.Organization, input.Repository, "main", "", fingerprint); inspectErr == nil && current.Trusted && current.CommitSHA == currentCommit && current.RevisionID == strings.TrimSpace(input.RevisionID) && current.Digest == strings.TrimSpace(input.Digest) && current.PublicKeyFingerprint == fingerprint {
		if treeErr := s.services.ValidateManagedRepositoryTree(r.Context(), input.Organization, input.Repository, current.CommitSHA); treeErr != nil {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", treeErr.Error())
			return
		}
		result := integrations.RevisionResult{Organization: input.Organization, Repository: input.Repository, RevisionID: current.RevisionID, Digest: current.Digest, CommitSHA: current.CommitSHA, ChangedFiles: 0, PublicKeyFingerprint: current.PublicKeyFingerprint}
		recorded, recordErr := s.store.RecordManagedGitRevision(r.Context(), controlplane.ManagedGitRevision{Organization: result.Organization, Repository: result.Repository, Branch: "main", RevisionID: result.RevisionID, Digest: result.Digest, CommitSHA: result.CommitSHA, PublicKeyFingerprint: result.PublicKeyFingerprint, Source: "PLATFORM_PUBLISHED", DeliveryMode: controlplane.GitDeliveryDirectCommit}, actor)
		if recordErr != nil {
			writeStoreError(w, recordErr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deliveryMode": mode, "organization": result.Organization, "repository": result.Repository, "revisionId": result.RevisionID, "digest": result.Digest, "commitSha": result.CommitSHA, "changedFiles": 0, "publicKeyFingerprint": result.PublicKeyFingerprint, "authorityId": recorded.ID, "authorityRevision": recorded.Revision, "reconciledWithoutMutation": true})
		return
	}
	expectedBase := currentCommit
	latest, latestErr := s.store.GetLatestManagedGitRevision(r.Context(), input.Organization, input.Repository, "main")
	if latestErr == nil {
		if currentCommit != latest.CommitSHA {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "managed Git branch changed since the latest recorded authority; run drift reconciliation before direct delivery")
			return
		}
		base, inspectErr := s.services.InspectGitRevision(r.Context(), input.Organization, input.Repository, "main", "", latest.PublicKeyFingerprint)
		if inspectErr != nil || !base.Trusted || base.CommitSHA != latest.CommitSHA || base.RevisionID != latest.RevisionID || base.Digest != latest.Digest {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "live Git branch no longer matches the latest managed authority")
			return
		}
		if treeErr := s.services.ValidateManagedRepositoryTree(r.Context(), input.Organization, input.Repository, latest.CommitSHA); treeErr != nil {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", treeErr.Error())
			return
		}
		expectedBase = latest.CommitSHA
	} else if !errors.Is(latestErr, controlplane.ErrNotFound) {
		writeStoreError(w, latestErr)
		return
	} else if !repo.Created {
		bootstrapBase, baseErr := s.services.BootstrapRepositoryBaseCommit(r.Context(), input.Organization, input.Repository)
		if baseErr != nil || bootstrapBase != currentCommit {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_REQUIRED", "direct delivery without prior managed revision requires the exact product-managed bootstrap repository seed")
			return
		}
		expectedBase = bootstrapBase
	}
	result, err := s.services.PublishRevisionFromBase(r.Context(), input, expectedBase)
	if err != nil {
		writeError(w, http.StatusConflict, "INTERNAL_GIT_REVISION_FAILED", err.Error())
		return
	}
	recorded, err := s.store.RecordManagedGitRevision(r.Context(), controlplane.ManagedGitRevision{Organization: result.Organization, Repository: result.Repository, Branch: "main", RevisionID: result.RevisionID, Digest: result.Digest, CommitSHA: result.CommitSHA, PublicKeyFingerprint: result.PublicKeyFingerprint, Source: "PLATFORM_PUBLISHED", DeliveryMode: controlplane.GitDeliveryDirectCommit}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveryMode": mode, "organization": result.Organization, "repository": result.Repository, "revisionId": result.RevisionID, "digest": result.Digest, "commitSha": result.CommitSHA, "changedFiles": result.ChangedFiles, "publicKeyFingerprint": result.PublicKeyFingerprint, "authorityId": recorded.ID, "authorityRevision": recorded.Revision})
}

func (s *Server) listManagedGitRevisions(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	items, err := s.store.ListManagedGitRevisions(r.Context(), r.URL.Query().Get("organization"), r.URL.Query().Get("repository"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adoptGitDrift(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	scan, err := s.store.GetDriftScan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, scan.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	if s.services == nil {
		writeError(w, http.StatusServiceUnavailable, "GIT_AUTHORITY_UNAVAILABLE", "managed Forgejo integration is not configured")
		return
	}
	var in struct {
		ClusterID string `json:"clusterId"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	for _, target := range scan.Targets {
		if target.ClusterID != strings.TrimSpace(in.ClusterID) || target.Git == nil {
			continue
		}
		g := target.Git
		if !g.CurrentTrusted || g.Classification != controlplane.GitDriftExternalApplied || g.ObservedDigest != g.CurrentDigest {
			writeError(w, 422, "GIT_ADOPTION_NOT_SAFE", "only a trusted externally changed revision already observed live can be adopted without overwrite")
			return
		}
		// Re-read branch head to close the scan-to-adopt race; no Git content is overwritten.
		current, e := s.services.InspectGitRevision(r.Context(), g.Organization, g.Repository, g.Branch, g.BaseCommitSHA, g.PublicKeyFingerprint)
		if e != nil {
			writeError(w, 502, "GIT_SNAPSHOT_FAILED", e.Error())
			return
		}
		if current.CommitSHA != g.CurrentCommitSHA || current.Digest != g.CurrentDigest || !current.Trusted {
			writeError(w, 409, "GIT_HEAD_CHANGED", "Git head changed after the drift scan; run a new scan")
			return
		}
		v, e := s.store.RecordManagedGitRevision(r.Context(), controlplane.ManagedGitRevision{Organization: g.Organization, Repository: g.Repository, Branch: g.Branch, RevisionID: g.CurrentRevisionID, Digest: g.CurrentDigest, CommitSHA: g.CurrentCommitSHA, PublicKeyFingerprint: g.PublicKeyFingerprint, Source: "TRUSTED_EXTERNAL_ADOPTED"}, actor)
		if e != nil {
			writeStoreError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"authority": v, "overwroteGit": false, "next": "run a new drift scan"})
		return
	}
	writeError(w, 404, "GIT_DRIFT_TARGET_NOT_FOUND", "Git drift target not found")
}

func (s *Server) catalogSummary(w http.ResponseWriter, _ *http.Request) {
	certification := map[string]int{}
	risk := map[string]int{}
	resolved := 0
	componentAuthority := make(map[string]catalog.Component, len(s.components))
	for _, c := range s.components {
		certification[c.Spec.Certification.Status]++
		risk[c.Spec.Risk]++
		componentAuthority[c.Metadata.Name] = c
		if c.Spec.Source.Resolved {
			resolved++
		}
	}
	admission, err := catalog.LoadUpstreamAdmission()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_UPSTREAM_ADMISSION_UNAVAILABLE", "upstream acquisition admission authority is unavailable")
		return
	}
	if err = catalog.ValidateUpstreamAdmission(admission, componentAuthority); err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_UPSTREAM_ADMISSION_INVALID", "upstream acquisition admission authority failed validation")
		return
	}
	ready := 0
	runtimeBlocked := 0
	for _, row := range admission.Spec.Components {
		if row.Status == "ready-for-acquisition" {
			ready++
		}
		if row.RuntimeStatus != "eligible-after-source-resolution" {
			runtimeBlocked++
		}
	}
	renderable := len(catalog.ResolvedRenderable(s.components))
	runtimeTransition, transitionErr := catalog.LoadRuntimeDependencyTransition()
	if transitionErr != nil || catalog.ValidateRuntimeDependencyTransition(runtimeTransition, componentAuthority, admission) != nil {
		writeError(w, http.StatusInternalServerError, "RUNTIME_DEPENDENCY_TRANSITION_AUTHORITY_INVALID", "runtime dependency transition authority failed validation")
		return
	}
	runtimeRegistry, runtimeRegistryErr := catalog.LoadComponentRuntimeCertificationRegistry()
	if runtimeRegistryErr != nil || catalog.ValidateComponentRuntimeCertificationRegistry(runtimeRegistry, s.components) != nil {
		writeError(w, http.StatusInternalServerError, "COMPONENT_RUNTIME_CERTIFICATION_AUTHORITY_INVALID", "component runtime certification authority failed validation")
		return
	}
	runtimeStats := catalog.ComponentRuntimeCertificationStatistics(runtimeRegistry)
	writeJSON(w, http.StatusOK, map[string]any{
		"componentCount":                len(s.components),
		"resolvedComponentCount":        resolved,
		"renderableComponentCount":      renderable,
		"unresolvedComponentCount":      len(s.components) - resolved,
		"digest":                        catalog.Digest(s.components),
		"certification":                 certification,
		"risk":                          risk,
		"runtimeCertificationAuthority": map[string]any{"authority": runtimeRegistry.Metadata.Name, "stats": runtimeStats},
		"runtimeDependencyTransition": map[string]any{
			"authority":             runtimeTransition.Spec.Authority,
			"status":                runtimeTransition.Spec.Status,
			"gatewayTargetRelease":  runtimeTransition.Spec.GatewayAPI.TargetRelease,
			"kgatewayTargetRelease": runtimeTransition.Spec.KGateway.TargetRelease,
			"ciliumTargetRelease":   runtimeTransition.Spec.Cilium.TargetRelease,
		},
		"upstreamAdmission": map[string]any{
			"authority":           admission.Metadata.Name,
			"total":               len(admission.Spec.Components),
			"readyForAcquisition": ready,
			"reviewRequired":      len(admission.Spec.Components) - ready,
			"runtimeBlocked":      runtimeBlocked,
			"components":          admission.Spec.Components,
		},
	})
}
func (s *Server) tenantPlans(w http.ResponseWriter, _ *http.Request) {
	plans, err := catalog.LoadTenantPlans()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TENANT_PLAN_LOAD_FAILED", "tenant plan catalog is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, plans)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return ensureEOF(dec)
}
func decodeBlueprint(w http.ResponseWriter, r *http.Request) (domain.Blueprint, error) {
	var b domain.Blueprint
	err := decodeJSON(w, r, &b)
	return b, err
}
func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
func actorID(r *http.Request) (string, error) {
	v := ""
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		v = strings.TrimSpace(principal.Subject)
	} else {
		v = strings.TrimSpace(r.Header.Get("X-Actor-ID"))
	}
	if v == "" {
		return "", errors.New("authenticated actor is required")
	}
	if len(v) > 200 {
		return "", errors.New("actor ID is too long")
	}
	return v, nil
}
func parseExpectedRevision(r *http.Request) (int64, error) {
	raw := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), "\"")
	if raw == "" {
		return 0, errors.New("If-Match revision is required")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("If-Match must contain a positive resource revision")
	}
	return v, nil
}
func setRevisionETag(w http.ResponseWriter, revision int64) {
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", revision))
}
func parseAuthorityWritePrecondition(r *http.Request) (int64, error) {
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == "*" {
		if strings.TrimSpace(r.Header.Get("If-Match")) != "" {
			return 0, errors.New("If-Match and If-None-Match cannot be combined")
		}
		return 0, nil
	}
	return parseExpectedRevision(r)
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBlueprint(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result := bp.Validate(b, s.components)
	status := http.StatusOK
	if !result.Valid {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}
func (s *Server) createPlan(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBlueprint(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v := bp.Validate(b, s.components)
	if !v.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, v)
		return
	}
	p, err := plan.Build(b, s.components)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "PLAN_FAILED", "plan generation failed")
		s.logger.Error("plan generation failed", "error", err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

type requestedReadScope struct {
	organizations               map[string]bool
	projects                    map[string]bool
	resourceOrganizations       map[string]bool
	allOrganizationsAndProjects bool
	allResourceOrganizations    bool
	explicitOrganizationID      string
	explicitProjectID           string
}

// resolveRequestedReadScope turns the console's selected organization/project
// context into the same authorization-aware sets used by collection handlers.
// It is deliberately fail-closed: an explicit scope is never widened merely
// because the principal has broader platform access.
func (s *Server) resolveRequestedReadScope(w http.ResponseWriter, r *http.Request) (requestedReadScope, bool) {
	allowedOrganizations, allOrganizations, err := s.accessibleOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return requestedReadScope{}, false
	}
	allowedProjects, allProjects, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return requestedReadScope{}, false
	}
	resourceOrganizations, allResourceOrganizations, err := s.resourceOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return requestedReadScope{}, false
	}

	organizationID := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		project, accessErr := s.requireProjectAccess(r, projectID, organizationRead)
		if accessErr != nil {
			writeScopeError(w, accessErr)
			return requestedReadScope{}, false
		}
		if organizationID != "" && project.OrganizationID != organizationID {
			writeError(w, http.StatusBadRequest, "SCOPE_SELECTION_MISMATCH", "projectId does not belong to organizationId")
			return requestedReadScope{}, false
		}
		return requestedReadScope{
			organizations:               map[string]bool{project.OrganizationID: true},
			projects:                    map[string]bool{project.ID: true},
			resourceOrganizations:       map[string]bool{},
			allOrganizationsAndProjects: false,
			allResourceOrganizations:    false,
			explicitOrganizationID:      project.OrganizationID,
			explicitProjectID:           project.ID,
		}, true
	}
	if organizationID != "" {
		if err = s.requireOrganizationAccess(r, organizationID, organizationRead); err != nil {
			writeScopeError(w, err)
			return requestedReadScope{}, false
		}
		organizationProjects, listErr := s.store.ListProjects(r.Context(), organizationID)
		if listErr != nil {
			writeStoreError(w, listErr)
			return requestedReadScope{}, false
		}
		selectedProjects := make(map[string]bool, len(organizationProjects))
		for _, project := range organizationProjects {
			if allProjects || allowedProjects[project.ID] {
				selectedProjects[project.ID] = true
			}
		}
		return requestedReadScope{
			organizations:               map[string]bool{organizationID: true},
			projects:                    selectedProjects,
			resourceOrganizations:       map[string]bool{organizationID: true},
			allOrganizationsAndProjects: false,
			allResourceOrganizations:    false,
			explicitOrganizationID:      organizationID,
		}, true
	}
	return requestedReadScope{
		organizations:               allowedOrganizations,
		projects:                    allowedProjects,
		resourceOrganizations:       resourceOrganizations,
		allOrganizationsAndProjects: allOrganizations && allProjects,
		allResourceOrganizations:    allResourceOrganizations,
	}, true
}

func normalizedAttentionLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 9, nil
	}
	limit, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || limit <= 0 || limit > 50 {
		return 0, fmt.Errorf("limit must be an integer between 1 and 50")
	}
	return limit, nil
}

func (s *Server) controlPlaneAttention(w http.ResponseWriter, r *http.Request) {
	limit, err := normalizedAttentionLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LIMIT", err.Error())
		return
	}
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	projectIDs := boolSetIDs(scope.projects)
	if store, ok := s.store.(controlPlaneAttentionStore); ok {
		items, err := store.ControlPlaneAttention(r.Context(), projectIDs, scope.allOrganizationsAndProjects, limit)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "control-plane attention authority is unavailable")
			s.logger.Error("control-plane attention query failed", "error", err)
			return
		}
		w.Header().Set("X-Result-Limit", strconv.Itoa(limit))
		writeJSON(w, http.StatusOK, items)
		return
	}

	// Development-store fallback only. Runtime PostgreSQL implements the bounded
	// query above so Overview polling never materializes full resource families.
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed := scope.projects
	all := scope.allOrganizationsAndProjects
	visible := func(projectID string) bool { return all || allowed[projectID] }
	items := make([]controlplane.OperatorAttentionItem, 0)
	add := func(kind, id, projectID, name, state, message, page string, updatedAt time.Time) {
		if visible(projectID) {
			items = append(items, controlplane.OperatorAttentionItem{Kind: kind, ID: id, ProjectID: projectID, DisplayName: name, State: state, Message: message, Page: page, UpdatedAt: updatedAt})
		}
	}
	for _, v := range snap.BaselineDeployments {
		if v.State == controlplane.BaselineDeploymentFailed {
			add("baseline-deployment", v.ID, v.ProjectID, v.BaselineID+"@"+v.BaselineVersion, string(v.State), v.LastError, "baselines", v.UpdatedAt)
		}
	}
	for _, v := range snap.RuntimeVerifications {
		if v.State == controlplane.RuntimeVerificationFailed {
			add("runtime-verification", v.ID, v.ProjectID, v.ID, string(v.State), v.LastError, "verification", v.UpdatedAt)
		}
	}
	for _, v := range snap.RuntimeClosureCampaigns {
		if v.State == controlplane.RuntimeClosureFailed {
			add("runtime-closure", v.ID, v.ProjectID, v.ID, string(v.State), v.LastError, "verification", v.UpdatedAt)
		}
	}
	for _, v := range snap.Tenants {
		if v.State == controlplane.TenantFailed {
			add("tenant", v.ID, v.ProjectID, v.DisplayName, string(v.State), v.LastError, "tenants", v.UpdatedAt)
		}
	}
	for _, v := range snap.ProviderProfiles {
		if v.State == controlplane.ProviderProfileFailed {
			add("provider-profile", v.ID, v.ProjectID, v.DisplayName, string(v.State), v.LastError, "providers", v.UpdatedAt)
		}
	}
	for _, v := range snap.ProviderClusters {
		if v.State == controlplane.ProviderClusterFailed || v.State == controlplane.ProviderClusterRecoveryRequired {
			add("provider-cluster", v.ID, v.ProjectID, v.DisplayName, string(v.State), v.LastError, "providers", v.UpdatedAt)
		}
	}
	now := time.Now().UTC()
	for _, v := range snap.ManagedClusters {
		offline := v.ConnectionState != "REVOKED" && (v.LastSeenAt == nil || now.Sub(v.LastSeenAt.UTC()) > 3*time.Minute)
		if offline {
			add("managed-cluster", v.ID, v.ProjectID, v.DisplayName, "OFFLINE", "Cluster heartbeat or inventory is stale.", "clusters", v.UpdatedAt)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].UpdatedAt.After(items[j].UpdatedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	w.Header().Set("X-Result-Limit", strconv.Itoa(limit))
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) controlPlaneSummary(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	allowedOrganizations := scope.organizations
	allowedProjects := scope.projects
	resourceOrganizations := scope.resourceOrganizations
	all := scope.allOrganizationsAndProjects
	allResourceOrganizations := scope.allResourceOrganizations
	if counter, ok := s.store.(controlPlaneSummaryCounter); ok {
		organizationIDs := boolSetIDs(allowedOrganizations)
		projectIDs := boolSetIDs(allowedProjects)
		resourceOrganizationIDs := boolSetIDs(resourceOrganizations)
		counts, countErr := counter.ControlPlaneSummaryCounts(r.Context(), organizationIDs, projectIDs, resourceOrganizationIDs, all, allResourceOrganizations)
		if countErr != nil {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "control-plane store is unavailable")
			s.logger.Error("control-plane summary aggregate failed", "error", countErr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"organizations": counts.Organizations, "projects": counts.Projects, "blueprintRevisions": counts.BlueprintRevisions,
			"assignments": counts.Assignments, "operations": counts.Operations, "operationStates": counts.OperationStates,
			"notificationDeliveryStates": counts.NotificationDeliveryStates,
			"unpublishedOutbox":          counts.UnpublishedOutbox, "auditEvents": counts.AuditEvents, "evidence": counts.Evidence,
			"clusterImports": counts.ClusterImports, "managedClusters": counts.ManagedClusters, "connectedClusters": counts.ConnectedClusters,
			"baselineDeployments": counts.BaselineDeployments, "successfulBaselineDeployments": counts.SuccessfulBaselineDeployments,
			"runtimeVerifications": counts.RuntimeVerifications, "successfulRuntimeVerifications": counts.SuccessfulRuntimeVerifications,
			"runtimeClosureCampaigns": counts.RuntimeClosureCampaigns, "successfulRuntimeClosureCampaigns": counts.SuccessfulRuntimeClosureCampaigns,
			"failedProductWorkflows": counts.FailedProductWorkflows,
			"entitlements":           counts.Entitlements, "oemProfiles": counts.OEMProfiles, "tenants": counts.Tenants,
			"providerProfiles": counts.ProviderProfiles, "providerClusters": counts.ProviderClusters,
			"clusterMutationEnabled": true, "clusterMutationScope": "organization-membership-scoped", "authorityBackend": s.store.Backend(),
		})
		return
	}

	// Development stores retain the canonical snapshot implementation. Runtime
	// PostgreSQL must use the bounded aggregate path above so UI polling never
	// materializes append-only history or sealed evidence payload bytes.
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "control-plane store is unavailable")
		return
	}
	if all {
		allowedOrganizations = map[string]bool{}
		for _, v := range snap.Organizations {
			allowedOrganizations[v.ID] = true
		}
		allowedProjects = map[string]bool{}
		for _, v := range snap.Projects {
			allowedProjects[v.ID] = true
		}
	}
	if allResourceOrganizations {
		resourceOrganizations = map[string]bool{}
		for _, v := range snap.Organizations {
			resourceOrganizations[v.ID] = true
		}
	}
	index := buildScopeIndex(snap, resourceOrganizations, allowedProjects)
	states := map[controlplane.OperationState]int{}
	notificationStates := map[controlplane.NotificationDeliveryState]int{}
	organizations, projects, revisions, assignments, operations, evidence := 0, 0, 0, 0, 0, 0
	clusterImports, managedClusters, connectedClusters := 0, 0, 0
	baselineDeployments, successfulBaselines, runtimeVerifications, successfulVerifications, runtimeClosures, successfulClosures := 0, 0, 0, 0, 0, 0
	failedProductWorkflows := 0
	entitlements, oemProfiles, tenants, providerProfiles, providerClusters := 0, 0, 0, 0, 0
	now := time.Now().UTC()
	for _, v := range snap.Organizations {
		if allowedOrganizations[v.ID] {
			organizations++
		}
	}
	for _, v := range snap.Projects {
		if allowedProjects[v.ID] {
			projects++
		}
	}
	for _, v := range snap.Revisions {
		if allowedProjects[v.ProjectID] {
			revisions++
		}
	}
	for _, v := range snap.Assignments {
		if allowedProjects[v.ProjectID] {
			assignments++
		}
	}
	for _, v := range snap.Operations {
		if allowedProjects[v.ProjectID] {
			operations++
			states[v.State]++
		}
	}
	for _, v := range snap.Evidence {
		if index.operations[v.OperationID] {
			evidence++
		}
	}
	visibleNotificationEvents := map[string]bool{}
	for _, event := range snap.NotificationEvents {
		if (event.ProjectID != "" && allowedProjects[event.ProjectID]) || (event.ProjectID == "" && resourceOrganizations[event.OrganizationID]) {
			visibleNotificationEvents[event.ID] = true
		}
	}
	for _, delivery := range snap.NotificationDeliveries {
		if visibleNotificationEvents[delivery.EventID] {
			notificationStates[delivery.State]++
		}
	}
	for _, v := range snap.ClusterImports {
		if allowedProjects[v.ProjectID] {
			clusterImports++
		}
	}
	for _, v := range snap.ManagedClusters {
		if allowedProjects[v.ProjectID] {
			managedClusters++
			if v.ConnectionState != "REVOKED" && v.LastSeenAt != nil && now.Sub(v.LastSeenAt.UTC()) <= 3*time.Minute {
				connectedClusters++
			}
		}
	}
	for _, v := range snap.BaselineDeployments {
		if allowedProjects[v.ProjectID] {
			baselineDeployments++
			if v.State == controlplane.BaselineDeploymentSucceeded {
				successfulBaselines++
			}
			if v.State == controlplane.BaselineDeploymentFailed {
				failedProductWorkflows++
			}
		}
	}
	for _, v := range snap.RuntimeVerifications {
		if allowedProjects[v.ProjectID] {
			runtimeVerifications++
			if v.State == controlplane.RuntimeVerificationSucceeded {
				successfulVerifications++
			}
			if v.State == controlplane.RuntimeVerificationFailed {
				failedProductWorkflows++
			}
		}
	}
	for _, v := range snap.RuntimeClosureCampaigns {
		if allowedProjects[v.ProjectID] {
			runtimeClosures++
			if v.State == controlplane.RuntimeClosureSucceeded {
				successfulClosures++
			}
			if v.State == controlplane.RuntimeClosureFailed {
				failedProductWorkflows++
			}
		}
	}
	for _, v := range snap.Entitlements {
		if resourceOrganizations[v.OrganizationID] {
			entitlements++
		}
	}
	for _, v := range snap.OEMProfiles {
		if resourceOrganizations[v.OrganizationID] {
			oemProfiles++
		}
	}
	for _, v := range snap.Tenants {
		if allowedProjects[v.ProjectID] {
			tenants++
			if v.State == controlplane.TenantFailed {
				failedProductWorkflows++
			}
		}
	}
	for _, v := range snap.ProviderProfiles {
		if allowedProjects[v.ProjectID] {
			providerProfiles++
			if v.State == controlplane.ProviderProfileFailed {
				failedProductWorkflows++
			}
		}
	}
	for _, v := range snap.ProviderClusters {
		if allowedProjects[v.ProjectID] {
			providerClusters++
			if v.State == controlplane.ProviderClusterFailed {
				failedProductWorkflows++
			}
		}
	}
	unpublished := 0
	for _, event := range snap.Outbox {
		if event.PublishedAt == nil && index.resources[event.AggregateID] {
			unpublished++
		}
	}
	auditEvents := 0
	for _, event := range snap.Audit {
		if auditVisible(event, index) {
			auditEvents++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": organizations, "projects": projects, "blueprintRevisions": revisions, "assignments": assignments, "operations": operations, "operationStates": states, "notificationDeliveryStates": notificationStates, "unpublishedOutbox": unpublished, "auditEvents": auditEvents, "evidence": evidence, "clusterImports": clusterImports, "managedClusters": managedClusters, "connectedClusters": connectedClusters, "baselineDeployments": baselineDeployments, "successfulBaselineDeployments": successfulBaselines, "runtimeVerifications": runtimeVerifications, "successfulRuntimeVerifications": successfulVerifications, "runtimeClosureCampaigns": runtimeClosures, "successfulRuntimeClosureCampaigns": successfulClosures, "failedProductWorkflows": failedProductWorkflows, "entitlements": entitlements, "oemProfiles": oemProfiles, "tenants": tenants, "providerProfiles": providerProfiles, "providerClusters": providerClusters, "clusterMutationEnabled": true, "clusterMutationScope": "organization-membership-scoped", "authorityBackend": s.store.Backend()})
}
func (s *Server) accessContext(w http.ResponseWriter, r *http.Request) {
	principal, authenticated := requestPrincipal(r)
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "authenticated principal is required")
		return
	}
	effective, err := s.effectiveAccessContext(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if auth.HasAnyRole(principal, "platform-admin") {
		writeJSON(w, http.StatusOK, map[string]any{"subject": principal.Subject, "globalRole": "platform-admin", "authentication": principal.Authentication, "mappingDigest": principal.MappingDigest, "mappedOrganizationRoles": principal.OrganizationRoles, "mappedProjectRoles": principal.ProjectRoles, "effectiveOrganizationRoles": effective.OrganizationRoles, "effectiveProjectRoles": effective.ProjectRoles, "allOrganizations": true, "memberships": []controlplane.OrganizationMembership{}})
		return
	}
	if principal.Authentication == "api-token" {
		writeJSON(w, http.StatusOK, map[string]any{"subject": principal.Subject, "globalRole": auth.CanonicalRole(principal.Roles), "authentication": "api-token", "serviceAccountId": principal.ServiceAccountID, "credentialId": principal.CredentialID, "organizationId": principal.OrganizationID, "projectId": principal.ProjectID, "permissions": principal.Permissions, "effectiveOrganizationRoles": effective.OrganizationRoles, "effectiveProjectRoles": effective.ProjectRoles, "allOrganizations": false, "memberships": []controlplane.OrganizationMembership{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subject": principal.Subject, "globalRole": auth.CanonicalRole(principal.Roles), "authentication": principal.Authentication, "mappingDigest": principal.MappingDigest, "mappedOrganizationRoles": principal.OrganizationRoles, "mappedProjectRoles": principal.ProjectRoles, "effectiveOrganizationRoles": effective.OrganizationRoles, "effectiveProjectRoles": effective.ProjectRoles, "allOrganizations": false, "memberships": effective.Memberships})
}

type organizationInput struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	if _, authenticated := requestPrincipal(r); authenticated && !requestHasRole(r, "platform-admin") {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "creating an organization requires platform-admin")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in organizationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.CreateOrganization(r.Context(), controlplane.Organization{Name: in.Name, DisplayName: in.DisplayName}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListOrganizations(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !all {
		filtered := make([]controlplane.Organization, 0, len(v))
		for _, org := range v {
			if allowed[org.ID] {
				filtered = append(filtered, org)
			}
		}
		v = filtered
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.GetOrganization(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) updateOrganization(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in organizationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.UpdateOrganization(r.Context(), r.PathValue("id"), rev, in.DisplayName, in.Name, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

type projectInput struct {
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in projectInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err = s.requireOrganizationAccess(r, in.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.CreateProject(r.Context(), controlplane.Project{OrganizationID: in.OrganizationID, Name: in.Name, DisplayName: in.DisplayName}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	organizationID := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if organizationID != "" {
		if err := s.requireOrganizationAccess(r, organizationID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListProjects(r.Context(), organizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowedProjects, allProjects, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !allProjects {
		filtered := make([]controlplane.Project, 0, len(v))
		for _, project := range v {
			if allowedProjects[project.ID] {
				filtered = append(filtered, project)
			}
		}
		v = filtered
	}
	writeJSON(w, http.StatusOK, v)
}

type organizationMembershipInput struct {
	Role controlplane.OrganizationMembershipRole `json:"role"`
}

func (s *Server) listOrganizationMemberships(w http.ResponseWriter, r *http.Request) {
	organizationID := r.PathValue("id")
	if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.ListOrganizationMemberships(r.Context(), organizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) upsertOrganizationMembership(w http.ResponseWriter, r *http.Request) {
	organizationID := r.PathValue("id")
	if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in organizationMembershipInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	expected, err := parseAuthorityWritePrecondition(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "AUTHORITY_PRECONDITION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.UpsertOrganizationMembership(r.Context(), controlplane.OrganizationMembership{OrganizationID: organizationID, Subject: r.PathValue("subject"), Role: in.Role}, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) revokeOrganizationMembership(w http.ResponseWriter, r *http.Request) {
	organizationID := r.PathValue("id")
	if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-organization-membership" {
		writeError(w, http.StatusBadRequest, "REVOCATION_CONFIRMATION_REQUIRED", "X-Confirm-Revoke must be revoke-organization-membership")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeOrganizationMembership(r.Context(), organizationID, r.PathValue("subject"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createOperation(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return
	}
	var in controlplane.OperationRequest
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	op, replay, err := s.store.CreateOperation(r.Context(), in, key, actor, r.Header.Get("X-Request-ID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	if replay {
		w.Header().Set("Idempotent-Replay", "true")
		writeJSON(w, http.StatusOK, op)
		return
	}
	writeJSON(w, http.StatusCreated, op)
}
func (s *Server) listOperations(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	projectID := scope.explicitProjectID
	allowed := scope.projects
	all := scope.allOrganizationsAndProjects
	var err error
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed <= 0 || parsed > 500 {
			writeError(w, http.StatusBadRequest, "INVALID_LIMIT", "limit must be an integer between 1 and 500")
			return
		}
		limit = parsed
	}
	var v []controlplane.Operation
	if limit > 0 {
		switch {
		case projectID != "":
			if pager, ok := s.store.(operationPageStore); ok {
				v, err = pager.ListOperationsPage(r.Context(), projectID, limit)
			} else {
				v, err = s.store.ListOperations(r.Context(), projectID)
				if err == nil && len(v) > limit {
					v = v[len(v)-limit:]
				}
			}
		case all:
			if pager, ok := s.store.(operationPageStore); ok {
				v, err = pager.ListOperationsPage(r.Context(), "", limit)
			} else {
				v, err = s.store.ListOperations(r.Context(), "")
				if err == nil && len(v) > limit {
					v = v[len(v)-limit:]
				}
			}
		default:
			// Authorization must constrain the candidate set before LIMIT. Paging
			// the global operations table first can hide older authorized rows when
			// newer operations belong to another tenant/project.
			if pager, ok := s.store.(operationScopedPageStore); ok {
				v, err = pager.ListOperationsPageByProjects(r.Context(), boolSetIDs(allowed), limit)
			} else {
				v, err = s.store.ListOperations(r.Context(), "")
				if err == nil {
					v = filterProjectScoped(v, allowed, false, func(item controlplane.Operation) string { return item.ProjectID })
					if len(v) > limit {
						v = v[len(v)-limit:]
					}
				}
			}
		}
		w.Header().Set("X-Result-Limit", strconv.Itoa(limit))
	} else {
		v, err = s.store.ListOperations(r.Context(), projectID)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// Defense in depth: even scoped store implementations are filtered again at
	// the API boundary so a backend regression cannot widen the response scope.
	v = filterProjectScoped(v, allowed, all, func(item controlplane.Operation) string { return item.ProjectID })
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) getOperation(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	steps, err := s.store.ListOperationSteps(r.Context(), v.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	traces, err := s.store.ListOperationStepTraces(r.Context(), v.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	compensation, err := s.store.ListOperationCompensationSteps(r.Context(), v.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	evidence, err := s.store.ListEvidence(r.Context(), v.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operation": v, "traceMethod": controlplane.OperationStepTraceMethod, "steps": steps, "traces": traces, "compensation": compensation, "evidence": evidence})
}

func normalizedAuditLimit(raw string) int {
	limit, _ := strconv.Atoi(raw)
	if limit <= 0 || limit > 1000 {
		return 100
	}
	return limit
}

func limitAuditTail(events []controlplane.AuditEvent, limit int) []controlplane.AuditEvent {
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}
	out := make([]controlplane.AuditEvent, 0, limit)
	for i := len(events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, events[i])
	}
	return out
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := normalizedAuditLimit(r.URL.Query().Get("limit"))
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	if scope.allOrganizationsAndProjects && scope.allResourceOrganizations {
		v, err := s.store.ListAudit(r.Context(), limit)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	if pager, ok := s.store.(auditScopedPageStore); ok {
		values, err := pager.ListAuditPageByScopes(r.Context(), boolSetIDs(scope.resourceOrganizations), boolSetIDs(scope.projects), limit)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, values)
		return
	}
	snapshot, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	index := buildScopeIndex(snapshot, scope.resourceOrganizations, scope.projects)
	filtered := make([]controlplane.AuditEvent, 0, len(snapshot.Audit))
	for _, event := range snapshot.Audit {
		if auditVisible(event, index) {
			filtered = append(filtered, event)
		}
	}
	writeJSON(w, http.StatusOK, limitAuditTail(filtered, limit))
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlplane.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, controlplane.ErrConflict):
		writeError(w, http.StatusConflict, "REVISION_CONFLICT", err.Error())
	case errors.Is(err, controlplane.ErrDuplicateName):
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", err.Error())
	case errors.Is(err, controlplane.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", err.Error())
	case errors.Is(err, controlplane.ErrInvalidTransition):
		writeError(w, http.StatusConflict, "INVALID_TRANSITION", err.Error())
	case errors.Is(err, controlplane.ErrImmutable):
		writeError(w, http.StatusConflict, "RESOURCE_IMMUTABLE", err.Error())
	case errors.Is(err, controlplane.ErrLeaseHeld):
		writeError(w, http.StatusConflict, "LEASE_HELD", err.Error())
	case errors.Is(err, controlplane.ErrNotClaimable):
		writeError(w, http.StatusConflict, "OPERATION_NOT_CLAIMABLE", err.Error())
	case errors.Is(err, controlplane.ErrStaleFence):
		writeError(w, http.StatusConflict, "STALE_FENCE", err.Error())
	case errors.Is(err, controlplane.ErrPlanStale):
		writeError(w, http.StatusConflict, "PLAN_STALE", err.Error())
	case errors.Is(err, controlplane.ErrMaintenanceWindow):
		writeError(w, http.StatusConflict, "MAINTENANCE_WINDOW_CLOSED", err.Error())
	case errors.Is(err, controlplane.ErrPrerequisite):
		writeError(w, http.StatusUnprocessableEntity, "PREREQUISITE_NOT_SATISFIED", err.Error())
	case errors.Is(err, controlplane.ErrValidation):
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "CONTROL_PLANE_ERROR", "control-plane operation failed")
	}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}
func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = "req-" + strconv.FormatUint(s.requestSeq.Add(1), 10)
		}
		w.Header().Set("X-Request-ID", id)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.logger.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", status, "bytes", sw.bytes, "duration_ms", time.Since(started).Milliseconds())
	})
}
