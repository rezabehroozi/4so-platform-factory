package controlplane

import (
	"context"
	"time"
)

// Store is the durable authority boundary used by the API and operation workers.
// Implementations must preserve optimistic concurrency, idempotency, append-only
// audit, transactional outbox, and monotonic fencing semantics.
type Store interface {
	Health(context.Context) error
	Backend() string

	CreateOrganization(context.Context, Organization, string) (Organization, error)
	UpdateOrganization(context.Context, string, int64, string, string, string) (Organization, error)
	GetOrganization(context.Context, string) (Organization, error)
	ListOrganizations(context.Context) ([]Organization, error)

	CreateProject(context.Context, Project, string) (Project, error)
	GetProject(context.Context, string) (Project, error)
	ListProjects(context.Context, string) ([]Project, error)

	UpsertOrganizationMembership(context.Context, OrganizationMembership, int64, string) (OrganizationMembership, error)
	GetOrganizationMembership(context.Context, string, string) (OrganizationMembership, error)
	ListOrganizationMemberships(context.Context, string) ([]OrganizationMembership, error)
	ListSubjectOrganizationMemberships(context.Context, string) ([]OrganizationMembership, error)
	RevokeOrganizationMembership(context.Context, string, string, int64, string) (OrganizationMembership, error)

	CreateOIDCGroupMapping(context.Context, OIDCGroupMapping, string) (OIDCGroupMapping, error)
	ListOIDCGroupMappings(context.Context, OIDCGroupMappingState) ([]OIDCGroupMapping, error)
	RevokeOIDCGroupMapping(context.Context, string, int64, string) (OIDCGroupMapping, error)
	ResolveOIDCGroups(context.Context, []string) (OIDCGroupResolution, error)
	AppendSecurityAudit(context.Context, SecurityAuditInput) (SecurityAuditEvent, error)
	ListSecurityAudit(context.Context, int) ([]SecurityAuditEvent, error)

	CreateServiceAccount(context.Context, ServiceAccount, string) (ServiceAccount, error)
	GetServiceAccount(context.Context, string) (ServiceAccount, error)
	ListServiceAccounts(context.Context, string) ([]ServiceAccount, error)
	RevokeServiceAccount(context.Context, string, int64, string) (ServiceAccount, error)

	CreateAPIToken(context.Context, APIToken, string) (APIToken, error)
	GetAPIToken(context.Context, string) (APIToken, error)
	GetAPITokenByIdempotencyKey(context.Context, string, string) (APIToken, error)
	ListAPITokens(context.Context, string) ([]APIToken, error)
	RevokeAPIToken(context.Context, string, int64, string) (APIToken, error)
	RotateAPIToken(context.Context, string, int64, APIToken, string) (APIToken, APIToken, error)

	CreateBlueprintOverlay(context.Context, BlueprintOverlay, string) (BlueprintOverlay, error)
	GetBlueprintOverlay(context.Context, string) (BlueprintOverlay, error)
	ListBlueprintOverlays(context.Context, string, BlueprintOverlayScope) ([]BlueprintOverlay, error)

	CreateBlueprintRevision(context.Context, BlueprintRevision, string) (BlueprintRevision, error)
	GetBlueprintRevision(context.Context, string) (BlueprintRevision, error)
	CreateBlueprintReleaseWithRevision(context.Context, BlueprintRevision, BlueprintRelease, string) (BlueprintRevision, BlueprintRelease, error)
	UpdateBlueprintReleaseDraftWithRevision(context.Context, string, int64, BlueprintRevision, bool, string, []string, string) (BlueprintRevision, BlueprintRelease, error)

	CreateBlueprintRelease(context.Context, BlueprintRelease, string) (BlueprintRelease, error)
	GetBlueprintRelease(context.Context, string) (BlueprintRelease, error)
	ListBlueprintReleases(context.Context, string) ([]BlueprintRelease, error)
	UpdateBlueprintReleaseDraft(context.Context, string, int64, string, string, string, bool, string, []string, string) (BlueprintRelease, error)
	TransitionBlueprintRelease(context.Context, string, int64, BlueprintLifecycleState, string) (BlueprintRelease, error)

	CreateCatalogTrustKey(context.Context, CatalogTrustKey, string) (CatalogTrustKey, error)
	GetCatalogTrustKey(context.Context, string) (CatalogTrustKey, error)
	ListCatalogTrustKeys(context.Context, string) ([]CatalogTrustKey, error)
	RevokeCatalogTrustKey(context.Context, string, int64, string) (CatalogTrustKey, error)

	CreateCatalogRevision(context.Context, CatalogRevision, string) (CatalogRevision, error)
	GetCatalogRevision(context.Context, string) (CatalogRevision, error)
	CreateCatalogReleaseWithRevision(context.Context, CatalogRevision, CatalogRelease, string) (CatalogRevision, CatalogRelease, error)
	UpdateCatalogReleaseDraftWithRevision(context.Context, string, int64, CatalogRevision, string) (CatalogRevision, CatalogRelease, error)
	CreateCatalogRelease(context.Context, CatalogRelease, string) (CatalogRelease, error)
	GetCatalogRelease(context.Context, string) (CatalogRelease, error)
	ListCatalogReleases(context.Context, string) ([]CatalogRelease, error)
	UpdateCatalogReleaseDraft(context.Context, string, int64, string, string, string) (CatalogRelease, error)
	SubmitCatalogReleaseReview(context.Context, string, int64, string, string, string, string) (CatalogRelease, error)
	TransitionCatalogRelease(context.Context, string, int64, CatalogLifecycleState, string) (CatalogRelease, error)

	CreateAssignment(context.Context, Assignment, string) (Assignment, error)
	UpdateAssignment(context.Context, string, int64, string, int64, string) (Assignment, error)
	GetAssignment(context.Context, string) (Assignment, error)

	CreateOperation(context.Context, OperationRequest, string, string, string) (Operation, bool, error)
	GetOperation(context.Context, string) (Operation, error)
	ListOperations(context.Context, string) ([]Operation, error)
	TransitionOperation(context.Context, string, int64, OperationState, string, string) (Operation, error)
	ClaimOperation(context.Context, string, string, time.Duration, time.Time) (ClaimResult, error)
	RenewOperationLease(context.Context, string, string, int64, time.Duration, time.Time) (ClaimResult, error)
	ReleaseOperationLease(context.Context, string, string, int64) error
	StartOperationAttempt(context.Context, string, int64, string, int64, string) (Operation, error)
	BeginOperationVerification(context.Context, string, int64, string, int64, string) (Operation, error)
	ReportOperationFailure(context.Context, string, int64, string, int64, OperationFailureReport, string) (Operation, error)
	CompleteOperation(context.Context, string, int64, string, int64, string) (Operation, error)
	RequestOperationCancellation(context.Context, string, int64, string, string) (Operation, error)
	AcknowledgeOperationCancellation(context.Context, string, int64, string, int64, string) (Operation, error)
	SetOperationCompensationPlan(context.Context, string, int64, []CompensationPlanStep, string) (Operation, []OperationCompensationStep, error)
	ListOperationCompensationSteps(context.Context, string) ([]OperationCompensationStep, error)
	RecordOperationForwardStepCompleted(context.Context, string, string, int64, string, int64, string) (OperationCompensationStep, Operation, error)
	BeginOperationCompensation(context.Context, string, int64, string) (Operation, error)
	ClaimNextOperationCompensationStep(context.Context, string, string, int64, string) (OperationCompensationStep, Operation, error)
	CompleteOperationCompensationStep(context.Context, string, string, string, int64, string, string) (OperationCompensationStep, Operation, error)
	ReportOperationCompensationStepFailure(context.Context, string, string, string, int64, CompensationStepFailure, string) (OperationCompensationStep, Operation, error)

	AppendOperationStep(context.Context, OperationStep, string) (OperationStep, error)
	ListOperationSteps(context.Context, string) ([]OperationStep, error)
	AppendOperationStepTrace(context.Context, OperationStepTraceInput, string, int64, string) (OperationStepTrace, EvidenceMetadata, error)
	ListOperationStepTraces(context.Context, string) ([]OperationStepTrace, error)
	GetEvidencePayload(context.Context, string) (EvidenceMetadata, []byte, error)

	ClaimOutbox(context.Context, string, int, time.Duration, time.Time) ([]OutboxEvent, error)
	MarkOutboxPublished(context.Context, string, string, time.Time) error

	CreateNotificationDestination(context.Context, NotificationDestination, string) (NotificationDestination, error)
	UpdateNotificationDestination(context.Context, string, int64, NotificationDestination, string) (NotificationDestination, error)
	DisableNotificationDestination(context.Context, string, int64, string) (NotificationDestination, error)
	GetNotificationDestination(context.Context, string) (NotificationDestination, error)
	ListNotificationDestinations(context.Context, string) ([]NotificationDestination, error)
	CreateNotificationRoute(context.Context, NotificationRoute, string) (NotificationRoute, error)
	UpdateNotificationRoute(context.Context, string, int64, NotificationRoute, string) (NotificationRoute, error)
	GetNotificationRoute(context.Context, string) (NotificationRoute, error)
	ListNotificationRoutes(context.Context, string, string) ([]NotificationRoute, error)
	RouteNotificationEvent(context.Context, NotificationEvent, string) (NotificationEvent, []NotificationDelivery, bool, error)
	GetNotificationEvent(context.Context, string) (NotificationEvent, error)
	ListNotificationEvents(context.Context, string, string, int) ([]NotificationEvent, error)
	GetNotificationDelivery(context.Context, string) (NotificationDelivery, error)
	ListNotificationDeliveries(context.Context, string, string, NotificationDeliveryState, int) ([]NotificationDelivery, error)
	ClaimNotificationDeliveries(context.Context, string, int, time.Duration, time.Time) ([]NotificationDelivery, error)
	ReportNotificationDelivery(context.Context, string, string, time.Time, NotificationDeliveryResult) (NotificationDelivery, NotificationDeliveryAttempt, error)
	RetryNotificationDelivery(context.Context, string, int64, string) (NotificationDelivery, error)
	ListNotificationDeliveryAttempts(context.Context, string) ([]NotificationDeliveryAttempt, error)

	AppendEvidence(context.Context, EvidenceMetadata, string) (EvidenceMetadata, error)
	ListEvidence(context.Context, string) ([]EvidenceMetadata, error)
	ListAudit(context.Context, int) ([]AuditEvent, error)

	CreateClusterImport(context.Context, ClusterImport, string) (ClusterImport, error)
	ApproveClusterImport(context.Context, string, int64, string) (ClusterImport, error)
	RevokeClusterImport(context.Context, string, int64, string) (ClusterImport, error)
	GetClusterImport(context.Context, string) (ClusterImport, error)
	ListClusterImports(context.Context, string) ([]ClusterImport, error)
	ClaimClusterImport(context.Context, string, string, string, string, string) (ClusterImport, ManagedCluster, error)
	UpsertClusterInventory(context.Context, string, string, string, ClusterInventory) (ManagedCluster, ClusterInventory, error)
	AuthorizeClusterMutationRBACActivation(context.Context, string, string) (ManagedCluster, ClusterImport, error)
	HeartbeatCluster(context.Context, string, string, string, string) (ManagedCluster, error)
	RevokeManagedCluster(context.Context, string, int64, string) (ManagedCluster, ClusterImport, error)
	AcknowledgeManagedClusterTargetRBACRevocation(context.Context, string, int64, string, string) (ManagedCluster, error)
	CreateAgentCertificate(context.Context, AgentCertificate, string) (AgentCertificate, error)
	GetAgentCertificate(context.Context, string) (AgentCertificate, error)
	GetAgentCertificateBySerial(context.Context, string) (AgentCertificate, error)
	ListAgentCertificates(context.Context, string) ([]AgentCertificate, error)
	RotateAgentCertificate(context.Context, string, AgentCertificate, string) (AgentCertificate, AgentCertificate, error)
	RevokeAgentCertificate(context.Context, string, int64, string) (AgentCertificate, error)
	GetManagedCluster(context.Context, string) (ManagedCluster, error)
	ListManagedClusters(context.Context, string) ([]ManagedCluster, error)
	GetLatestClusterInventory(context.Context, string) (ClusterInventory, error)
	UpsertClusterMaintenanceProfile(context.Context, ClusterMaintenanceProfile, int64, string) (ClusterMaintenanceProfile, error)
	GetClusterMaintenanceProfile(context.Context, string) (ClusterMaintenanceProfile, error)
	CreateClusterMaintenanceWindow(context.Context, ClusterMaintenanceWindow, string) (ClusterMaintenanceWindow, error)
	GetClusterMaintenanceWindow(context.Context, string) (ClusterMaintenanceWindow, error)
	ListClusterMaintenanceWindows(context.Context, string) ([]ClusterMaintenanceWindow, error)
	CancelClusterMaintenanceWindow(context.Context, string, int64, string) (ClusterMaintenanceWindow, error)
	CreateClusterMaintenanceRun(context.Context, ClusterMaintenanceRun, string) (ClusterMaintenanceRun, bool, error)
	CreateClusterMaintenanceRunRequest(context.Context, ClusterMaintenanceRun, OperationRequest, string, string, string) (ClusterMaintenanceRun, Operation, bool, error)
	GetClusterMaintenanceRun(context.Context, string) (ClusterMaintenanceRun, error)
	ListClusterMaintenanceRuns(context.Context, string) ([]ClusterMaintenanceRun, error)
	ApproveClusterMaintenanceRun(context.Context, string, int64, string) (ClusterMaintenanceRun, error)
	NextClusterMaintenanceTask(context.Context, string, string) (ClusterMaintenanceRun, Operation, error)
	ReportClusterMaintenanceTask(context.Context, string, string, int64, ClusterMaintenanceTaskResult) (ClusterMaintenanceRun, Operation, error)

	CreateBaselineDeployment(context.Context, BaselineDeployment, string) (BaselineDeployment, bool, error)
	GetBaselineDeployment(context.Context, string) (BaselineDeployment, error)
	ListBaselineDeployments(context.Context, string, string) ([]BaselineDeployment, error)
	ApproveBaselineDeployment(context.Context, string, int64, string) (BaselineDeployment, error)
	RevalidateBaselineDeployment(context.Context, string, int64, string) (BaselineDeployment, error)
	RetryBaselineDeployment(context.Context, string, int64, string) (BaselineDeployment, error)
	QueueBaselineRollback(context.Context, string, int64, string, string, string) (BaselineDeployment, error)
	NextBaselineTask(context.Context, string, string) (BaselineDeployment, error)
	ReportBaselineTask(context.Context, string, string, int64, BaselineTaskResult) (BaselineDeployment, error)

	CreateRuntimeVerification(context.Context, RuntimeVerification, string) (RuntimeVerification, bool, error)
	GetRuntimeVerification(context.Context, string) (RuntimeVerification, error)
	ListRuntimeVerifications(context.Context, string, string, string) ([]RuntimeVerification, error)
	RetryRuntimeVerification(context.Context, string, int64, string) (RuntimeVerification, error)
	NextRuntimeVerificationTask(context.Context, string, string) (RuntimeVerification, error)
	ReportRuntimeVerificationTask(context.Context, string, string, int64, RuntimeVerificationResult) (RuntimeVerification, error)

	CreateRuntimeCertification(context.Context, RuntimeCertificationRun, string) (RuntimeCertificationRun, bool, error)
	GetRuntimeCertification(context.Context, string) (RuntimeCertificationRun, error)
	ListRuntimeCertifications(context.Context, string, string) ([]RuntimeCertificationRun, error)
	NextRuntimeCertificationTask(context.Context, string, string) (RuntimeCertificationRun, error)
	ReportRuntimeCertificationTask(context.Context, string, string, int64, RuntimeCertificationResult) (RuntimeCertificationRun, error)
	RevokeRuntimeCertification(context.Context, string, int64, string) (RuntimeCertificationRun, error)

	CreateRecoveryCheckpoint(context.Context, RecoveryCheckpoint, string) (RecoveryCheckpoint, error)
	GetRecoveryCheckpoint(context.Context, string) (RecoveryCheckpoint, error)
	ListRecoveryCheckpoints(context.Context, string, string) ([]RecoveryCheckpoint, error)
	RevokeRecoveryCheckpoint(context.Context, string, int64, string) (RecoveryCheckpoint, error)

	CreateFleetGroup(context.Context, FleetGroup, string) (FleetGroup, bool, error)
	GetFleetGroup(context.Context, string) (FleetGroup, error)
	ListFleetGroups(context.Context, string) ([]FleetGroup, error)

	CreateGitCredential(context.Context, GitCredential, string) (GitCredential, error)
	GetGitCredential(context.Context, string) (GitCredential, error)
	ListGitCredentials(context.Context) ([]GitCredential, error)
	RotateGitCredential(context.Context, string, int64, GitCredential, string) (GitCredential, GitCredential, error)
	RevokeGitCredential(context.Context, string, int64, string) (GitCredential, error)
	CreateGitProvider(context.Context, GitProvider, string) (GitProvider, error)
	GetGitProvider(context.Context, string) (GitProvider, error)
	ListGitProviders(context.Context) ([]GitProvider, error)
	GetDefaultGitProvider(context.Context) (GitProvider, GitCredential, error)
	UpdateGitProviderCredential(context.Context, string, int64, string, string) (GitProvider, error)

	CreateGitPullRequest(context.Context, GitPullRequest, string) (GitPullRequest, error)
	FinalizeGitPullRequest(context.Context, string, int64, int64, string, string, string) (GitPullRequest, error)
	GetGitPullRequest(context.Context, string) (GitPullRequest, error)
	ListGitPullRequests(context.Context, string, string) ([]GitPullRequest, error)
	ApproveGitPullRequest(context.Context, string, int64, string, string) (GitPullRequest, error)
	CommitMergedGitPullRequest(context.Context, string, int64, string, ManagedGitRevision, string) (GitPullRequest, ManagedGitRevision, error)
	RecordManagedGitRevision(context.Context, ManagedGitRevision, string) (ManagedGitRevision, error)
	GetLatestManagedGitRevision(context.Context, string, string, string) (ManagedGitRevision, error)
	GetManagedGitRevision(context.Context, string) (ManagedGitRevision, error)
	GetLastKnownGoodGitRevision(context.Context, string, string, string) (ManagedGitRevision, error)
	MarkManagedGitRevisionSynchronized(context.Context, string, int64, string, bool, string) (ManagedGitRevision, error)
	ListManagedGitRevisions(context.Context, string, string) ([]ManagedGitRevision, error)

	CreateDriftScan(context.Context, DriftScan, string) (DriftScan, bool, error)
	GetDriftScan(context.Context, string) (DriftScan, error)
	ListDriftScans(context.Context, string, string) ([]DriftScan, error)
	NextDriftTask(context.Context, string, string) (DriftScan, DriftScanTarget, error)
	ReportDriftTask(context.Context, string, string, int64, DriftTaskResult) (DriftScan, error)

	CreateUpgradeCampaign(context.Context, UpgradeCampaign, string) (UpgradeCampaign, bool, error)
	GetUpgradeCampaign(context.Context, string) (UpgradeCampaign, error)
	ListUpgradeCampaigns(context.Context, string, string) ([]UpgradeCampaign, error)
	ApproveUpgradeCampaign(context.Context, string, int64, string) (UpgradeCampaign, error)
	PauseUpgradeCampaign(context.Context, string, int64, string, string) (UpgradeCampaign, error)
	ResumeUpgradeCampaign(context.Context, string, int64, string) (UpgradeCampaign, error)
	CancelUpgradeCampaign(context.Context, string, int64, string, string) (UpgradeCampaign, error)
	RevalidateUpgradeCampaign(context.Context, string, int64, UpgradeCampaignRevalidation, string) (UpgradeCampaign, error)
	UpdateUpgradeCampaign(context.Context, UpgradeCampaign, int64, string) (UpgradeCampaign, error)

	UpsertEntitlement(context.Context, Entitlement, int64, string) (Entitlement, error)
	GetEntitlement(context.Context, string) (Entitlement, error)
	UpsertOEMProfile(context.Context, OEMProfile, int64, string) (OEMProfile, error)
	GetOEMProfile(context.Context, string) (OEMProfile, error)

	CreateTenant(context.Context, TenantEnvironment, string) (TenantEnvironment, bool, error)
	GetTenant(context.Context, string) (TenantEnvironment, error)
	ListTenants(context.Context, string, string) ([]TenantEnvironment, error)
	QueueTenantResize(context.Context, string, int64, string, map[string]string, string, string, string) (TenantEnvironment, error)
	QueueTenantAction(context.Context, string, int64, string, string, string, string) (TenantEnvironment, error)
	ApproveTenantAction(context.Context, string, int64, string) (TenantEnvironment, error)
	NextTenantTask(context.Context, string, string) (TenantEnvironment, error)
	ReportTenantTask(context.Context, string, string, int64, TenantTaskResult) (TenantEnvironment, error)

	CreateProviderProfile(context.Context, ProviderProfile, string) (ProviderProfile, bool, error)
	GetProviderProfile(context.Context, string) (ProviderProfile, error)
	ListProviderProfiles(context.Context, string, string) ([]ProviderProfile, error)
	RetryProviderProfile(context.Context, string, int64, string) (ProviderProfile, error)
	NextProviderProfileTask(context.Context, string, string) (ProviderProfile, error)
	ReportProviderProfileTask(context.Context, string, string, int64, ProviderProfileTaskResult) (ProviderProfile, error)

	CreateProviderCluster(context.Context, ProviderCluster, string) (ProviderCluster, bool, error)
	GetProviderCluster(context.Context, string) (ProviderCluster, error)
	ListProviderClusters(context.Context, string, string) ([]ProviderCluster, error)
	QueueProviderClusterChange(context.Context, string, int64, string, ProviderClusterSpec, string, string, string, string) (ProviderCluster, error)
	ApproveProviderCluster(context.Context, string, int64, string) (ProviderCluster, error)
	RetryProviderCluster(context.Context, string, int64, string) (ProviderCluster, error)
	NextProviderClusterTask(context.Context, string, string) (ProviderCluster, ProviderProfile, error)
	ReportProviderClusterTask(context.Context, string, string, int64, ProviderClusterTaskResult) (ProviderCluster, error)

	CreateAIRun(context.Context, AIRun, string) (AIRun, bool, error)
	GetAIRun(context.Context, string) (AIRun, error)
	GetAIRunByIdempotencyKey(context.Context, string, string) (AIRun, error)
	ListAIRuns(context.Context, string) ([]AIRun, error)

	CreateMarketplaceRecommendation(context.Context, MarketplaceRecommendation, string) (MarketplaceRecommendation, bool, error)
	GetMarketplaceRecommendation(context.Context, string) (MarketplaceRecommendation, error)
	GetMarketplaceRecommendationByIdempotencyKey(context.Context, string, string) (MarketplaceRecommendation, error)
	ListMarketplaceRecommendations(context.Context, string, string) ([]MarketplaceRecommendation, error)

	CreateRuntimeClosureCampaign(context.Context, RuntimeClosureCampaign, string) (RuntimeClosureCampaign, bool, error)
	GetRuntimeClosureCampaign(context.Context, string) (RuntimeClosureCampaign, error)
	ListRuntimeClosureCampaigns(context.Context, string, string) ([]RuntimeClosureCampaign, error)
	UpdateRuntimeClosureCampaign(context.Context, string, int64, RuntimeClosureCampaignUpdate, string) (RuntimeClosureCampaign, error)

	// Snapshot is intended for read-only diagnostics and development backup.
	// Production backup/restore is performed at PostgreSQL and object-store layers.
	Snapshot(context.Context) (Snapshot, error)
}

type ClusterImportCredentialSnapshot struct {
	ImportID         string `json:"importId"`
	TokenDigest      string `json:"tokenDigest,omitempty"`
	AgentTokenDigest string `json:"agentTokenDigest,omitempty"`
}

type Snapshot struct {
	Organizations              []Organization                    `json:"organizations"`
	OrganizationMemberships    []OrganizationMembership          `json:"organizationMemberships"`
	OIDCGroupMappings          []OIDCGroupMapping                `json:"oidcGroupMappings"`
	SecurityAudit              []SecurityAuditEvent              `json:"securityAudit"`
	ServiceAccounts            []ServiceAccount                  `json:"serviceAccounts"`
	APITokens                  []APIToken                        `json:"apiTokens"`
	Projects                   []Project                         `json:"projects"`
	BlueprintOverlays          []BlueprintOverlay                `json:"blueprintOverlays"`
	Revisions                  []BlueprintRevision               `json:"blueprintRevisions"`
	BlueprintReleases          []BlueprintRelease                `json:"blueprintReleases"`
	CatalogTrustKeys           []CatalogTrustKey                 `json:"catalogTrustKeys"`
	CatalogRevisions           []CatalogRevision                 `json:"catalogRevisions"`
	CatalogReleases            []CatalogRelease                  `json:"catalogReleases"`
	Assignments                []Assignment                      `json:"assignments"`
	Operations                 []Operation                       `json:"operations"`
	Steps                      []OperationStep                   `json:"operationSteps"`
	StepTraces                 []OperationStepTrace              `json:"operationStepTraces"`
	CompensationSteps          []OperationCompensationStep       `json:"operationCompensationSteps"`
	Outbox                     []OutboxEvent                     `json:"outbox"`
	NotificationDestinations   []NotificationDestination         `json:"notificationDestinations"`
	NotificationRoutes         []NotificationRoute               `json:"notificationRoutes"`
	NotificationEvents         []NotificationEvent               `json:"notificationEvents"`
	NotificationDeliveries     []NotificationDelivery            `json:"notificationDeliveries"`
	NotificationAttempts       []NotificationDeliveryAttempt     `json:"notificationDeliveryAttempts"`
	Audit                      []AuditEvent                      `json:"audit"`
	Evidence                   []EvidenceMetadata                `json:"evidence"`
	EvidencePayloads           []EvidencePayload                 `json:"evidencePayloads,omitempty"`
	ClusterImports             []ClusterImport                   `json:"clusterImports"`
	ClusterImportCredentials   []ClusterImportCredentialSnapshot `json:"-"`
	ManagedClusters            []ManagedCluster                  `json:"managedClusters"`
	ClusterMaintenanceProfiles []ClusterMaintenanceProfile       `json:"clusterMaintenanceProfiles"`
	ClusterMaintenanceWindows  []ClusterMaintenanceWindow        `json:"clusterMaintenanceWindows"`
	ClusterMaintenanceRuns     []ClusterMaintenanceRun           `json:"clusterMaintenanceRuns"`
	AgentCertificates          []AgentCertificate                `json:"agentCertificates"`
	ClusterInventories         []ClusterInventory                `json:"clusterInventories"`
	BaselineDeployments        []BaselineDeployment              `json:"baselineDeployments"`
	RuntimeVerifications       []RuntimeVerification             `json:"runtimeVerifications"`
	RuntimeCertifications      []RuntimeCertificationRun         `json:"runtimeCertifications"`
	RecoveryCheckpoints        []RecoveryCheckpoint              `json:"recoveryCheckpoints"`
	FleetGroups                []FleetGroup                      `json:"fleetGroups"`
	GitCredentials             []GitCredential                   `json:"gitCredentials"`
	GitProviders               []GitProvider                     `json:"gitProviders"`
	GitPullRequests            []GitPullRequest                  `json:"gitPullRequests"`
	ManagedGitRevisions        []ManagedGitRevision              `json:"managedGitRevisions"`
	DriftScans                 []DriftScan                       `json:"driftScans"`
	UpgradeCampaigns           []UpgradeCampaign                 `json:"upgradeCampaigns"`
	Entitlements               []Entitlement                     `json:"entitlements"`
	OEMProfiles                []OEMProfile                      `json:"oemProfiles"`
	Tenants                    []TenantEnvironment               `json:"tenants"`
	ProviderProfiles           []ProviderProfile                 `json:"providerProfiles"`
	ProviderClusters           []ProviderCluster                 `json:"providerClusters"`
	AIRuns                     []AIRun                           `json:"aiRuns"`
	MarketplaceRecommendations []MarketplaceRecommendation       `json:"marketplaceRecommendations"`
	RuntimeClosureCampaigns    []RuntimeClosureCampaign          `json:"runtimeClosureCampaigns"`
}
