package controlplane

import (
	"encoding/json"
	"time"

	compatauth "platform.4so.io/factory/internal/compatibility"
)

type ResourceMeta struct {
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Organization struct {
	ResourceMeta
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type Project struct {
	ResourceMeta
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
}

// OrganizationMembership is the durable tenant authorization authority.
// Product-wide roles define the global ceiling. A platform-operator may be
// delegated organization-admin authority inside a specific organization, while
// platform-viewer remains read-only and platform-admin remains the super-admin.
type OrganizationMembershipRole string

const (
	OrganizationAdmin    OrganizationMembershipRole = "organization-admin"
	OrganizationOperator OrganizationMembershipRole = "organization-operator"
	OrganizationViewer   OrganizationMembershipRole = "organization-viewer"
)

type OrganizationMembershipState string

const (
	OrganizationMembershipActive  OrganizationMembershipState = "ACTIVE"
	OrganizationMembershipRevoked OrganizationMembershipState = "REVOKED"
)

type OrganizationMembership struct {
	ResourceMeta
	OrganizationID string                      `json:"organizationId"`
	Subject        string                      `json:"subject"`
	Role           OrganizationMembershipRole  `json:"role"`
	State          OrganizationMembershipState `json:"state"`
	GrantedBy      string                      `json:"grantedBy"`
	RevokedBy      string                      `json:"revokedBy,omitempty"`
	RevokedAt      *time.Time                  `json:"revokedAt,omitempty"`
}

// ServiceAccount is a non-human API identity scoped to exactly one
// organization and optionally one project. Service accounts deliberately
// cannot hold platform-admin so critical human approval separation remains
// intact.
type ServiceAccountState string

const (
	ServiceAccountActive  ServiceAccountState = "ACTIVE"
	ServiceAccountRevoked ServiceAccountState = "REVOKED"
)

type ServiceAccount struct {
	ResourceMeta
	OrganizationID string              `json:"organizationId"`
	ProjectID      string              `json:"projectId,omitempty"`
	Name           string              `json:"name"`
	DisplayName    string              `json:"displayName"`
	ProductRole    string              `json:"productRole"`
	State          ServiceAccountState `json:"state"`
	CreatedBy      string              `json:"createdBy"`
	RevokedBy      string              `json:"revokedBy,omitempty"`
	RevokedAt      *time.Time          `json:"revokedAt,omitempty"`
}

type APITokenState string

const (
	APITokenActive  APITokenState = "ACTIVE"
	APITokenRevoked APITokenState = "REVOKED"
)

const (
	APITokenPermissionRead       = "read"
	APITokenPermissionOperate    = "operate"
	APITokenPermissionMCPRead    = "mcp.read"
	APITokenPermissionAIDiagnose = "ai.diagnose"
)

// APIToken persists only a one-way token digest. Raw token material is returned
// once by issue/rotate API responses and must never enter authoritative state.
type APIToken struct {
	ResourceMeta
	ServiceAccountID string        `json:"serviceAccountId"`
	OrganizationID   string        `json:"organizationId"`
	ProjectID        string        `json:"projectId,omitempty"`
	TokenPrefix      string        `json:"tokenPrefix"`
	TokenDigest      string        `json:"tokenDigest,omitempty"`
	IdempotencyKey   string        `json:"idempotencyKey,omitempty"`
	Permissions      []string      `json:"permissions"`
	State            APITokenState `json:"state"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	CreatedBy        string        `json:"createdBy"`
	RotatedFromID    string        `json:"rotatedFromId,omitempty"`
	RevokedBy        string        `json:"revokedBy,omitempty"`
	RevokedAt        *time.Time    `json:"revokedAt,omitempty"`
}

// BlueprintOverlay is an immutable, versioned set of exact JSON-Pointer changes.
// It is an input to Blueprint resolution, never a second desired-state authority.
type BlueprintOverlayScope string

const (
	BlueprintOverlayProvider    BlueprintOverlayScope = "PROVIDER"
	BlueprintOverlayEnvironment BlueprintOverlayScope = "ENVIRONMENT"
)

type BlueprintOverlayChange struct {
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type BlueprintOverlay struct {
	ResourceMeta
	ProjectID string                   `json:"projectId"`
	Name      string                   `json:"name"`
	Version   string                   `json:"version"`
	Scope     BlueprintOverlayScope    `json:"scope"`
	ScopeKey  string                   `json:"scopeKey"`
	Digest    string                   `json:"digest"`
	Changes   []BlueprintOverlayChange `json:"changes"`
	CreatedBy string                   `json:"createdBy"`
}

type BlueprintFieldResolution struct {
	Path                 string `json:"path"`
	Policy               string `json:"policy"`
	EffectiveOwner       string `json:"effectiveOwner"`
	ProviderOverlayID    string `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID string `json:"environmentOverlayId,omitempty"`
	ValueDigest          string `json:"valueDigest"`
}

type BlueprintResolution struct {
	BaseBlueprintDigest  string                     `json:"baseBlueprintDigest"`
	OverlayDigest        string                     `json:"overlayDigest"`
	OwnershipDigest      string                     `json:"ownershipDigest"`
	ProviderOverlayID    string                     `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID string                     `json:"environmentOverlayId,omitempty"`
	Fields               []BlueprintFieldResolution `json:"fields"`
}

type BlueprintRevision struct {
	ResourceMeta
	ProjectID            string `json:"projectId"`
	BlueprintName        string `json:"blueprintName"`
	BlueprintVersion     string `json:"blueprintVersion"`
	BlueprintDigest      string `json:"blueprintDigest"`
	CatalogDigest        string `json:"catalogDigest"`
	BaseBlueprintDigest  string `json:"baseBlueprintDigest,omitempty"`
	OverlayDigest        string `json:"overlayDigest,omitempty"`
	OwnershipDigest      string `json:"ownershipDigest,omitempty"`
	ProviderOverlayID    string `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID string `json:"environmentOverlayId,omitempty"`
	BasePayload          []byte `json:"basePayload,omitempty"`
	ResolutionPayload    []byte `json:"resolutionPayload,omitempty"`
	Payload              []byte `json:"payload"`
}

type BlueprintLifecycleState string

const (
	BlueprintDraft      BlueprintLifecycleState = "DRAFT"
	BlueprintReview     BlueprintLifecycleState = "REVIEW"
	BlueprintPublished  BlueprintLifecycleState = "PUBLISHED"
	BlueprintDeprecated BlueprintLifecycleState = "DEPRECATED"
	BlueprintRevoked    BlueprintLifecycleState = "REVOKED"
)

// BlueprintRelease owns the operator lifecycle around immutable BlueprintRevision
// records. Draft edits never mutate a revision: they create a new immutable
// revision and atomically move CurrentRevisionID. Once published, the release
// identity and current revision are locked permanently.
type BlueprintRelease struct {
	ResourceMeta
	ProjectID              string                  `json:"projectId"`
	BlueprintName          string                  `json:"blueprintName"`
	BlueprintVersion       string                  `json:"blueprintVersion"`
	State                  BlueprintLifecycleState `json:"state"`
	CurrentRevisionID      string                  `json:"currentRevisionId"`
	CurrentBlueprintDigest string                  `json:"currentBlueprintDigest"`
	CatalogDigest          string                  `json:"catalogDigest"`
	CatalogReleaseID       string                  `json:"catalogReleaseId,omitempty"`
	SourceReleaseID        string                  `json:"sourceReleaseId,omitempty"`
	UpgradeFromIDs         []string                `json:"upgradeFromIds,omitempty"`
	ExecutionReady         bool                    `json:"executionReady"`
	PlanStatus             string                  `json:"planStatus"`
	RequestedBy            string                  `json:"requestedBy"`
	ReviewRequestedAt      *time.Time              `json:"reviewRequestedAt,omitempty"`
	PublishedBy            string                  `json:"publishedBy,omitempty"`
	PublishedAt            *time.Time              `json:"publishedAt,omitempty"`
	DeprecatedBy           string                  `json:"deprecatedBy,omitempty"`
	DeprecatedAt           *time.Time              `json:"deprecatedAt,omitempty"`
	RevokedBy              string                  `json:"revokedBy,omitempty"`
	RevokedAt              *time.Time              `json:"revokedAt,omitempty"`
}

type CatalogVisibility string

const (
	CatalogVisibilityPlatform CatalogVisibility = "PLATFORM"
	CatalogVisibilityPrivate  CatalogVisibility = "PRIVATE"
)

type CatalogChannel string

const (
	CatalogChannelCandidate  CatalogChannel = "CANDIDATE"
	CatalogChannelRender     CatalogChannel = "RENDER"
	CatalogChannelRuntime    CatalogChannel = "RUNTIME"
	CatalogChannelProduction CatalogChannel = "PRODUCTION"
)

type CatalogLifecycleState string

const (
	CatalogDraft      CatalogLifecycleState = "DRAFT"
	CatalogReview     CatalogLifecycleState = "REVIEW"
	CatalogPublished  CatalogLifecycleState = "PUBLISHED"
	CatalogDeprecated CatalogLifecycleState = "DEPRECATED"
	CatalogRevoked    CatalogLifecycleState = "REVOKED"
)

type CatalogTrustKeyState string

const (
	CatalogTrustKeyActive  CatalogTrustKeyState = "ACTIVE"
	CatalogTrustKeyRevoked CatalogTrustKeyState = "REVOKED"
)

// CatalogTrustKey is the durable public-key trust authority used to verify
// signed catalog releases. OrganizationID is empty for platform-wide trust and
// set for a private organization trust domain.
type CatalogTrustKey struct {
	ResourceMeta
	OrganizationID string               `json:"organizationId,omitempty"`
	Name           string               `json:"name"`
	Algorithm      string               `json:"algorithm"`
	PublicKey      string               `json:"publicKey"`
	Fingerprint    string               `json:"fingerprint"`
	State          CatalogTrustKeyState `json:"state"`
	CreatedBy      string               `json:"createdBy"`
	RevokedBy      string               `json:"revokedBy,omitempty"`
	RevokedAt      *time.Time           `json:"revokedAt,omitempty"`
}

// CatalogRevision is immutable catalog material. Draft edits create another
// revision and move a CatalogRelease pointer rather than mutating payload bytes.
type CatalogRevision struct {
	ResourceMeta
	OrganizationID string `json:"organizationId,omitempty"`
	CatalogName    string `json:"catalogName"`
	CatalogVersion string `json:"catalogVersion"`
	ManifestDigest string `json:"manifestDigest"`
	Payload        []byte `json:"payload"`
}

// CatalogRelease owns trust, promotion and retirement state around an immutable
// CatalogRevision. A promoted release keeps SourceReleaseID for traceability.
type CatalogRelease struct {
	ResourceMeta
	OrganizationID        string                `json:"organizationId,omitempty"`
	CatalogName           string                `json:"catalogName"`
	CatalogVersion        string                `json:"catalogVersion"`
	Visibility            CatalogVisibility     `json:"visibility"`
	Channel               CatalogChannel        `json:"channel"`
	State                 CatalogLifecycleState `json:"state"`
	CurrentRevisionID     string                `json:"currentRevisionId"`
	ManifestDigest        string                `json:"manifestDigest"`
	SourceReleaseID       string                `json:"sourceReleaseId,omitempty"`
	SigningKeyID          string                `json:"signingKeyId,omitempty"`
	SigningKeyFingerprint string                `json:"signingKeyFingerprint,omitempty"`
	Signature             string                `json:"signature,omitempty"`
	RequestedBy           string                `json:"requestedBy"`
	ReviewRequestedAt     *time.Time            `json:"reviewRequestedAt,omitempty"`
	PublishedBy           string                `json:"publishedBy,omitempty"`
	PublishedAt           *time.Time            `json:"publishedAt,omitempty"`
	DeprecatedBy          string                `json:"deprecatedBy,omitempty"`
	DeprecatedAt          *time.Time            `json:"deprecatedAt,omitempty"`
	RevokedBy             string                `json:"revokedBy,omitempty"`
	RevokedAt             *time.Time            `json:"revokedAt,omitempty"`
}

type Assignment struct {
	ResourceMeta
	ProjectID           string `json:"projectId"`
	TargetRef           string `json:"targetRef"`
	BlueprintRevisionID string `json:"blueprintRevisionId"`
	DesiredGeneration   int64  `json:"desiredGeneration"`
	ObservedGeneration  int64  `json:"observedGeneration"`
}

type OperationState string

const (
	OperationDraft            OperationState = "DRAFT"
	OperationPlanning         OperationState = "PLANNING"
	OperationPlanFailed       OperationState = "PLAN_FAILED"
	OperationAwaitingApproval OperationState = "AWAITING_APPROVAL"
	OperationApproved         OperationState = "APPROVED"
	OperationQueued           OperationState = "QUEUED"
	OperationRunning          OperationState = "RUNNING"
	OperationRetryWait        OperationState = "RETRY_WAIT"
	OperationCancelRequested  OperationState = "CANCEL_REQUESTED"
	OperationVerifying        OperationState = "VERIFYING"
	OperationSucceeded        OperationState = "SUCCEEDED"
	OperationFailed           OperationState = "FAILED"
	OperationRollingBack      OperationState = "ROLLING_BACK"
	OperationRolledBack       OperationState = "ROLLED_BACK"
	OperationRollbackFailed   OperationState = "ROLLBACK_FAILED"
	OperationNeedsOperator    OperationState = "NEEDS_OPERATOR"
	OperationCancelled        OperationState = "CANCELLED"
)

type OperationClass string

const (
	OperationClassReadOnly    OperationClass = "READ_ONLY"
	OperationClassMutating    OperationClass = "MUTATING"
	OperationClassDestructive OperationClass = "DESTRUCTIVE"
)

type OperationFailureClass string

const (
	OperationFailureTransientNetwork      OperationFailureClass = "TRANSIENT_NETWORK"
	OperationFailureRateLimited           OperationFailureClass = "RATE_LIMITED"
	OperationFailureDependencyUnavailable OperationFailureClass = "DEPENDENCY_UNAVAILABLE"
	OperationFailureConflict              OperationFailureClass = "CONFLICT"
	OperationFailurePermanent             OperationFailureClass = "PERMANENT"
	OperationFailureUnknown               OperationFailureClass = "UNKNOWN"
)

type OperationRetryPolicy struct {
	MaxAttempts           int                     `json:"maxAttempts"`
	InitialBackoffSeconds int                     `json:"initialBackoffSeconds"`
	MaxBackoffSeconds     int                     `json:"maxBackoffSeconds"`
	RetryableClasses      []OperationFailureClass `json:"retryableClasses"`
}

type OperationFailureReport struct {
	Class             OperationFailureClass `json:"class"`
	Code              string                `json:"code,omitempty"`
	Message           string                `json:"message"`
	RetryAfterSeconds int                   `json:"retryAfterSeconds,omitempty"`
}

type Operation struct {
	ResourceMeta
	ProjectID               string                `json:"projectId"`
	Kind                    string                `json:"kind"`
	TargetRef               string                `json:"targetRef"`
	DesiredRevision         string                `json:"desiredRevision"`
	State                   OperationState        `json:"state"`
	Risk                    string                `json:"risk"`
	Class                   OperationClass        `json:"class"`
	RetryPolicy             OperationRetryPolicy  `json:"retryPolicy"`
	Attempt                 int                   `json:"attempt"`
	NextAttemptAt           *time.Time            `json:"nextAttemptAt,omitempty"`
	LastFailureClass        OperationFailureClass `json:"lastFailureClass,omitempty"`
	RetryExhausted          bool                  `json:"retryExhausted"`
	RecoveryCheckpointID    string                `json:"recoveryCheckpointId,omitempty"`
	RecoveryEvidenceDigest  string                `json:"recoveryEvidenceDigest,omitempty"`
	RecoveryInventoryDigest string                `json:"recoveryInventoryDigest,omitempty"`
	CancelRequestedBy       string                `json:"cancelRequestedBy,omitempty"`
	CancelRequestedAt       *time.Time            `json:"cancelRequestedAt,omitempty"`
	CancelReason            string                `json:"cancelReason,omitempty"`
	IdempotencyKey          string                `json:"idempotencyKey"`
	RequestDigest           string                `json:"requestDigest"`
	ActorID                 string                `json:"actorId"`
	LeaseOwner              string                `json:"leaseOwner,omitempty"`
	LeaseExpiresAt          *time.Time            `json:"leaseExpiresAt,omitempty"`
	FenceToken              int64                 `json:"fenceToken"`
	LastError               string                `json:"lastError,omitempty"`
	CompensationPlanDigest  string                `json:"compensationPlanDigest,omitempty"`
	CompensationStepCount   int                   `json:"compensationStepCount,omitempty"`
	CompensationCursor      int                   `json:"compensationCursor,omitempty"`
	CompensationStartedAt   *time.Time            `json:"compensationStartedAt,omitempty"`
	CompensationFinishedAt  *time.Time            `json:"compensationFinishedAt,omitempty"`
	CompensationFailureStep string                `json:"compensationFailureStep,omitempty"`
}

type OperationStep struct {
	ResourceMeta
	OperationID string         `json:"operationId"`
	StepKey     string         `json:"stepKey"`
	State       OperationState `json:"state"`
	Attempt     int            `json:"attempt"`
	FenceToken  int64          `json:"fenceToken"`
	StartedAt   *time.Time     `json:"startedAt,omitempty"`
	FinishedAt  *time.Time     `json:"finishedAt,omitempty"`
	LastError   string         `json:"lastError,omitempty"`
}

// OperationStepPhase makes forward and compensation traces explicit so logs and
// evidence never rely on ambiguous step-key joins.
type OperationStepPhase string

const (
	OperationStepPhaseForward      OperationStepPhase = "FORWARD"
	OperationStepPhaseCompensation OperationStepPhase = "COMPENSATION"
)

type OperationStepLogLevel string

const (
	OperationStepLogDebug OperationStepLogLevel = "DEBUG"
	OperationStepLogInfo  OperationStepLogLevel = "INFO"
	OperationStepLogWarn  OperationStepLogLevel = "WARN"
	OperationStepLogError OperationStepLogLevel = "ERROR"
)

// OperationStepTrace is append-only operator-visible execution history.
// TraceKey is worker supplied and idempotent within one operation/phase/step/attempt.
type OperationStepTrace struct {
	ResourceMeta
	OperationID    string                `json:"operationId"`
	Phase          OperationStepPhase    `json:"phase"`
	StepKey        string                `json:"stepKey"`
	Attempt        int                   `json:"attempt"`
	Sequence       int64                 `json:"sequence"`
	TraceKey       string                `json:"traceKey"`
	Level          OperationStepLogLevel `json:"level"`
	EventType      string                `json:"eventType"`
	Message        string                `json:"message"`
	EvidenceID     string                `json:"evidenceId,omitempty"`
	EvidenceDigest string                `json:"evidenceDigest,omitempty"`
}

type OperationStepTraceInput struct {
	OperationID  string                `json:"operationId"`
	Phase        OperationStepPhase    `json:"phase"`
	StepKey      string                `json:"stepKey"`
	TraceKey     string                `json:"traceKey"`
	Level        OperationStepLogLevel `json:"level"`
	EventType    string                `json:"eventType"`
	Message      string                `json:"message"`
	EvidenceKind string                `json:"evidenceKind"`
	MediaType    string                `json:"mediaType"`
	Location     string                `json:"location"`
	Payload      []byte                `json:"-"`
}

type EvidencePayload struct {
	EvidenceID string `json:"evidenceId"`
	Payload    []byte `json:"payload"`
}

type CompensationStrategy string

const (
	CompensationNone                          CompensationStrategy = "NONE"
	CompensationAutomaticRollback             CompensationStrategy = "AUTOMATIC_ROLLBACK"
	CompensationRestorePreviousRevision       CompensationStrategy = "RESTORE_PREVIOUS_REVISION"
	CompensationPreserveDataRestoreController CompensationStrategy = "PRESERVE_DATA_RESTORE_CONTROLLER"
	CompensationProviderRecovery              CompensationStrategy = "PROVIDER_RECOVERY"
	CompensationManualRecovery                CompensationStrategy = "MANUAL_RECOVERY"
	CompensationIrreversible                  CompensationStrategy = "IRREVERSIBLE"
)

type CompensationStepState string

const (
	CompensationStepPending        CompensationStepState = "PENDING"
	CompensationStepRunning        CompensationStepState = "RUNNING"
	CompensationStepSucceeded      CompensationStepState = "SUCCEEDED"
	CompensationStepFailed         CompensationStepState = "FAILED"
	CompensationStepSkipped        CompensationStepState = "SKIPPED"
	CompensationStepManualRequired CompensationStepState = "MANUAL_REQUIRED"
)

type CompensationPlanStep struct {
	StepKey      string               `json:"stepKey"`
	ForwardOrder int                  `json:"forwardOrder"`
	Strategy     CompensationStrategy `json:"strategy"`
	Action       string               `json:"action"`
	InputDigest  string               `json:"inputDigest"`
	MaxAttempts  int                  `json:"maxAttempts,omitempty"`
}

type OperationCompensationStep struct {
	ResourceMeta
	OperationID        string                `json:"operationId"`
	StepKey            string                `json:"stepKey"`
	ForwardOrder       int                   `json:"forwardOrder"`
	Strategy           CompensationStrategy  `json:"strategy"`
	Action             string                `json:"action"`
	InputDigest        string                `json:"inputDigest"`
	MaxAttempts        int                   `json:"maxAttempts"`
	ForwardCompleted   bool                  `json:"forwardCompleted"`
	ForwardCompletedAt *time.Time            `json:"forwardCompletedAt,omitempty"`
	State              CompensationStepState `json:"state"`
	Attempt            int                   `json:"attempt"`
	FenceToken         int64                 `json:"fenceToken,omitempty"`
	StartedAt          *time.Time            `json:"startedAt,omitempty"`
	FinishedAt         *time.Time            `json:"finishedAt,omitempty"`
	EvidenceDigest     string                `json:"evidenceDigest,omitempty"`
	LastError          string                `json:"lastError,omitempty"`
}

type CompensationStepFailure struct {
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type OutboxEvent struct {
	ResourceMeta
	AggregateType string     `json:"aggregateType"`
	AggregateID   string     `json:"aggregateId"`
	EventType     string     `json:"eventType"`
	Payload       []byte     `json:"payload"`
	AvailableAt   time.Time  `json:"availableAt"`
	ClaimedBy     string     `json:"claimedBy,omitempty"`
	ClaimedUntil  *time.Time `json:"claimedUntil,omitempty"`
	Attempt       int        `json:"attempt"`
	PublishedAt   *time.Time `json:"publishedAt,omitempty"`
}

type AuditEvent struct {
	ID           string         `json:"id"`
	OccurredAt   time.Time      `json:"occurredAt"`
	ActorID      string         `json:"actorId"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resourceType"`
	ResourceID   string         `json:"resourceId"`
	Revision     int64          `json:"revision"`
	RequestID    string         `json:"requestId,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// Notification routing turns authoritative control-plane events into durable,
// operator-visible delivery work. Destination secrets are referenced by
// environment-variable name only; raw secret material never enters Store state.
type NotificationDestinationKind string

const (
	NotificationDestinationConsole NotificationDestinationKind = "CONSOLE"
	NotificationDestinationWebhook NotificationDestinationKind = "WEBHOOK"
)

type NotificationDestinationState string

const (
	NotificationDestinationActive   NotificationDestinationState = "ACTIVE"
	NotificationDestinationDisabled NotificationDestinationState = "DISABLED"
)

type NotificationDestination struct {
	ResourceMeta
	OrganizationID   string                       `json:"organizationId"`
	Name             string                       `json:"name"`
	Kind             NotificationDestinationKind  `json:"kind"`
	Endpoint         string                       `json:"endpoint,omitempty"`
	AuthorizationEnv string                       `json:"authorizationEnv,omitempty"`
	HMACSecretEnv    string                       `json:"hmacSecretEnv,omitempty"`
	AllowHTTP        bool                         `json:"allowHttp"`
	TimeoutSeconds   int                          `json:"timeoutSeconds"`
	State            NotificationDestinationState `json:"state"`
	CreatedBy        string                       `json:"createdBy"`
	DisabledBy       string                       `json:"disabledBy,omitempty"`
	DisabledAt       *time.Time                   `json:"disabledAt,omitempty"`
}

type NotificationSeverity string

const (
	NotificationInfo     NotificationSeverity = "INFO"
	NotificationWarning  NotificationSeverity = "WARNING"
	NotificationCritical NotificationSeverity = "CRITICAL"
)

type NotificationRoute struct {
	ResourceMeta
	OrganizationID  string               `json:"organizationId"`
	ProjectID       string               `json:"projectId,omitempty"`
	Name            string               `json:"name"`
	Enabled         bool                 `json:"enabled"`
	EventPatterns   []string             `json:"eventPatterns"`
	MinimumSeverity NotificationSeverity `json:"minimumSeverity"`
	DestinationIDs  []string             `json:"destinationIds"`
	CreatedBy       string               `json:"createdBy"`
}

type NotificationEvent struct {
	ResourceMeta
	OrganizationID string               `json:"organizationId"`
	ProjectID      string               `json:"projectId,omitempty"`
	SourceEventID  string               `json:"sourceEventId"`
	AggregateType  string               `json:"aggregateType"`
	AggregateID    string               `json:"aggregateId"`
	EventType      string               `json:"eventType"`
	Severity       NotificationSeverity `json:"severity"`
	Title          string               `json:"title"`
	Summary        string               `json:"summary"`
	Payload        []byte               `json:"payload,omitempty"`
	OccurredAt     time.Time            `json:"occurredAt"`
}

type NotificationDeliveryState string

const (
	NotificationDeliveryPending    NotificationDeliveryState = "PENDING"
	NotificationDeliveryDelivering NotificationDeliveryState = "DELIVERING"
	NotificationDeliveryRetryWait  NotificationDeliveryState = "RETRY_WAIT"
	NotificationDeliverySucceeded  NotificationDeliveryState = "SUCCEEDED"
	NotificationDeliveryDeadLetter NotificationDeliveryState = "DEAD_LETTER"
)

type NotificationDelivery struct {
	ResourceMeta
	EventID        string                    `json:"eventId"`
	RouteID        string                    `json:"routeId"`
	DestinationID  string                    `json:"destinationId"`
	State          NotificationDeliveryState `json:"state"`
	Attempt        int                       `json:"attempt"`
	MaxAttempts    int                       `json:"maxAttempts"`
	NextAttemptAt  time.Time                 `json:"nextAttemptAt"`
	ClaimedBy      string                    `json:"claimedBy,omitempty"`
	ClaimedUntil   *time.Time                `json:"claimedUntil,omitempty"`
	LastStatusCode int                       `json:"lastStatusCode,omitempty"`
	LastError      string                    `json:"lastError,omitempty"`
	DeliveredAt    *time.Time                `json:"deliveredAt,omitempty"`
}

type NotificationDeliveryAttempt struct {
	ResourceMeta
	DeliveryID     string    `json:"deliveryId"`
	Attempt        int       `json:"attempt"`
	StartedAt      time.Time `json:"startedAt"`
	FinishedAt     time.Time `json:"finishedAt"`
	Success        bool      `json:"success"`
	Retryable      bool      `json:"retryable"`
	StatusCode     int       `json:"statusCode,omitempty"`
	Error          string    `json:"error,omitempty"`
	ResponseDigest string    `json:"responseDigest,omitempty"`
	DurationMillis int64     `json:"durationMillis,omitempty"`
}

type NotificationDeliveryResult struct {
	Success        bool   `json:"success"`
	Retryable      bool   `json:"retryable"`
	StatusCode     int    `json:"statusCode,omitempty"`
	Error          string `json:"error,omitempty"`
	ResponseDigest string `json:"responseDigest,omitempty"`
	DurationMillis int64  `json:"durationMillis,omitempty"`
}

type EvidenceMetadata struct {
	ResourceMeta
	OperationID string             `json:"operationId"`
	Phase       OperationStepPhase `json:"phase,omitempty"`
	StepKey     string             `json:"stepKey,omitempty"`
	Attempt     int                `json:"attempt,omitempty"`
	TraceID     string             `json:"traceId,omitempty"`
	Kind        string             `json:"kind"`
	Digest      string             `json:"digest"`
	MediaType   string             `json:"mediaType"`
	Location    string             `json:"location"`
	Size        int64              `json:"size"`
	HasPayload  bool               `json:"hasPayload"`
	Sealed      bool               `json:"sealed"`
}

type OperationRequest struct {
	ProjectID            string         `json:"projectId"`
	Kind                 string         `json:"kind"`
	TargetRef            string         `json:"targetRef"`
	DesiredRevision      string         `json:"desiredRevision"`
	Risk                 string         `json:"risk"`
	Class                OperationClass `json:"class,omitempty"`
	RecoveryCheckpointID string         `json:"recoveryCheckpointId,omitempty"`
}

type ClaimResult struct {
	OperationID    string    `json:"operationId"`
	LeaseOwner     string    `json:"leaseOwner"`
	LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
	FenceToken     int64     `json:"fenceToken"`
}

type ClusterImportState string

const (
	ClusterImportPendingApproval ClusterImportState = "PENDING_APPROVAL"
	ClusterImportApproved        ClusterImportState = "APPROVED"
	ClusterImportClaimed         ClusterImportState = "CLAIMED"
	ClusterImportExpired         ClusterImportState = "EXPIRED"
	ClusterImportRevoked         ClusterImportState = "REVOKED"
)

type ClusterImport struct {
	ResourceMeta
	ProjectID           string             `json:"projectId"`
	Name                string             `json:"name"`
	DisplayName         string             `json:"displayName"`
	State               ClusterImportState `json:"state"`
	TokenDigest         string             `json:"-"`
	AgentTokenDigest    string             `json:"-"`
	AgentServiceAccount string             `json:"agentServiceAccount,omitempty"`
	ExpiresAt           time.Time          `json:"expiresAt"`
	ApprovedAt          *time.Time         `json:"approvedAt,omitempty"`
	ClaimedAt           *time.Time         `json:"claimedAt,omitempty"`
	ClusterID           string             `json:"clusterId,omitempty"`
	RequestedBy         string             `json:"requestedBy"`
	ApprovedBy          string             `json:"approvedBy,omitempty"`
}

type ClusterNode struct {
	Name           string   `json:"name"`
	UID            string   `json:"uid"`
	Roles          []string `json:"roles,omitempty"`
	OS             string   `json:"os,omitempty"`
	Architecture   string   `json:"architecture,omitempty"`
	KubeletVersion string   `json:"kubeletVersion,omitempty"`
	Ready          bool     `json:"ready"`
}

type ClusterAddOn struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   string `json:"version,omitempty"`
	Healthy   bool   `json:"healthy"`
}

type ClusterStorageClass struct {
	Name                 string `json:"name"`
	Provisioner          string `json:"provisioner"`
	ReclaimPolicy        string `json:"reclaimPolicy,omitempty"`
	VolumeBindingMode    string `json:"volumeBindingMode,omitempty"`
	AllowVolumeExpansion bool   `json:"allowVolumeExpansion"`
	Default              bool   `json:"default"`
}

type ClusterCapacity struct {
	CPUCapacityMilli       int64 `json:"cpuCapacityMilli"`
	CPUAllocatableMilli    int64 `json:"cpuAllocatableMilli"`
	MemoryCapacityBytes    int64 `json:"memoryCapacityBytes"`
	MemoryAllocatableBytes int64 `json:"memoryAllocatableBytes"`
	PodsCapacity           int64 `json:"podsCapacity"`
	PodsAllocatable        int64 `json:"podsAllocatable"`
}

type ClusterAPIResourceObservation struct {
	APIVersion string   `json:"apiVersion"`
	Group      string   `json:"group,omitempty"`
	Version    string   `json:"version"`
	Kind       string   `json:"kind"`
	Resource   string   `json:"resource"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs,omitempty"`
}

type ClusterCRDVersionObservation struct {
	Name    string `json:"name"`
	Served  bool   `json:"served"`
	Storage bool   `json:"storage"`
}

type ClusterCRDObservation struct {
	Name     string                         `json:"name"`
	Group    string                         `json:"group"`
	Kind     string                         `json:"kind"`
	Plural   string                         `json:"plural"`
	Scope    string                         `json:"scope"`
	Versions []ClusterCRDVersionObservation `json:"versions"`
}

type ClusterCertificateObservation struct {
	Name         string    `json:"name"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SerialNumber string    `json:"serialNumber,omitempty"`
	Fingerprint  string    `json:"fingerprint"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
}

type ClusterNetworking struct {
	CNI                string   `json:"cni,omitempty"`
	IngressControllers []string `json:"ingressControllers,omitempty"`
	GatewayAPI         bool     `json:"gatewayApi"`
}

type ClusterInventory struct {
	ResourceMeta
	ClusterID                   string                          `json:"clusterId"`
	ObservedAt                  time.Time                       `json:"observedAt"`
	Distribution                string                          `json:"distribution"`
	DistributionEvidenceMethod  string                          `json:"distributionEvidenceMethod,omitempty"`
	DistributionEvidenceUID     string                          `json:"distributionEvidenceUid,omitempty"`
	DistributionEvidenceVersion string                          `json:"distributionEvidenceVersion,omitempty"`
	KubernetesVersion           string                          `json:"kubernetesVersion"`
	Nodes                       []ClusterNode                   `json:"nodes"`
	AddOns                      []ClusterAddOn                  `json:"addOns"`
	StorageClasses              []ClusterStorageClass           `json:"storageClasses"`
	Capacity                    ClusterCapacity                 `json:"capacity"`
	Certificates                []ClusterCertificateObservation `json:"certificates"`
	Networking                  ClusterNetworking               `json:"networking"`
	APIResources                []ClusterAPIResourceObservation `json:"apiResources,omitempty"`
	CRDs                        []ClusterCRDObservation         `json:"crds,omitempty"`
	APIDiscoveryComplete        bool                            `json:"apiDiscoveryComplete"`
	CRDDiscoveryComplete        bool                            `json:"crdDiscoveryComplete"`
	SchemaDiscoveryVersion      string                          `json:"schemaDiscoveryVersion,omitempty"`
	SchemaDiscoveryDigest       string                          `json:"schemaDiscoveryDigest,omitempty"`
	SchemaDiscoveryComplete     bool                            `json:"schemaDiscoveryComplete"`
	Capabilities                []string                        `json:"capabilities"`
	Digest                      string                          `json:"digest"`
}

type AgentCertificateState string

const (
	AgentCertificateActive  AgentCertificateState = "ACTIVE"
	AgentCertificateRevoked AgentCertificateState = "REVOKED"
)

type AgentCertificate struct {
	ResourceMeta
	ClusterID    string                `json:"clusterId"`
	SerialNumber string                `json:"serialNumber"`
	Fingerprint  string                `json:"fingerprint"`
	Subject      string                `json:"subject"`
	State        AgentCertificateState `json:"state"`
	NotBefore    time.Time             `json:"notBefore"`
	NotAfter     time.Time             `json:"notAfter"`
	IssuedBy     string                `json:"issuedBy"`
	RevokedBy    string                `json:"revokedBy,omitempty"`
	RevokedAt    *time.Time            `json:"revokedAt,omitempty"`
	ReplacedByID string                `json:"replacedById,omitempty"`
}

type ManagedCluster struct {
	ResourceMeta
	ProjectID                              string            `json:"projectId"`
	ImportID                               string            `json:"importId"`
	Name                                   string            `json:"name"`
	DisplayName                            string            `json:"displayName"`
	ExternalUID                            string            `json:"externalUid"`
	ConnectionState                        string            `json:"connectionState"`
	Distribution                           string            `json:"distribution,omitempty"`
	KubernetesVersion                      string            `json:"kubernetesVersion,omitempty"`
	AgentVersion                           string            `json:"agentVersion,omitempty"`
	LastSeenAt                             *time.Time        `json:"lastSeenAt,omitempty"`
	InventoryUpdatedAt                     *time.Time        `json:"inventoryUpdatedAt,omitempty"`
	InventoryObservedAt                    *time.Time        `json:"inventoryObservedAt,omitempty"`
	Labels                                 map[string]string `json:"labels,omitempty"`
	Capabilities                           []string          `json:"capabilities,omitempty"`
	InventoryDigest                        string            `json:"inventoryDigest,omitempty"`
	MutationRBACBasisDigest                string            `json:"mutationRbacBasisDigest,omitempty"`
	MutationRBACIssuedForDigest            string            `json:"mutationRbacIssuedForDigest,omitempty"`
	TargetRBACRevocationAcknowledgedDigest string            `json:"targetRbacRevocationAcknowledgedDigest,omitempty"`
	TargetRBACRevocationAcknowledgedAt     *time.Time        `json:"targetRbacRevocationAcknowledgedAt,omitempty"`
	TargetRBACRevocationAcknowledgedBy     string            `json:"targetRbacRevocationAcknowledgedBy,omitempty"`
}

const ClusterMaintenanceAuthorityMethod = "KUBERNETES_NODE_MAINTENANCE_V1"
const ClusterMaintenanceFencedReportCapability = "cluster-maintenance-fenced-report"

type ClusterEnvironment string

const (
	ClusterEnvironmentDevelopment ClusterEnvironment = "DEVELOPMENT"
	ClusterEnvironmentStaging     ClusterEnvironment = "STAGING"
	ClusterEnvironmentProduction  ClusterEnvironment = "PRODUCTION"
)

type ClusterMaintenanceProfile struct {
	ResourceMeta
	ProjectID                  string             `json:"projectId"`
	ClusterID                  string             `json:"clusterId"`
	Environment                ClusterEnvironment `json:"environment"`
	DefaultDrainTimeoutSeconds int                `json:"defaultDrainTimeoutSeconds"`
	UpdatedBy                  string             `json:"updatedBy"`
}

type ClusterMaintenanceWindowState string

const (
	ClusterMaintenanceWindowActive    ClusterMaintenanceWindowState = "ACTIVE"
	ClusterMaintenanceWindowCancelled ClusterMaintenanceWindowState = "CANCELLED"
)

type ClusterMaintenanceWindow struct {
	ResourceMeta
	ProjectID           string                        `json:"projectId"`
	ClusterID           string                        `json:"clusterId"`
	Name                string                        `json:"name"`
	StartsAt            time.Time                     `json:"startsAt"`
	EndsAt              time.Time                     `json:"endsAt"`
	MaxUnavailable      int                           `json:"maxUnavailable"`
	DrainTimeoutSeconds int                           `json:"drainTimeoutSeconds"`
	State               ClusterMaintenanceWindowState `json:"state"`
	CreatedBy           string                        `json:"createdBy"`
	CancelledBy         string                        `json:"cancelledBy,omitempty"`
	CancelledAt         *time.Time                    `json:"cancelledAt,omitempty"`
}

type ClusterMaintenanceRunState string

const (
	ClusterMaintenanceAwaitingApproval ClusterMaintenanceRunState = "AWAITING_APPROVAL"
	ClusterMaintenanceQueued           ClusterMaintenanceRunState = "QUEUED"
	ClusterMaintenanceRunning          ClusterMaintenanceRunState = "RUNNING"
	ClusterMaintenanceRestoring        ClusterMaintenanceRunState = "RESTORING"
	ClusterMaintenanceSucceeded        ClusterMaintenanceRunState = "SUCCEEDED"
	ClusterMaintenanceFailed           ClusterMaintenanceRunState = "FAILED"
	ClusterMaintenanceNeedsOperator    ClusterMaintenanceRunState = "NEEDS_OPERATOR"
	ClusterMaintenanceCancelled        ClusterMaintenanceRunState = "CANCELLED"
)

type NodeMaintenanceResult struct {
	NodeName       string   `json:"nodeName"`
	Cordoned       bool     `json:"cordoned"`
	DrainAttempted bool     `json:"drainAttempted"`
	Drained        bool     `json:"drained"`
	Uncordoned     bool     `json:"uncordoned"`
	EvictedPods    []string `json:"evictedPods,omitempty"`
	SkippedPods    []string `json:"skippedPods,omitempty"`
	PDBBlockedPods []string `json:"pdbBlockedPods,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type ClusterMaintenanceRun struct {
	ResourceMeta
	ProjectID           string                     `json:"projectId"`
	ClusterID           string                     `json:"clusterId"`
	WindowID            string                     `json:"windowId"`
	OperationID         string                     `json:"operationId"`
	State               ClusterMaintenanceRunState `json:"state"`
	NodeNames           []string                   `json:"nodeNames"`
	NodeUIDs            map[string]string          `json:"nodeUids"`
	InventoryDigest     string                     `json:"inventoryDigest"`
	MaxUnavailable      int                        `json:"maxUnavailable"`
	DrainTimeoutSeconds int                        `json:"drainTimeoutSeconds"`
	RequestedBy         string                     `json:"requestedBy"`
	ApprovedBy          string                     `json:"approvedBy,omitempty"`
	ApprovedAt          *time.Time                 `json:"approvedAt,omitempty"`
	StartedAt           *time.Time                 `json:"startedAt,omitempty"`
	FinishedAt          *time.Time                 `json:"finishedAt,omitempty"`
	Results             []NodeMaintenanceResult    `json:"results,omitempty"`
	LastError           string                     `json:"lastError,omitempty"`
	IdempotencyKey      string                     `json:"idempotencyKey"`
	RequestDigest       string                     `json:"requestDigest"`
}

type ClusterMaintenanceTask struct {
	RunID               string            `json:"runId"`
	RunRevision         int64             `json:"runRevision"`
	OperationID         string            `json:"operationId"`
	OperationRevision   int64             `json:"operationRevision"`
	OperationFenceToken int64             `json:"operationFenceToken"`
	LeaseExpiresAt      time.Time         `json:"leaseExpiresAt"`
	ClusterID           string            `json:"clusterId"`
	NodeNames           []string          `json:"nodeNames"`
	NodeUIDs            map[string]string `json:"nodeUids"`
	InventoryDigest     string            `json:"inventoryDigest"`
	DrainTimeoutSeconds int               `json:"drainTimeoutSeconds"`
	Method              string            `json:"method"`
}

type ClusterMaintenanceTaskResult struct {
	OperationFenceToken int64                   `json:"operationFenceToken"`
	Success             bool                    `json:"success"`
	Results             []NodeMaintenanceResult `json:"results,omitempty"`
	Error               string                  `json:"error,omitempty"`
}

type BaselineDeploymentState string

const BaselineSourceMarketplace = "marketplace"

const (
	BaselineDeploymentPlanning         BaselineDeploymentState = "PLANNING"
	BaselineDeploymentAwaitingApproval BaselineDeploymentState = "AWAITING_APPROVAL"
	BaselineDeploymentQueued           BaselineDeploymentState = "QUEUED"
	BaselineDeploymentApplying         BaselineDeploymentState = "APPLYING"
	BaselineDeploymentSucceeded        BaselineDeploymentState = "SUCCEEDED"
	BaselineDeploymentFailed           BaselineDeploymentState = "FAILED"
	BaselineDeploymentRollbackQueued   BaselineDeploymentState = "ROLLBACK_QUEUED"
	BaselineDeploymentRollingBack      BaselineDeploymentState = "ROLLING_BACK"
	BaselineDeploymentRolledBack       BaselineDeploymentState = "ROLLED_BACK"
)

type BaselinePlanChange struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Current  string `json:"currentDigest,omitempty"`
	Desired  string `json:"desiredDigest,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type PlanSchemaCompatibility struct {
	Status             string   `json:"status"`
	Method             string   `json:"method"`
	HTTPStatus         int      `json:"httpStatus"`
	SchemaIndexVersion string   `json:"schemaIndexVersion"`
	SchemaIndexDigest  string   `json:"schemaIndexDigest"`
	Warnings           []string `json:"warnings,omitempty"`
	FailureDigest      string   `json:"failureDigest,omitempty"`
}

type PlanAPIImpact struct {
	Resource         string                  `json:"resource"`
	APIVersion       string                  `json:"apiVersion"`
	Kind             string                  `json:"kind"`
	DiscoveryStatus  string                  `json:"discoveryStatus"`
	LifecycleStatus  string                  `json:"lifecycleStatus"`
	DeprecatedIn     string                  `json:"deprecatedIn,omitempty"`
	RemovedIn        string                  `json:"removedIn,omitempty"`
	Replacement      string                  `json:"replacement,omitempty"`
	CustomResource   bool                    `json:"customResource"`
	CRDName          string                  `json:"crdName,omitempty"`
	CRDVersionServed bool                    `json:"crdVersionServed,omitempty"`
	Schema           PlanSchemaCompatibility `json:"schema"`
	Severity         string                  `json:"severity"`
	Message          string                  `json:"message"`
}

type PlanQuotaImpact struct {
	Resource string            `json:"resource"`
	Action   string            `json:"action"`
	Current  map[string]string `json:"current,omitempty"`
	Desired  map[string]string `json:"desired,omitempty"`
}

type PlanCapacityEstimate struct {
	DemandDeltaKnown              bool              `json:"demandDeltaKnown"`
	CPURequestDeltaMilli          int64             `json:"cpuRequestDeltaMilli"`
	MemoryRequestDeltaBytes       int64             `json:"memoryRequestDeltaBytes"`
	PodReplicaDelta               int64             `json:"podReplicaDelta"`
	WorkloadResources             int               `json:"workloadResources"`
	CPUAllocatableCeilingMilli    int64             `json:"cpuAllocatableCeilingMilli"`
	MemoryAllocatableCeilingBytes int64             `json:"memoryAllocatableCeilingBytes"`
	PodsAllocatableCeiling        int64             `json:"podsAllocatableCeiling"`
	CeilingCheck                  string            `json:"ceilingCheck"`
	CurrentUsageKnown             bool              `json:"currentUsageKnown"`
	UnknownReasons                []string          `json:"unknownReasons,omitempty"`
	QuotaImpacts                  []PlanQuotaImpact `json:"quotaImpacts,omitempty"`
}

type PlanDisruptionEstimate struct {
	Level                     string   `json:"level"`
	MaintenanceRecommendation string   `json:"maintenanceRecommendation"`
	Reasons                   []string `json:"reasons,omitempty"`
	AffectedResources         []string `json:"affectedResources,omitempty"`
}

type PlanRollbackResource struct {
	Resource             string         `json:"resource"`
	ChangeAction         string         `json:"changeAction"`
	Strategy             string         `json:"strategy"`
	Status               string         `json:"status"`
	AuthorizationStatus  string         `json:"authorizationStatus"`
	DryRunStatus         string         `json:"dryRunStatus"`
	HTTPStatus           int            `json:"httpStatus,omitempty"`
	SchemaIndexVersion   string         `json:"schemaIndexVersion"`
	SchemaIndexDigest    string         `json:"schemaIndexDigest"`
	ObservedUID          string         `json:"observedUid,omitempty"`
	ObservedObjectDigest string         `json:"observedObjectDigest,omitempty"`
	RestoreObjectDigest  string         `json:"restoreObjectDigest,omitempty"`
	RestoreObject        map[string]any `json:"restoreObject,omitempty"`
	Warnings             []string       `json:"warnings,omitempty"`
	FailureDigest        string         `json:"failureDigest,omitempty"`
}

type PlanRollbackFeasibility struct {
	Status    string                 `json:"status"`
	Method    string                 `json:"method"`
	Resources []PlanRollbackResource `json:"resources"`
	Blockers  []string               `json:"blockers,omitempty"`
	Warnings  []string               `json:"warnings,omitempty"`
	Digest    string                 `json:"digest"`
}

type PlanEvidenceArtifact struct {
	Key            string `json:"key"`
	Kind           string `json:"kind"`
	Resource       string `json:"resource,omitempty"`
	Authority      string `json:"authority"`
	SourceLocation string `json:"sourceLocation"`
	OutputLocation string `json:"outputLocation"`
	MediaType      string `json:"mediaType"`
	Phase          string `json:"phase"`
	Required       bool   `json:"required"`
	RetentionDays  int    `json:"retentionDays"`
}

type PlanEvidenceCollection struct {
	Status        string                 `json:"status"`
	Method        string                 `json:"method"`
	RequiredCount int                    `json:"requiredCount"`
	Artifacts     []PlanEvidenceArtifact `json:"artifacts"`
	Blockers      []string               `json:"blockers,omitempty"`
	Warnings      []string               `json:"warnings,omitempty"`
	Digest        string                 `json:"digest"`
}

type BaselineEvidenceArtifact struct {
	Key           string         `json:"key"`
	Kind          string         `json:"kind"`
	Resource      string         `json:"resource,omitempty"`
	Authority     string         `json:"authority"`
	Digest        string         `json:"digest"`
	MediaType     string         `json:"mediaType"`
	Location      string         `json:"location"`
	Size          int64          `json:"size"`
	Required      bool           `json:"required"`
	RetentionDays int            `json:"retentionDays"`
	CollectedAt   *time.Time     `json:"collectedAt,omitempty"`
	RetainUntil   *time.Time     `json:"retainUntil,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
}

type PlanCapabilityCheck struct {
	Key       string   `json:"key"`
	Domain    string   `json:"domain"`
	Required  bool     `json:"required"`
	Status    string   `json:"status"`
	Authority string   `json:"authority"`
	Impact    string   `json:"impact"`
	Detail    string   `json:"detail"`
	Evidence  []string `json:"evidence,omitempty"`
}

type PlanCapabilityPreflight struct {
	Status          string                `json:"status"`
	Method          string                `json:"method"`
	InventoryDigest string                `json:"inventoryDigest"`
	Checks          []PlanCapabilityCheck `json:"checks"`
	Blockers        []string              `json:"blockers,omitempty"`
	Warnings        []string              `json:"warnings,omitempty"`
	Digest          string                `json:"digest"`
}

type BaselinePlanImpact struct {
	SchemaVersion   int                     `json:"schemaVersion"`
	InventoryDigest string                  `json:"inventoryDigest"`
	Compatibility   compatauth.Decision     `json:"compatibility"`
	Capability      PlanCapabilityPreflight `json:"capability"`
	API             []PlanAPIImpact         `json:"api"`
	Capacity        PlanCapacityEstimate    `json:"capacity"`
	Disruption      PlanDisruptionEstimate  `json:"disruption"`
	Rollback        PlanRollbackFeasibility `json:"rollback"`
	Evidence        PlanEvidenceCollection  `json:"evidence"`
	ApprovalReady   bool                    `json:"approvalReady"`
	Blockers        []string                `json:"blockers,omitempty"`
	Warnings        []string                `json:"warnings,omitempty"`
	Digest          string                  `json:"digest"`
}

type BaselineDeployment struct {
	ResourceMeta
	ProjectID              string                     `json:"projectId"`
	ClusterID              string                     `json:"clusterId"`
	BaselineID             string                     `json:"baselineId"`
	BaselineVersion        string                     `json:"baselineVersion"`
	TargetNamespace        string                     `json:"targetNamespace"`
	State                  BaselineDeploymentState    `json:"state"`
	Risk                   string                     `json:"risk"`
	DesiredDigest          string                     `json:"desiredDigest"`
	ObservedDigest         string                     `json:"observedDigest,omitempty"`
	PreviousDigest         string                     `json:"previousDigest,omitempty"`
	RequestDigest          string                     `json:"requestDigest"`
	IdempotencyKey         string                     `json:"idempotencyKey"`
	RequestedBy            string                     `json:"requestedBy"`
	ApprovedBy             string                     `json:"approvedBy,omitempty"`
	ApprovedAt             *time.Time                 `json:"approvedAt,omitempty"`
	StartedAt              *time.Time                 `json:"startedAt,omitempty"`
	FinishedAt             *time.Time                 `json:"finishedAt,omitempty"`
	Plan                   []BaselinePlanChange       `json:"plan,omitempty"`
	PlanCreatedAt          *time.Time                 `json:"planCreatedAt,omitempty"`
	PlanExpiresAt          *time.Time                 `json:"planExpiresAt,omitempty"`
	PlanInventoryDigest    string                     `json:"planInventoryDigest,omitempty"`
	PlanImpact             BaselinePlanImpact         `json:"planImpact,omitempty"`
	PlanImpactDigest       string                     `json:"planImpactDigest,omitempty"`
	PlanContextDigest      string                     `json:"planContextDigest,omitempty"`
	Evidence               []BaselineEvidenceArtifact `json:"evidence,omitempty"`
	EvidenceDigest         string                     `json:"evidenceDigest,omitempty"`
	PlanRevalidationCount  int                        `json:"planRevalidationCount"`
	LastError              string                     `json:"lastError,omitempty"`
	TaskAttempt            int                        `json:"taskAttempt"`
	TaskFenceToken         int64                      `json:"taskFenceToken"`
	TaskLeaseExpiresAt     *time.Time                 `json:"taskLeaseExpiresAt,omitempty"`
	PendingAction          string                     `json:"pendingAction,omitempty"`
	DestructiveOperationID string                     `json:"destructiveOperationId,omitempty"`
	SourceType             string                     `json:"sourceType,omitempty"`
	SourceID               string                     `json:"sourceId,omitempty"`
	SourceVersion          string                     `json:"sourceVersion,omitempty"`
}

type BaselineTask struct {
	DeploymentID     string                 `json:"deploymentId"`
	DeploymentRev    int64                  `json:"deploymentRevision"`
	TaskFenceToken   int64                  `json:"taskFenceToken"`
	LeaseExpiresAt   time.Time              `json:"leaseExpiresAt"`
	Action           string                 `json:"action"`
	BaselineID       string                 `json:"baselineId"`
	BaselineVersion  string                 `json:"baselineVersion"`
	TargetNamespace  string                 `json:"targetNamespace"`
	DesiredDigest    string                 `json:"desiredDigest"`
	Inventory        ClusterInventory       `json:"inventory"`
	Resources        []BaselineTaskResource `json:"resources"`
	Rollback         []PlanRollbackResource `json:"rollback,omitempty"`
	EvidencePlan     PlanEvidenceCollection `json:"evidencePlan,omitempty"`
	PlanImpactDigest string                 `json:"planImpactDigest,omitempty"`
}

type BaselineTaskResource struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Namespace  string         `json:"namespace,omitempty"`
	Name       string         `json:"name"`
	Object     map[string]any `json:"object,omitempty"`
}

type BaselineTaskResult struct {
	DeploymentID   string                     `json:"-"`
	TaskFenceToken int64                      `json:"taskFenceToken"`
	Action         string                     `json:"action"`
	Success        bool                       `json:"success"`
	ObservedDigest string                     `json:"observedDigest,omitempty"`
	Changes        []BaselinePlanChange       `json:"changes,omitempty"`
	Impact         BaselinePlanImpact         `json:"impact,omitempty"`
	Evidence       []BaselineEvidenceArtifact `json:"evidence,omitempty"`
	Error          string                     `json:"error,omitempty"`
}

type AIRun struct {
	ResourceMeta
	ProjectID          string          `json:"projectId"`
	Purpose            string          `json:"purpose"`
	Provider           string          `json:"provider"`
	Model              string          `json:"model,omitempty"`
	PromptID           string          `json:"promptId"`
	PromptDigest       string          `json:"promptDigest"`
	ContextDigest      string          `json:"contextDigest"`
	OutputDigest       string          `json:"outputDigest"`
	RedactionCount     int             `json:"redactionCount"`
	InputBytes         int             `json:"inputBytes"`
	InputTokens        int             `json:"inputTokens,omitempty"`
	CachedTokens       int             `json:"cachedTokens,omitempty"`
	OutputTokens       int             `json:"outputTokens,omitempty"`
	Output             json.RawMessage `json:"output"`
	LinkedResourceType string          `json:"linkedResourceType,omitempty"`
	LinkedResourceID   string          `json:"linkedResourceId,omitempty"`
	RequestedBy        string          `json:"requestedBy"`
	IdempotencyKey     string          `json:"idempotencyKey"`
	RequestDigest      string          `json:"requestDigest"`
	AdvisoryOnly       bool            `json:"advisoryOnly"`
}

type MarketplaceRecommendationItem struct {
	OfferID      string `json:"offerId"`
	OfferVersion string `json:"offerVersion"`
	Score        int    `json:"score"`
	Reason       string `json:"reason"`
	Risk         string `json:"risk"`
}

type MarketplaceRecommendation struct {
	ResourceMeta
	ProjectID      string                          `json:"projectId"`
	ClusterID      string                          `json:"clusterId"`
	Objective      string                          `json:"objective"`
	Engine         string                          `json:"engine"`
	Model          string                          `json:"model,omitempty"`
	ContextDigest  string                          `json:"contextDigest"`
	ResponseDigest string                          `json:"responseDigest"`
	Items          []MarketplaceRecommendationItem `json:"items"`
	RequestedBy    string                          `json:"requestedBy"`
	IdempotencyKey string                          `json:"idempotencyKey"`
	RequestDigest  string                          `json:"requestDigest"`
}

type RuntimeVerificationState string

const (
	RuntimeVerificationQueued    RuntimeVerificationState = "QUEUED"
	RuntimeVerificationRunning   RuntimeVerificationState = "RUNNING"
	RuntimeVerificationSucceeded RuntimeVerificationState = "SUCCEEDED"
	RuntimeVerificationFailed    RuntimeVerificationState = "FAILED"
)

type RuntimeCheck struct {
	Key            string `json:"key"`
	Status         string `json:"status"`
	Detail         string `json:"detail,omitempty"`
	DurationMillis int64  `json:"durationMillis,omitempty"`
}

type RuntimeVerification struct {
	ResourceMeta
	ProjectID            string                   `json:"projectId"`
	ClusterID            string                   `json:"clusterId"`
	BaselineDeploymentID string                   `json:"baselineDeploymentId"`
	State                RuntimeVerificationState `json:"state"`
	DesiredDigest        string                   `json:"desiredDigest"`
	ObservedDigest       string                   `json:"observedDigest,omitempty"`
	ProbeImage           string                   `json:"probeImage"`
	RequestDigest        string                   `json:"requestDigest"`
	IdempotencyKey       string                   `json:"idempotencyKey"`
	RequestedBy          string                   `json:"requestedBy"`
	StartedAt            *time.Time               `json:"startedAt,omitempty"`
	FinishedAt           *time.Time               `json:"finishedAt,omitempty"`
	Checks               []RuntimeCheck           `json:"checks,omitempty"`
	ReportDigest         string                   `json:"reportDigest,omitempty"`
	LastError            string                   `json:"lastError,omitempty"`
	TaskAttempt          int                      `json:"taskAttempt"`
	TaskFenceToken       int64                    `json:"taskFenceToken"`
	TaskLeaseExpiresAt   *time.Time               `json:"taskLeaseExpiresAt,omitempty"`
}

type RuntimeVerificationTask struct {
	VerificationID       string    `json:"verificationId"`
	VerificationRevision int64     `json:"verificationRevision"`
	TaskFenceToken       int64     `json:"taskFenceToken"`
	LeaseExpiresAt       time.Time `json:"leaseExpiresAt"`
	BaselineDeploymentID string    `json:"baselineDeploymentId"`
	TargetNamespace      string    `json:"targetNamespace"`
	DesiredDigest        string    `json:"desiredDigest"`
	ProbeImage           string    `json:"probeImage"`
}

type RuntimeVerificationResult struct {
	VerificationID string         `json:"-"`
	TaskFenceToken int64          `json:"taskFenceToken"`
	Success        bool           `json:"success"`
	ObservedDigest string         `json:"observedDigest,omitempty"`
	Checks         []RuntimeCheck `json:"checks,omitempty"`
	Error          string         `json:"error,omitempty"`
}

type RuntimeCertificationProfile string

const (
	RuntimeCertificationFoundationV1    RuntimeCertificationProfile = "FOUNDATION_V1"
	RuntimeCertificationObservabilityV1 RuntimeCertificationProfile = "OBSERVABILITY_V1"
	RuntimeCertificationTargetV1        RuntimeCertificationProfile = "TARGET_RUNTIME_V1"
)

type RuntimeCertificationState string

const (
	RuntimeCertificationQueued     RuntimeCertificationState = "QUEUED"
	RuntimeCertificationInstalling RuntimeCertificationState = "INSTALLING"
	RuntimeCertificationVerifying  RuntimeCertificationState = "VERIFYING"
	RuntimeCertificationSucceeded  RuntimeCertificationState = "SUCCEEDED"
	RuntimeCertificationBlocked    RuntimeCertificationState = "BLOCKED"
	RuntimeCertificationFailed     RuntimeCertificationState = "FAILED"
	RuntimeCertificationRevoked    RuntimeCertificationState = "REVOKED"
)

type RuntimeCertificationPhase string

const (
	RuntimeCertificationPhaseInstall RuntimeCertificationPhase = "INSTALL"
	RuntimeCertificationPhaseVerify  RuntimeCertificationPhase = "VERIFY"
)

type RuntimeCertificationCleanupGeneration struct {
	TaskAttempt int                       `json:"taskAttempt"`
	Phase       RuntimeCertificationPhase `json:"phase"`
	Token       string                    `json:"token"`
}

// RuntimeCertificationRun is an evidence-bound, immutable-context certification
// attempt. A successful run is never silently revalidated against a newer
// cluster inventory; a new run is required when the environment changes.
type RuntimeCertificationRun struct {
	ResourceMeta
	ProjectID               string                                  `json:"projectId"`
	ClusterID               string                                  `json:"clusterId"`
	CatalogReleaseID        string                                  `json:"catalogReleaseId"`
	CatalogRevisionID       string                                  `json:"catalogRevisionId"`
	Profile                 RuntimeCertificationProfile             `json:"profile"`
	State                   RuntimeCertificationState               `json:"state"`
	Phase                   RuntimeCertificationPhase               `json:"phase"`
	Namespace               string                                  `json:"namespace"`
	InventoryDigest         string                                  `json:"inventoryDigest"`
	EnvironmentFingerprint  string                                  `json:"environmentFingerprint"`
	ManifestDigest          string                                  `json:"manifestDigest"`
	SourceLockDigest        string                                  `json:"sourceLockDigest"`
	RenderedDigest          string                                  `json:"renderedDigest"`
	ResourceCount           int                                     `json:"resourceCount"`
	Checks                  []RuntimeCheck                          `json:"checks,omitempty"`
	InstallCheckpointDigest string                                  `json:"installCheckpointDigest,omitempty"`
	EvidenceDigest          string                                  `json:"evidenceDigest,omitempty"`
	RequestedBy             string                                  `json:"requestedBy"`
	IdempotencyKey          string                                  `json:"idempotencyKey"`
	RequestDigest           string                                  `json:"requestDigest"`
	TaskAttempt             int                                     `json:"taskAttempt"`
	TaskFenceToken          int64                                   `json:"taskFenceToken"`
	TaskLeaseExpiresAt      *time.Time                              `json:"taskLeaseExpiresAt,omitempty"`
	CleanupGenerations      []RuntimeCertificationCleanupGeneration `json:"cleanupGenerations,omitempty"`
	StartedAt               *time.Time                              `json:"startedAt,omitempty"`
	InstallCheckpointAt     *time.Time                              `json:"installCheckpointAt,omitempty"`
	FinishedAt              *time.Time                              `json:"finishedAt,omitempty"`
	ExpiresAt               *time.Time                              `json:"expiresAt,omitempty"`
	RevokedBy               string                                  `json:"revokedBy,omitempty"`
	RevokedAt               *time.Time                              `json:"revokedAt,omitempty"`
	LastError               string                                  `json:"lastError,omitempty"`
}

type RuntimeCertificationTask struct {
	RunID                   string                                  `json:"runId"`
	RunRevision             int64                                   `json:"runRevision"`
	TaskFenceToken          int64                                   `json:"taskFenceToken"`
	LeaseExpiresAt          time.Time                               `json:"leaseExpiresAt"`
	Profile                 RuntimeCertificationProfile             `json:"profile"`
	Phase                   RuntimeCertificationPhase               `json:"phase"`
	Namespace               string                                  `json:"namespace"`
	InventoryDigest         string                                  `json:"inventoryDigest"`
	EnvironmentFingerprint  string                                  `json:"environmentFingerprint"`
	CatalogReleaseID        string                                  `json:"catalogReleaseId"`
	ManifestDigest          string                                  `json:"manifestDigest"`
	SourceLockDigest        string                                  `json:"sourceLockDigest"`
	RenderedDigest          string                                  `json:"renderedDigest"`
	InstallCheckpointDigest string                                  `json:"installCheckpointDigest,omitempty"`
	TaskAttempt             int                                     `json:"taskAttempt"`
	CleanupToken            string                                  `json:"cleanupToken"`
	PriorCleanupGenerations []RuntimeCertificationCleanupGeneration `json:"priorCleanupGenerations,omitempty"`
	Resources               []map[string]any                        `json:"resources"`
}

type RuntimeCertificationResult struct {
	RunID           string                    `json:"-"`
	TaskFenceToken  int64                     `json:"taskFenceToken"`
	Phase           RuntimeCertificationPhase `json:"phase"`
	Success         bool                      `json:"success"`
	Blocked         bool                      `json:"blocked,omitempty"`
	InventoryDigest string                    `json:"inventoryDigest"`
	RenderedDigest  string                    `json:"renderedDigest"`
	Checks          []RuntimeCheck            `json:"checks,omitempty"`
	Error           string                    `json:"error,omitempty"`
}

type FleetGroup struct {
	ResourceMeta
	ProjectID      string   `json:"projectId"`
	Name           string   `json:"name"`
	DisplayName    string   `json:"displayName"`
	ClusterIDs     []string `json:"clusterIds"`
	RequestedBy    string   `json:"requestedBy"`
	IdempotencyKey string   `json:"idempotencyKey"`
	RequestDigest  string   `json:"requestDigest"`
}

type GitCredentialState string

const (
	GitCredentialActive  GitCredentialState = "ACTIVE"
	GitCredentialRevoked GitCredentialState = "REVOKED"
)

type GitCredential struct {
	ResourceMeta
	Name          string             `json:"name"`
	Username      string             `json:"username"`
	SecretRef     string             `json:"secretRef"`
	State         GitCredentialState `json:"state"`
	CreatedBy     string             `json:"createdBy"`
	RotatedFromID string             `json:"rotatedFromId,omitempty"`
	RevokedBy     string             `json:"revokedBy,omitempty"`
	RevokedAt     *time.Time         `json:"revokedAt,omitempty"`
}

type GitProviderState string

const (
	GitProviderActive   GitProviderState = "ACTIVE"
	GitProviderDisabled GitProviderState = "DISABLED"
)

type GitProvider struct {
	ResourceMeta
	Name         string           `json:"name"`
	Kind         string           `json:"kind"`
	BaseURL      string           `json:"baseUrl"`
	CredentialID string           `json:"credentialId"`
	Default      bool             `json:"default"`
	State        GitProviderState `json:"state"`
	CreatedBy    string           `json:"createdBy"`
}

type GitDeliveryMode string

const (
	GitDeliveryDirectCommit GitDeliveryMode = "DIRECT_COMMIT"
	GitDeliveryPullRequest  GitDeliveryMode = "PULL_REQUEST"
)

type GitPullRequestState string

const (
	GitPullRequestRequested GitPullRequestState = "REQUESTED"
	GitPullRequestOpen      GitPullRequestState = "OPEN"
	GitPullRequestApproved  GitPullRequestState = "APPROVED"
	GitPullRequestMerged    GitPullRequestState = "MERGED"
	GitPullRequestClosed    GitPullRequestState = "CLOSED"
)

type GitPullRequest struct {
	ResourceMeta
	Organization          string              `json:"organization"`
	Repository            string              `json:"repository"`
	BaseBranch            string              `json:"baseBranch"`
	BaseCommitSHA         string              `json:"baseCommitSha"`
	HeadBranch            string              `json:"headBranch"`
	CandidateCommitSHA    string              `json:"candidateCommitSha,omitempty"`
	ApprovedHeadCommitSHA string              `json:"approvedHeadCommitSha,omitempty"`
	RevisionID            string              `json:"revisionId"`
	Digest                string              `json:"digest"`
	PublicKeyFingerprint  string              `json:"publicKeyFingerprint"`
	ExternalNumber        int64               `json:"externalNumber"`
	ExternalURL           string              `json:"externalUrl,omitempty"`
	State                 GitPullRequestState `json:"state"`
	RequestedBy           string              `json:"requestedBy"`
	ApprovedBy            string              `json:"approvedBy,omitempty"`
	ApprovedAt            *time.Time          `json:"approvedAt,omitempty"`
	MergedBy              string              `json:"mergedBy,omitempty"`
	MergedAt              *time.Time          `json:"mergedAt,omitempty"`
	MergedCommitSHA       string              `json:"mergedCommitSha,omitempty"`
}

type ManagedGitRevision struct {
	ResourceMeta
	Organization         string          `json:"organization"`
	Repository           string          `json:"repository"`
	Branch               string          `json:"branch"`
	RevisionID           string          `json:"revisionId"`
	Digest               string          `json:"digest"`
	CommitSHA            string          `json:"commitSha"`
	PublicKeyFingerprint string          `json:"publicKeyFingerprint"`
	Source               string          `json:"source"`
	DeliveryMode         GitDeliveryMode `json:"deliveryMode"`
	PullRequestID        string          `json:"pullRequestId,omitempty"`
	SyncHealthy          bool            `json:"syncHealthy"`
	ObservedDigest       string          `json:"observedDigest,omitempty"`
	LastKnownGood        bool            `json:"lastKnownGood"`
	LastKnownGoodAt      *time.Time      `json:"lastKnownGoodAt,omitempty"`
	RecordedBy           string          `json:"recordedBy"`
}

type GitDriftClassification string

const (
	GitDriftNotRequested     GitDriftClassification = "NOT_REQUESTED"
	GitDriftInSync           GitDriftClassification = "IN_SYNC"
	GitDriftExternalChange   GitDriftClassification = "EXTERNAL_GIT_CHANGE"
	GitDriftExternalApplied  GitDriftClassification = "EXTERNAL_GIT_APPLIED"
	GitDriftLiveDrift        GitDriftClassification = "LIVE_DRIFT"
	GitDriftThreeWayConflict GitDriftClassification = "THREE_WAY_CONFLICT"
	GitDriftUntrustedChange  GitDriftClassification = "UNTRUSTED_GIT_CHANGE"
	GitDriftObservedUnknown  GitDriftClassification = "OBSERVED_UNKNOWN"
	GitDriftCommitOnlyChange GitDriftClassification = "GIT_COMMIT_ONLY_CHANGE"
)

type GitDriftEvidence struct {
	Organization         string                 `json:"organization"`
	Repository           string                 `json:"repository"`
	Branch               string                 `json:"branch"`
	BaseRevisionID       string                 `json:"baseRevisionId"`
	BaseDigest           string                 `json:"baseDigest"`
	BaseCommitSHA        string                 `json:"baseCommitSha"`
	CurrentRevisionID    string                 `json:"currentRevisionId"`
	CurrentDigest        string                 `json:"currentDigest"`
	CurrentCommitSHA     string                 `json:"currentCommitSha"`
	PublicKeyFingerprint string                 `json:"publicKeyFingerprint"`
	CurrentTrusted       bool                   `json:"currentTrusted"`
	ChangedFiles         []string               `json:"changedFiles,omitempty"`
	ObservedDigest       string                 `json:"observedDigest,omitempty"`
	Classification       GitDriftClassification `json:"classification"`
	Conflict             bool                   `json:"conflict"`
	Adoptable            bool                   `json:"adoptable"`
	Summary              string                 `json:"summary,omitempty"`
}

type DriftScanState string

const (
	DriftScanQueued  DriftScanState = "QUEUED"
	DriftScanRunning DriftScanState = "RUNNING"
	DriftScanInSync  DriftScanState = "IN_SYNC"
	DriftScanDrifted DriftScanState = "DRIFTED"
	DriftScanFailed  DriftScanState = "FAILED"
)

type DriftTargetState string

const (
	DriftTargetPending DriftTargetState = "PENDING"
	DriftTargetRunning DriftTargetState = "RUNNING"
	DriftTargetInSync  DriftTargetState = "IN_SYNC"
	DriftTargetDrifted DriftTargetState = "DRIFTED"
	DriftTargetFailed  DriftTargetState = "FAILED"
)

type DriftSeverity string

const (
	DriftSeverityInfo     DriftSeverity = "INFO"
	DriftSeverityLow      DriftSeverity = "LOW"
	DriftSeverityMedium   DriftSeverity = "MEDIUM"
	DriftSeverityHigh     DriftSeverity = "HIGH"
	DriftSeverityCritical DriftSeverity = "CRITICAL"
)

type DriftRemediation struct {
	Action   string `json:"action"`
	Mode     string `json:"mode"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

type DriftComparison struct {
	ProductGeneratedDigest string `json:"productGeneratedDigest"`
	GitDesiredDigest       string `json:"gitDesiredDigest,omitempty"`
	LiveObservedDigest     string `json:"liveObservedDigest,omitempty"`
	Classification         string `json:"classification"`
}

type DriftFinding struct {
	Fingerprint string           `json:"fingerprint"`
	Category    string           `json:"category"`
	Code        string           `json:"code"`
	Severity    DriftSeverity    `json:"severity"`
	Owner       string           `json:"owner"`
	Resource    string           `json:"resource,omitempty"`
	Summary     string           `json:"summary"`
	FirstSeenAt time.Time        `json:"firstSeenAt"`
	LastSeenAt  time.Time        `json:"lastSeenAt"`
	Occurrences int              `json:"occurrences"`
	Remediation DriftRemediation `json:"remediation"`
}

type DriftScanTarget struct {
	ClusterID            string               `json:"clusterId"`
	BaselineDeploymentID string               `json:"baselineDeploymentId"`
	BaselineID           string               `json:"baselineId"`
	BaselineVersion      string               `json:"baselineVersion"`
	DesiredDigest        string               `json:"desiredDigest"`
	ObservedDigest       string               `json:"observedDigest,omitempty"`
	State                DriftTargetState     `json:"state"`
	Changes              []BaselinePlanChange `json:"changes,omitempty"`
	LastError            string               `json:"lastError,omitempty"`
	StartedAt            *time.Time           `json:"startedAt,omitempty"`
	FinishedAt           *time.Time           `json:"finishedAt,omitempty"`
	Attempt              int                  `json:"attempt"`
	Git                  *GitDriftEvidence    `json:"git,omitempty"`
	Comparison           *DriftComparison     `json:"comparison,omitempty"`
	Findings             []DriftFinding       `json:"findings,omitempty"`
}

type DriftScan struct {
	ResourceMeta
	ProjectID      string            `json:"projectId"`
	FleetGroupID   string            `json:"fleetGroupId,omitempty"`
	State          DriftScanState    `json:"state"`
	Targets        []DriftScanTarget `json:"targets"`
	RequestedBy    string            `json:"requestedBy"`
	IdempotencyKey string            `json:"idempotencyKey"`
	RequestDigest  string            `json:"requestDigest"`
	StartedAt      *time.Time        `json:"startedAt,omitempty"`
	FinishedAt     *time.Time        `json:"finishedAt,omitempty"`
	Summary        string            `json:"summary,omitempty"`
}

type DriftTask struct {
	ScanID               string                 `json:"scanId"`
	ScanRevision         int64                  `json:"scanRevision"`
	ClusterID            string                 `json:"clusterId"`
	BaselineDeploymentID string                 `json:"baselineDeploymentId"`
	BaselineID           string                 `json:"baselineId"`
	BaselineVersion      string                 `json:"baselineVersion"`
	TargetNamespace      string                 `json:"targetNamespace"`
	DesiredDigest        string                 `json:"desiredDigest"`
	Resources            []BaselineTaskResource `json:"resources"`
	Git                  *GitDriftEvidence      `json:"git,omitempty"`
}

type DriftTaskResult struct {
	ScanID            string               `json:"-"`
	ClusterID         string               `json:"clusterId"`
	Success           bool                 `json:"success"`
	ObservedDigest    string               `json:"observedDigest,omitempty"`
	Changes           []BaselinePlanChange `json:"changes,omitempty"`
	GitObservedDigest string               `json:"gitObservedDigest,omitempty"`
	Error             string               `json:"error,omitempty"`
}

type RecoveryCheckpointState string

const (
	RecoveryCheckpointVerified RecoveryCheckpointState = "VERIFIED"
	RecoveryCheckpointRevoked  RecoveryCheckpointState = "REVOKED"
)

type RecoveryCheckpoint struct {
	ResourceMeta
	ProjectID       string                  `json:"projectId"`
	ClusterID       string                  `json:"clusterId"`
	Provider        string                  `json:"provider"`
	Reference       string                  `json:"reference"`
	EvidenceDigest  string                  `json:"evidenceDigest"`
	InventoryDigest string                  `json:"inventoryDigest"`
	CompletedAt     time.Time               `json:"completedAt"`
	ExpiresAt       time.Time               `json:"expiresAt"`
	State           RecoveryCheckpointState `json:"state"`
	RequestedBy     string                  `json:"requestedBy"`
	RevokedBy       string                  `json:"revokedBy,omitempty"`
	RevokedAt       *time.Time              `json:"revokedAt,omitempty"`
}

type UpgradeCampaignState string

const (
	UpgradeCampaignAwaitingApproval UpgradeCampaignState = "AWAITING_APPROVAL"
	UpgradeCampaignQueued           UpgradeCampaignState = "QUEUED"
	UpgradeCampaignRunning          UpgradeCampaignState = "RUNNING"
	UpgradeCampaignPauseRequested   UpgradeCampaignState = "PAUSE_REQUESTED"
	UpgradeCampaignPaused           UpgradeCampaignState = "PAUSED"
	UpgradeCampaignCancelRequested  UpgradeCampaignState = "CANCEL_REQUESTED"
	UpgradeCampaignCancelled        UpgradeCampaignState = "CANCELLED"
	UpgradeCampaignHalted           UpgradeCampaignState = "HALTED"
	UpgradeCampaignSucceeded        UpgradeCampaignState = "SUCCEEDED"
	UpgradeCampaignFailed           UpgradeCampaignState = "FAILED"
)

type UpgradeTargetState string

const (
	UpgradeTargetPending     UpgradeTargetState = "PENDING"
	UpgradeTargetPlanning    UpgradeTargetState = "PLANNING"
	UpgradeTargetApplying    UpgradeTargetState = "APPLYING"
	UpgradeTargetVerifying   UpgradeTargetState = "VERIFYING"
	UpgradeTargetSucceeded   UpgradeTargetState = "SUCCEEDED"
	UpgradeTargetFailed      UpgradeTargetState = "FAILED"
	UpgradeTargetRollingBack UpgradeTargetState = "ROLLING_BACK"
	UpgradeTargetRolledBack  UpgradeTargetState = "ROLLED_BACK"
)

type UpgradeCampaignTarget struct {
	ClusterID                    string             `json:"clusterId"`
	Wave                         int                `json:"wave"`
	State                        UpgradeTargetState `json:"state"`
	PreviousBaselineDeploymentID string             `json:"previousBaselineDeploymentId"`
	PreviousVersion              string             `json:"previousVersion"`
	PreviousDigest               string             `json:"previousDigest"`
	UpgradeDeploymentID          string             `json:"upgradeDeploymentId,omitempty"`
	RuntimeVerificationID        string             `json:"runtimeVerificationId,omitempty"`
	RollbackDeploymentID         string             `json:"rollbackDeploymentId,omitempty"`
	RollbackVerificationID       string             `json:"rollbackVerificationId,omitempty"`
	LastError                    string             `json:"lastError,omitempty"`
}

type UpgradeCampaignRevalidation struct {
	RecoveryCheckpointIDs  []string  `json:"recoveryCheckpointIds,omitempty"`
	MaintenanceWindowStart time.Time `json:"maintenanceWindowStart,omitempty"`
	MaintenanceWindowEnd   time.Time `json:"maintenanceWindowEnd,omitempty"`
}

type UpgradeCampaign struct {
	ResourceMeta
	ProjectID              string                  `json:"projectId"`
	FleetGroupID           string                  `json:"fleetGroupId"`
	BaselineID             string                  `json:"baselineId"`
	TargetVersion          string                  `json:"targetVersion"`
	State                  UpgradeCampaignState    `json:"state"`
	CanaryCount            int                     `json:"canaryCount"`
	WaveSize               int                     `json:"waveSize"`
	HaltAfterFailures      int                     `json:"haltAfterFailures"`
	CurrentWave            int                     `json:"currentWave"`
	Targets                []UpgradeCampaignTarget `json:"targets"`
	RequestedBy            string                  `json:"requestedBy"`
	ApprovedBy             string                  `json:"approvedBy,omitempty"`
	ApprovedAt             *time.Time              `json:"approvedAt,omitempty"`
	StartedAt              *time.Time              `json:"startedAt,omitempty"`
	FinishedAt             *time.Time              `json:"finishedAt,omitempty"`
	IdempotencyKey         string                  `json:"idempotencyKey"`
	RequestDigest          string                  `json:"requestDigest"`
	MaintenanceWindowStart time.Time               `json:"maintenanceWindowStart"`
	MaintenanceWindowEnd   time.Time               `json:"maintenanceWindowEnd"`
	RecoveryCheckpointIDs  []string                `json:"recoveryCheckpointIds"`
	TargetInventoryDigests map[string]string       `json:"targetInventoryDigests"`
	PlanContextDigest      string                  `json:"planContextDigest"`
	PlanCreatedAt          *time.Time              `json:"planCreatedAt,omitempty"`
	PlanExpiresAt          *time.Time              `json:"planExpiresAt,omitempty"`
	PlanRevalidationCount  int                     `json:"planRevalidationCount"`
	PausedBy               string                  `json:"pausedBy,omitempty"`
	PausedAt               *time.Time              `json:"pausedAt,omitempty"`
	PauseCount             int                     `json:"pauseCount"`
	CancelRequestedBy      string                  `json:"cancelRequestedBy,omitempty"`
	CancelRequestedAt      *time.Time              `json:"cancelRequestedAt,omitempty"`
	CancelledBy            string                  `json:"cancelledBy,omitempty"`
	CancelledAt            *time.Time              `json:"cancelledAt,omitempty"`
	ControlReason          string                  `json:"controlReason,omitempty"`
	Summary                string                  `json:"summary,omitempty"`
}

type Entitlement struct {
	ResourceMeta
	OrganizationID string     `json:"organizationId"`
	Edition        string     `json:"edition"`
	MaxTenants     int        `json:"maxTenants"`
	OEMEnabled     bool       `json:"oemEnabled"`
	Features       []string   `json:"features"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	IssuedBy       string     `json:"issuedBy"`
}

type OEMProfile struct {
	ResourceMeta
	OrganizationID string `json:"organizationId"`
	BrandName      string `json:"brandName"`
	ProductTitle   string `json:"productTitle"`
	SupportURL     string `json:"supportUrl,omitempty"`
	LogoObjectRef  string `json:"logoObjectRef,omitempty"`
	AccentColor    string `json:"accentColor,omitempty"`
	CustomDomain   string `json:"customDomain,omitempty"`
	DefaultLocale  string `json:"defaultLocale"`
}

type TenantState string

const TenantDeleteObservedCapability = "tenant-delete-observed"

const (
	TenantQueued         TenantState = "QUEUED"
	TenantProvisioning   TenantState = "PROVISIONING"
	TenantActive         TenantState = "ACTIVE"
	TenantSuspendQueued  TenantState = "SUSPEND_QUEUED"
	TenantSuspending     TenantState = "SUSPENDING"
	TenantSuspended      TenantState = "SUSPENDED"
	TenantResumeQueued   TenantState = "RESUME_QUEUED"
	TenantResuming       TenantState = "RESUMING"
	TenantResizeApproval TenantState = "RESIZE_AWAITING_APPROVAL"
	TenantResizeQueued   TenantState = "RESIZE_QUEUED"
	TenantResizing       TenantState = "RESIZING"
	TenantDeleteApproval TenantState = "DELETE_AWAITING_APPROVAL"
	TenantDeleteQueued   TenantState = "DELETE_QUEUED"
	TenantDeleting       TenantState = "DELETING"
	TenantDeleted        TenantState = "DELETED"
	TenantFailed         TenantState = "FAILED"
)

type TenantStoragePolicy struct {
	ClassSelector string `json:"classSelector"`
	StorageClass  string `json:"storageClass"`
	RequestQuota  string `json:"requestQuota"`
	MaxPVCSize    string `json:"maxPVCSize"`
}

type TenantBackupPolicy struct {
	Provider  string `json:"provider"`
	Schedule  string `json:"schedule"`
	Retention string `json:"retention"`
}

type TenantSecurityPolicy struct {
	PodSecurityLevel   string `json:"podSecurityLevel"`
	DefaultDenyIngress bool   `json:"defaultDenyIngress"`
	DefaultDenyEgress  bool   `json:"defaultDenyEgress"`
	AllowDNS           bool   `json:"allowDNS"`
}

type TenantEvidenceArtifact struct {
	Key       string `json:"key"`
	Authority string `json:"authority"`
	Resource  string `json:"resource,omitempty"`
	Status    string `json:"status"`
	Digest    string `json:"digest"`
	Detail    string `json:"detail,omitempty"`
}

type TenantEnvironment struct {
	ResourceMeta
	OrganizationID         string                   `json:"organizationId"`
	ProjectID              string                   `json:"projectId"`
	ClusterID              string                   `json:"clusterId"`
	Name                   string                   `json:"name"`
	DisplayName            string                   `json:"displayName"`
	PlanName               string                   `json:"planName"`
	Namespace              string                   `json:"namespace"`
	State                  TenantState              `json:"state"`
	Quota                  map[string]string        `json:"quota"`
	StoragePolicy          TenantStoragePolicy      `json:"storagePolicy"`
	BackupPolicy           TenantBackupPolicy       `json:"backupPolicy"`
	SecurityPolicy         TenantSecurityPolicy     `json:"securityPolicy"`
	Evidence               []TenantEvidenceArtifact `json:"evidence,omitempty"`
	EvidenceDigest         string                   `json:"evidenceDigest,omitempty"`
	EvidenceSealedAt       *time.Time               `json:"evidenceSealedAt,omitempty"`
	DesiredDigest          string                   `json:"desiredDigest"`
	PendingPlanName        string                   `json:"pendingPlanName,omitempty"`
	PendingQuota           map[string]string        `json:"pendingQuota,omitempty"`
	PendingDesiredDigest   string                   `json:"pendingDesiredDigest,omitempty"`
	ObservedDigest         string                   `json:"observedDigest,omitempty"`
	RequestedBy            string                   `json:"requestedBy"`
	IdempotencyKey         string                   `json:"idempotencyKey"`
	RequestDigest          string                   `json:"requestDigest"`
	TaskAttempt            int                      `json:"taskAttempt"`
	RuntimeContractVersion int                      `json:"runtimeContractVersion"`
	TaskFenceToken         int64                    `json:"taskFenceToken"`
	TaskLeaseExpiresAt     *time.Time               `json:"taskLeaseExpiresAt,omitempty"`
	PendingAction          string                   `json:"pendingAction,omitempty"`
	DestructiveOperationID string                   `json:"destructiveOperationId,omitempty"`
	RecoveryCheckpointID   string                   `json:"recoveryCheckpointId,omitempty"`
	ApprovedBy             string                   `json:"approvedBy,omitempty"`
	ApprovedAt             *time.Time               `json:"approvedAt,omitempty"`
	LastError              string                   `json:"lastError,omitempty"`
}

type TenantTask struct {
	TenantID       string                 `json:"tenantId"`
	TenantRevision int64                  `json:"tenantRevision"`
	TaskFenceToken int64                  `json:"taskFenceToken"`
	LeaseExpiresAt time.Time              `json:"leaseExpiresAt"`
	Action         string                 `json:"action"`
	Namespace      string                 `json:"namespace"`
	PlanName       string                 `json:"planName"`
	DesiredDigest  string                 `json:"desiredDigest"`
	Resources      []BaselineTaskResource `json:"resources"`
	StoragePolicy  TenantStoragePolicy    `json:"storagePolicy"`
	BackupPolicy   TenantBackupPolicy     `json:"backupPolicy"`
	SecurityPolicy TenantSecurityPolicy   `json:"securityPolicy"`
}

type TenantTaskResult struct {
	TenantID       string                   `json:"-"`
	TaskFenceToken int64                    `json:"taskFenceToken"`
	Action         string                   `json:"action"`
	Success        bool                     `json:"success"`
	Deleted        bool                     `json:"deleted,omitempty"`
	ObservedDigest string                   `json:"observedDigest,omitempty"`
	Error          string                   `json:"error,omitempty"`
	Evidence       []TenantEvidenceArtifact `json:"evidence,omitempty"`
	EvidenceDigest string                   `json:"evidenceDigest,omitempty"`
}

type ProviderProfileState string

const (
	ProviderProfileVerifyQueued ProviderProfileState = "VERIFY_QUEUED"
	ProviderProfileVerifying    ProviderProfileState = "VERIFYING"
	ProviderProfileReady        ProviderProfileState = "READY"
	ProviderProfileFailed       ProviderProfileState = "FAILED"
)

// ProviderProfile is a product-owned, explicitly admitted binding to one
// pre-installed Cluster API ClusterClass. The first provider lifecycle adapter
// intentionally accepts no arbitrary manifests, variables or credentials.
type ProviderProfile struct {
	ResourceMeta
	ProjectID                string               `json:"projectId"`
	ManagementClusterID      string               `json:"managementClusterId"`
	Name                     string               `json:"name"`
	DisplayName              string               `json:"displayName"`
	Adapter                  string               `json:"adapter"`
	Namespace                string               `json:"namespace"`
	ClusterClassName         string               `json:"clusterClassName"`
	WorkerClassName          string               `json:"workerClassName"`
	DefaultKubernetesVersion string               `json:"defaultKubernetesVersion"`
	KubernetesSeries         []string             `json:"kubernetesSeries"`
	Architectures            []string             `json:"architectures"`
	DistributionProfiles     []string             `json:"distributionProfiles"`
	DistributionIdentities   []string             `json:"distributionIdentities,omitempty"`
	ProvisioningMode         string               `json:"provisioningMode,omitempty"`
	InfrastructureProvider   string               `json:"infrastructureProvider,omitempty"`
	MaxWorkerReplicas        int                  `json:"maxWorkerReplicas"`
	State                    ProviderProfileState `json:"state"`
	DesiredDigest            string               `json:"desiredDigest"`
	ObservedDigest           string               `json:"observedDigest,omitempty"`
	RequestedBy              string               `json:"requestedBy"`
	IdempotencyKey           string               `json:"idempotencyKey"`
	RequestDigest            string               `json:"requestDigest"`
	TaskAttempt              int                  `json:"taskAttempt"`
	TaskFenceToken           int64                `json:"taskFenceToken"`
	TaskLeaseExpiresAt       *time.Time           `json:"taskLeaseExpiresAt,omitempty"`
	LastError                string               `json:"lastError,omitempty"`
}

type ProviderClusterState string

const (
	ProviderClusterAwaitingApproval ProviderClusterState = "AWAITING_APPROVAL"
	ProviderClusterQueued           ProviderClusterState = "QUEUED"
	ProviderClusterApplying         ProviderClusterState = "APPLYING"
	ProviderClusterReconciling      ProviderClusterState = "RECONCILING"
	ProviderClusterActive           ProviderClusterState = "ACTIVE"
	ProviderClusterDeleteApproval   ProviderClusterState = "DELETE_AWAITING_APPROVAL"
	ProviderClusterDeleteQueued     ProviderClusterState = "DELETE_QUEUED"
	ProviderClusterDeleting         ProviderClusterState = "DELETING"
	ProviderClusterDeleted          ProviderClusterState = "DELETED"
	ProviderClusterFailed           ProviderClusterState = "FAILED"
)

type ProviderClusterSpec struct {
	KubernetesVersion      string `json:"kubernetesVersion"`
	Architecture           string `json:"architecture"`
	Distribution           string `json:"distribution,omitempty"` // Deprecated compatibility alias for distributionIdentity.
	DistributionIdentity   string `json:"distributionIdentity"`
	ProvisioningMode       string `json:"provisioningMode"`
	InfrastructureProvider string `json:"infrastructureProvider"`
	ControlPlaneReplicas   int    `json:"controlPlaneReplicas"`
	WorkerReplicas         int    `json:"workerReplicas"`
}

type ProviderCluster struct {
	ResourceMeta
	ProjectID              string               `json:"projectId"`
	ProviderProfileID      string               `json:"providerProfileId"`
	ManagementClusterID    string               `json:"managementClusterId"`
	Name                   string               `json:"name"`
	DisplayName            string               `json:"displayName"`
	ResourceName           string               `json:"resourceName"`
	Namespace              string               `json:"namespace"`
	State                  ProviderClusterState `json:"state"`
	Desired                ProviderClusterSpec  `json:"desired"`
	Applied                ProviderClusterSpec  `json:"applied"`
	DesiredDigest          string               `json:"desiredDigest"`
	ObservedDigest         string               `json:"observedDigest,omitempty"`
	PendingAction          string               `json:"pendingAction"`
	DestructiveOperationID string               `json:"destructiveOperationId,omitempty"`
	RequestedBy            string               `json:"requestedBy"`
	ApprovedBy             string               `json:"approvedBy,omitempty"`
	ApprovedAt             *time.Time           `json:"approvedAt,omitempty"`
	IdempotencyKey         string               `json:"idempotencyKey"`
	RequestDigest          string               `json:"requestDigest"`
	TaskAttempt            int                  `json:"taskAttempt"`
	TaskFenceToken         int64                `json:"taskFenceToken"`
	TaskLeaseExpiresAt     *time.Time           `json:"taskLeaseExpiresAt,omitempty"`
	Phase                  string               `json:"phase,omitempty"`
	Compatibility          compatauth.Decision  `json:"compatibility"`
	LastError              string               `json:"lastError,omitempty"`
}

type ProviderProfileTask struct {
	ProfileID        string    `json:"profileId"`
	ProfileRevision  int64     `json:"profileRevision"`
	TaskFenceToken   int64     `json:"taskFenceToken"`
	LeaseExpiresAt   time.Time `json:"leaseExpiresAt"`
	Namespace        string    `json:"namespace"`
	ClusterClassName string    `json:"clusterClassName"`
	WorkerClassName  string    `json:"workerClassName"`
}

type ProviderProfileTaskResult struct {
	ProfileID       string `json:"-"`
	TaskFenceToken  int64  `json:"taskFenceToken"`
	Success         bool   `json:"success"`
	ObservedDigest  string `json:"observedDigest,omitempty"`
	ObservedVersion string `json:"observedVersion,omitempty"`
	Error           string `json:"error,omitempty"`
}

type ProviderClusterTask struct {
	ProviderClusterID string         `json:"providerClusterId"`
	ClusterRevision   int64          `json:"clusterRevision"`
	TaskFenceToken    int64          `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time      `json:"leaseExpiresAt"`
	Action            string         `json:"action"`
	Namespace         string         `json:"namespace"`
	ResourceName      string         `json:"resourceName"`
	DesiredDigest     string         `json:"desiredDigest,omitempty"`
	Resource          map[string]any `json:"resource,omitempty"`
}

type ProviderClusterTaskResult struct {
	ProviderClusterID string `json:"-"`
	TaskFenceToken    int64  `json:"taskFenceToken"`
	Action            string `json:"action"`
	Success           bool   `json:"success"`
	Ready             bool   `json:"ready,omitempty"`
	Deleted           bool   `json:"deleted,omitempty"`
	ObservedDigest    string `json:"observedDigest,omitempty"`
	Phase             string `json:"phase,omitempty"`
	Error             string `json:"error,omitempty"`
}

type RuntimeClosureCampaignState string

const (
	RuntimeClosureWaitingBaseline     RuntimeClosureCampaignState = "WAITING_BASELINE"
	RuntimeClosureWaitingApproval     RuntimeClosureCampaignState = "WAITING_APPROVAL"
	RuntimeClosureWaitingVerification RuntimeClosureCampaignState = "WAITING_VERIFICATION"
	RuntimeClosureSucceeded           RuntimeClosureCampaignState = "SUCCEEDED"
	RuntimeClosureFailed              RuntimeClosureCampaignState = "FAILED"
)

type RuntimeClosureCampaign struct {
	ResourceMeta
	ProjectID             string                      `json:"projectId"`
	ClusterID             string                      `json:"clusterId"`
	BaselineDeploymentID  string                      `json:"baselineDeploymentId"`
	RuntimeVerificationID string                      `json:"runtimeVerificationId,omitempty"`
	State                 RuntimeClosureCampaignState `json:"state"`
	DesiredDigest         string                      `json:"desiredDigest"`
	ObservedDigest        string                      `json:"observedDigest,omitempty"`
	EvidenceDigest        string                      `json:"evidenceDigest,omitempty"`
	NextAction            string                      `json:"nextAction"`
	Summary               string                      `json:"summary,omitempty"`
	LastError             string                      `json:"lastError,omitempty"`
	RequestedBy           string                      `json:"requestedBy"`
	IdempotencyKey        string                      `json:"idempotencyKey"`
	RequestDigest         string                      `json:"requestDigest"`
	StartedAt             *time.Time                  `json:"startedAt,omitempty"`
	FinishedAt            *time.Time                  `json:"finishedAt,omitempty"`
}

type RuntimeClosureCampaignUpdate struct {
	State                 RuntimeClosureCampaignState
	RuntimeVerificationID string
	ObservedDigest        string
	EvidenceDigest        string
	NextAction            string
	Summary               string
	LastError             string
}
