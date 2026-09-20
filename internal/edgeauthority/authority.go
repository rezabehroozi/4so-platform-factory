package edgeauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	Authority                = "EDGE_LOCAL_AUTHORITY_V1"
	BootAttestationAuthority = "BOOT_SECURITY_ATTESTATION_AUTHORITY_V1"
	LocalAIProfileAuthority  = "LOCAL_AI_DISCONNECTED_PROFILE_AUTHORITY_V1"
)

type Action string

const (
	ActionObserve                 Action = "OBSERVE"
	ActionCollectDiagnostics      Action = "COLLECT_DIAGNOSTICS"
	ActionRestartApprovedWorkload Action = "RESTART_APPROVED_WORKLOAD"
	ActionCordonNode              Action = "CORDON_NODE"
	ActionUncordonNode            Action = "UNCORDON_NODE"
	ActionReconcileDesiredState   Action = "RECONCILE_APPROVED_DESIRED_STATE"
)

type LocalPolicy struct {
	Authority              string        `json:"authority"`
	SiteID                 string        `json:"siteId"`
	ProjectID              string        `json:"projectId"`
	Revision               int64         `json:"revision"`
	DesiredStateDigest     string        `json:"desiredStateDigest"`
	PolicyDigest           string        `json:"policyDigest"`
	AllowedActions         []Action      `json:"allowedActions"`
	MaxOfflineDuration     time.Duration `json:"maxOfflineDuration"`
	MaxQueuedEvidenceItems int           `json:"maxQueuedEvidenceItems"`
	ValidUntil             time.Time     `json:"validUntil"`
}

type MutationRequest struct {
	SiteID             string `json:"siteId"`
	ProjectID          string `json:"projectId"`
	Action             Action `json:"action"`
	TargetRef          string `json:"targetRef"`
	BaseRevision       int64  `json:"baseRevision"`
	BaseDesiredDigest  string `json:"baseDesiredDigest"`
	PolicyDigest       string `json:"policyDigest"`
	IdempotencyKey     string `json:"idempotencyKey"`
	RequestDigest      string `json:"requestDigest"`
}

type ConflictState string

const (
	ConflictNone           ConflictState = "NO_CONFLICT"
	ConflictReviewRequired ConflictState = "REVIEW_REQUIRED"
	ConflictRejected       ConflictState = "REJECTED"
)

type ReconnectDecision struct {
	State               ConflictState `json:"state"`
	AutomaticApply      bool          `json:"automaticApply"`
	CentralRevision     int64         `json:"centralRevision"`
	CentralDesiredDigest string       `json:"centralDesiredDigest"`
	Message             string        `json:"message,omitempty"`
}

type BootClaim struct {
	Authority              string    `json:"authority"`
	SiteID                 string    `json:"siteId"`
	NodeID                 string    `json:"nodeId"`
	ObservedAt             time.Time `json:"observedAt"`
	TPMPresent             bool      `json:"tpmPresent"`
	SecureBootEnabled      bool      `json:"secureBootEnabled"`
	MeasuredBootPresent    bool      `json:"measuredBootPresent"`
	DiskEncryptionVerified bool      `json:"diskEncryptionVerified"`
	QuoteVerified          bool      `json:"quoteVerified"`
	NonceBound             bool      `json:"nonceBound"`
	PCRPolicyMatched       bool      `json:"pcrPolicyMatched"`
	QuoteDigest            string    `json:"quoteDigest"`
	EventLogDigest         string    `json:"eventLogDigest"`
	EvidenceDigest         string    `json:"evidenceDigest"`
}

type BootAssessmentState string

const (
	BootAttested BootAssessmentState = "ATTESTED"
	BootRejected BootAssessmentState = "REJECTED"
)

type BootAssessment struct {
	Authority string              `json:"authority"`
	State     BootAssessmentState `json:"state"`
	NodeID    string              `json:"nodeId"`
	Message   string              `json:"message,omitempty"`
}

type LocalAIProfile struct {
	Authority          string `json:"authority"`
	Mode               string `json:"mode"`
	Runtime            string `json:"runtime"`
	ModelDigest        string `json:"modelDigest"`
	RuntimeImageDigest string `json:"runtimeImageDigest"`
	NetworkEgress      bool   `json:"networkEgress"`
	RawCredentials     bool   `json:"rawCredentials"`
	ExternalProvider   bool   `json:"externalProvider"`
	MaxPromptBytes     int    `json:"maxPromptBytes"`
	MaxOutputBytes     int    `json:"maxOutputBytes"`
}

var sha256Pattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")

func allowedAction(action Action) bool {
	switch action {
	case ActionObserve, ActionCollectDiagnostics, ActionRestartApprovedWorkload,
		ActionCordonNode, ActionUncordonNode, ActionReconcileDesiredState:
		return true
	default:
		return false
	}
}

func CanonicalPolicy(siteID, projectID, desiredDigest string, revision int64, actions []Action, maxOffline time.Duration, maxEvidence int, validUntil time.Time) (LocalPolicy, error) {
	siteID = strings.TrimSpace(siteID)
	projectID = strings.TrimSpace(projectID)
	desiredDigest = strings.TrimSpace(desiredDigest)
	if siteID == "" || projectID == "" || revision <= 0 {
		return LocalPolicy{}, errors.New("siteId, projectId and positive revision are required")
	}
	if !sha256Pattern.MatchString(desiredDigest) {
		return LocalPolicy{}, errors.New("desiredStateDigest must be an exact sha256 digest")
	}
	if maxOffline <= 0 || maxOffline > 30*24*time.Hour {
		return LocalPolicy{}, errors.New("maxOfflineDuration must be positive and no more than 30 days")
	}
	if maxEvidence < 1 || maxEvidence > 100000 {
		return LocalPolicy{}, errors.New("maxQueuedEvidenceItems is outside the bounded range")
	}
	if validUntil.IsZero() {
		return LocalPolicy{}, errors.New("validUntil is required")
	}
	seen := map[Action]bool{}
	canonical := make([]Action, 0, len(actions))
	for _, action := range actions {
		if !allowedAction(action) {
			return LocalPolicy{}, fmt.Errorf("action %q is not admitted for site-local authority", action)
		}
		if !seen[action] {
			seen[action] = true
			canonical = append(canonical, action)
		}
	}
	if len(canonical) == 0 {
		return LocalPolicy{}, errors.New("at least one bounded local action is required")
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	raw, err := json.Marshal([]any{Authority, siteID, projectID, revision, desiredDigest, canonical, maxOffline.Nanoseconds(), maxEvidence, validUntil.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return LocalPolicy{}, err
	}
	sum := sha256.Sum256(raw)
	return LocalPolicy{
		Authority: Authority, SiteID: siteID, ProjectID: projectID, Revision: revision,
		DesiredStateDigest: desiredDigest, PolicyDigest: "sha256:" + hex.EncodeToString(sum[:]),
		AllowedActions: canonical, MaxOfflineDuration: maxOffline, MaxQueuedEvidenceItems: maxEvidence,
		ValidUntil: validUntil.UTC(),
	}, nil
}

func AdmitOfflineMutation(policy LocalPolicy, request MutationRequest, now, disconnectedSince time.Time) error {
	if policy.Authority != Authority || !sha256Pattern.MatchString(policy.PolicyDigest) {
		return errors.New("edge local policy authority is invalid")
	}
	if request.SiteID != policy.SiteID || request.ProjectID != policy.ProjectID {
		return errors.New("mutation is outside the site/project authority")
	}
	if request.BaseRevision != policy.Revision || request.BaseDesiredDigest != policy.DesiredStateDigest || request.PolicyDigest != policy.PolicyDigest {
		return errors.New("mutation base revision/digest does not match the admitted central policy")
	}
	if strings.TrimSpace(request.TargetRef) == "" || strings.TrimSpace(request.IdempotencyKey) == "" || !sha256Pattern.MatchString(strings.TrimSpace(request.RequestDigest)) {
		return errors.New("targetRef, idempotencyKey and exact requestDigest are required")
	}
	if now.After(policy.ValidUntil) {
		return errors.New("edge local policy has expired")
	}
	if disconnectedSince.IsZero() || now.Before(disconnectedSince) || now.Sub(disconnectedSince) > policy.MaxOfflineDuration {
		return errors.New("offline authority window is not admitted")
	}
	permitted := false
	for _, action := range policy.AllowedActions {
		if action == request.Action {
			permitted = true
			break
		}
	}
	if !permitted {
		return fmt.Errorf("action %q is not admitted by the site-local policy", request.Action)
	}
	return nil
}

func ResolveReconnect(request MutationRequest, centralRevision int64, centralDesiredDigest string) ReconnectDecision {
	centralDesiredDigest = strings.TrimSpace(centralDesiredDigest)
	if centralRevision <= 0 || !sha256Pattern.MatchString(centralDesiredDigest) {
		return ReconnectDecision{State: ConflictRejected, AutomaticApply: false, CentralRevision: centralRevision, CentralDesiredDigest: centralDesiredDigest, Message: "central authority readback is invalid"}
	}
	if request.BaseRevision != centralRevision || request.BaseDesiredDigest != centralDesiredDigest {
		return ReconnectDecision{State: ConflictReviewRequired, AutomaticApply: false, CentralRevision: centralRevision, CentralDesiredDigest: centralDesiredDigest, Message: "central authority advanced while the site was disconnected; explicit reconciliation is required"}
	}
	return ReconnectDecision{State: ConflictNone, AutomaticApply: true, CentralRevision: centralRevision, CentralDesiredDigest: centralDesiredDigest}
}

func AssessBootClaim(claim BootClaim) BootAssessment {
	result := BootAssessment{Authority: BootAttestationAuthority, NodeID: strings.TrimSpace(claim.NodeID), State: BootRejected}
	if claim.Authority != BootAttestationAuthority || strings.TrimSpace(claim.SiteID) == "" || result.NodeID == "" || claim.ObservedAt.IsZero() {
		result.Message = "boot attestation identity is incomplete"
		return result
	}
	for _, digest := range []string{claim.QuoteDigest, claim.EventLogDigest, claim.EvidenceDigest} {
		if !sha256Pattern.MatchString(strings.TrimSpace(digest)) {
			result.Message = "boot attestation digest evidence is incomplete"
			return result
		}
	}
	if !claim.TPMPresent || !claim.SecureBootEnabled || !claim.MeasuredBootPresent || !claim.DiskEncryptionVerified ||
		!claim.QuoteVerified || !claim.NonceBound || !claim.PCRPolicyMatched {
		result.Message = "boot security evidence does not satisfy the admitted attestation policy"
		return result
	}
	result.State = BootAttested
	return result
}

func ValidateLocalAIProfile(profile LocalAIProfile) error {
	if profile.Authority != LocalAIProfileAuthority || profile.Mode != "disconnected" {
		return errors.New("local AI profile authority/mode is invalid")
	}
	if strings.TrimSpace(profile.Runtime) == "" {
		return errors.New("local AI runtime identity is required")
	}
	if !sha256Pattern.MatchString(strings.TrimSpace(profile.ModelDigest)) || !sha256Pattern.MatchString(strings.TrimSpace(profile.RuntimeImageDigest)) {
		return errors.New("local AI model and runtime image must be exact sha256 digests")
	}
	if profile.NetworkEgress || profile.RawCredentials || profile.ExternalProvider {
		return errors.New("disconnected local AI profile cannot use network egress, raw credentials or external providers")
	}
	if profile.MaxPromptBytes < 1024 || profile.MaxPromptBytes > 4*1024*1024 || profile.MaxOutputBytes < 1024 || profile.MaxOutputBytes > 4*1024*1024 {
		return errors.New("local AI prompt/output bounds are invalid")
	}
	return nil
}
