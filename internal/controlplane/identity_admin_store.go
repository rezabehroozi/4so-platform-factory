package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const KeycloakSAMLBrokerAuthority = "KEYCLOAK_SAML_BROKER_AUTHORITY_V1"
const IdentityAdminJobAuthority = "IDENTITY_ADMIN_JOB_AUTHORITY_V1"

var samlBrokerAliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type SAMLBrokerState string

const (
	SAMLBrokerPendingApproval SAMLBrokerState = "PENDING_APPROVAL"
	SAMLBrokerQueued          SAMLBrokerState = "QUEUED"
	SAMLBrokerReconciling     SAMLBrokerState = "RECONCILING"
	SAMLBrokerReady           SAMLBrokerState = "READY"
	SAMLBrokerError           SAMLBrokerState = "ERROR"
	SAMLBrokerDeleting        SAMLBrokerState = "DELETING"
	SAMLBrokerDeleted         SAMLBrokerState = "DELETED"
)

type SAMLBroker struct {
	ResourceMeta
	OrganizationID          string          `json:"organizationId"`
	Alias                   string          `json:"alias"`
	KeycloakAlias           string          `json:"keycloakAlias"`
	DisplayName             string          `json:"displayName"`
	EntityID                string          `json:"entityId"`
	SingleSignOnServiceURL  string          `json:"singleSignOnServiceUrl"`
	SingleLogoutServiceURL  string          `json:"singleLogoutServiceUrl,omitempty"`
	SigningCertificate      string          `json:"signingCertificate"` // canonical base64 DER; public trust material, never a private key
	NameIDPolicyFormat      string          `json:"nameIdPolicyFormat"`
	WantAuthnRequestsSigned bool            `json:"wantAuthnRequestsSigned"`
	Enabled                 bool            `json:"enabled"`
	State                   SAMLBrokerState `json:"state"`
	DesiredDigest           string          `json:"desiredDigest"`
	ObservedDigest          string          `json:"observedDigest,omitempty"`
	RequestedBy             string          `json:"requestedBy"`
	LastError               string          `json:"lastError,omitempty"`
}

type IdentityAdminJobKind string

type IdentityAdminJobState string

const (
	IdentityAdminUpsertSAML IdentityAdminJobKind = "UPSERT_SAML_BROKER"
	IdentityAdminDeleteSAML IdentityAdminJobKind = "DELETE_SAML_BROKER"

	IdentityAdminAwaitingApproval IdentityAdminJobState = "AWAITING_APPROVAL"
	IdentityAdminQueued           IdentityAdminJobState = "QUEUED"
	IdentityAdminRunning          IdentityAdminJobState = "RUNNING"
	IdentityAdminSucceeded        IdentityAdminJobState = "SUCCEEDED"
	IdentityAdminFailed           IdentityAdminJobState = "FAILED"
)

type IdentityAdminJob struct {
	ResourceMeta
	OrganizationID     string                `json:"organizationId"`
	BrokerID           string                `json:"brokerId"`
	BrokerRevision     int64                 `json:"brokerRevision"`
	Kind               IdentityAdminJobKind  `json:"kind"`
	State              IdentityAdminJobState `json:"state"`
	IdempotencyKey     string                `json:"idempotencyKey"`
	RequestDigest      string                `json:"requestDigest"`
	DesiredDigest      string                `json:"desiredDigest"`
	RequestedBy        string                `json:"requestedBy"`
	ApprovedBy         string                `json:"approvedBy,omitempty"`
	ApprovedAt         *time.Time            `json:"approvedAt,omitempty"`
	TaskAttempt        int                   `json:"taskAttempt"`
	TaskFenceToken     int64                 `json:"taskFenceToken"`
	TaskLeaseOwner     string                `json:"taskLeaseOwner,omitempty"`
	TaskLeaseExpiresAt *time.Time            `json:"taskLeaseExpiresAt,omitempty"`
	StartedAt          *time.Time            `json:"startedAt,omitempty"`
	FinishedAt         *time.Time            `json:"finishedAt,omitempty"`
	EvidenceDigest     string                `json:"evidenceDigest,omitempty"`
	LastError          string                `json:"lastError,omitempty"`
}

type IdentityAdminTask struct {
	Job          IdentityAdminJob `json:"job"`
	Broker       SAMLBroker       `json:"broker"`
	FenceToken   int64            `json:"fenceToken"`
	LeaseExpires time.Time        `json:"leaseExpiresAt"`
}

func NormalizeSAMLBroker(v SAMLBroker) (SAMLBroker, error) {
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.Alias = strings.ToLower(strings.TrimSpace(v.Alias))
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	v.EntityID = strings.TrimSpace(v.EntityID)
	v.SingleSignOnServiceURL = strings.TrimSpace(v.SingleSignOnServiceURL)
	v.SingleLogoutServiceURL = strings.TrimSpace(v.SingleLogoutServiceURL)
	v.NameIDPolicyFormat = strings.TrimSpace(v.NameIDPolicyFormat)
	if v.NameIDPolicyFormat == "" {
		v.NameIDPolicyFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	if v.OrganizationID == "" || !samlBrokerAliasRE.MatchString(v.Alias) || v.DisplayName == "" || len(v.DisplayName) > 120 || v.EntityID == "" || len(v.EntityID) > 500 {
		return v, ErrValidation
	}
	for _, rawURL := range []string{v.SingleSignOnServiceURL, v.SingleLogoutServiceURL} {
		if rawURL == "" {
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || strings.TrimSpace(u.Host) == "" || u.User != nil {
			return v, ErrValidation
		}
	}
	cert := strings.TrimSpace(v.SigningCertificate)
	if strings.Contains(cert, "PRIVATE KEY") {
		return v, ErrValidation
	}
	if block, _ := pem.Decode([]byte(cert)); block != nil {
		if block.Type != "CERTIFICATE" {
			return v, ErrValidation
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return v, ErrValidation
		}
		v.SigningCertificate = base64.StdEncoding.EncodeToString(parsed.Raw)
	} else {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return v, ErrValidation
		}
		if _, err = x509.ParseCertificate(raw); err != nil {
			return v, ErrValidation
		}
		v.SigningCertificate = base64.StdEncoding.EncodeToString(raw)
	}
	v.KeycloakAlias = keycloakAliasForOrganization(v.OrganizationID, v.Alias)
	return v, nil
}

func keycloakAliasForOrganization(organizationID, alias string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(organizationID)))
	prefix := hex.EncodeToString(h[:])[:10]
	alias = strings.ToLower(strings.TrimSpace(alias))
	maxAlias := 63 - len(prefix) - 1
	if len(alias) > maxAlias {
		alias = alias[:maxAlias]
	}
	return prefix + "-" + alias
}

func SAMLBrokerDesiredDigest(v SAMLBroker) string {
	raw, _ := json.Marshal(struct {
		Authority, OrganizationID, Alias, KeycloakAlias, DisplayName, EntityID, SSO, SLO, Certificate, NameID string
		WantSigned, Enabled                                                                                   bool
	}{KeycloakSAMLBrokerAuthority, v.OrganizationID, v.Alias, v.KeycloakAlias, v.DisplayName, v.EntityID, v.SingleSignOnServiceURL, v.SingleLogoutServiceURL, v.SigningCertificate, v.NameIDPolicyFormat, v.WantAuthnRequestsSigned, v.Enabled})
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func IdentityAdminEvidenceDigest(job IdentityAdminJob, broker SAMLBroker, observedDigest string) string {
	raw, _ := json.Marshal(struct {
		Authority, JobID, Kind, BrokerID, DesiredDigest, ObservedDigest string
		BrokerRevision                                                  int64
	}{IdentityAdminJobAuthority, job.ID, string(job.Kind), broker.ID, job.DesiredDigest, strings.TrimSpace(observedDigest), job.BrokerRevision})
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *MemoryStore) RequestSAMLBrokerUpsert(_ context.Context, v SAMLBroker, expected int64, idempotencyKey, requestDigest, actor string) (SAMLBroker, IdentityAdminJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var existing SAMLBroker
	isUpdate := strings.TrimSpace(v.ID) != ""
	if isUpdate {
		var ok bool
		existing, ok = s.samlBrokers[v.ID]
		if !ok {
			return v, IdentityAdminJob{}, false, ErrNotFound
		}
		if existing.Revision != expected || existing.State == SAMLBrokerDeleted {
			return v, IdentityAdminJob{}, false, ErrConflict
		}
		if v.OrganizationID == "" {
			v.OrganizationID = existing.OrganizationID
		}
		if v.OrganizationID != existing.OrganizationID {
			return v, IdentityAdminJob{}, false, ErrConflict
		}
	} else if expected != 0 {
		return v, IdentityAdminJob{}, false, ErrValidation
	}
	if _, ok := s.organizations[v.OrganizationID]; !ok {
		return v, IdentityAdminJob{}, false, ErrNotFound
	}
	var err error
	v, err = NormalizeSAMLBroker(v)
	if err != nil {
		return v, IdentityAdminJob{}, false, err
	}
	idempotencyKey, requestDigest, actor = strings.TrimSpace(idempotencyKey), strings.TrimSpace(requestDigest), strings.TrimSpace(actor)
	if idempotencyKey == "" || !validSHA256(requestDigest) || actor == "" {
		return v, IdentityAdminJob{}, false, ErrValidation
	}
	idem := "identityAdmin:" + v.OrganizationID + ":" + idempotencyKey
	if jobID := s.idempotency[idem]; jobID != "" {
		job, ok := s.identityAdminJobs[jobID]
		if !ok || job.RequestDigest != requestDigest {
			return v, IdentityAdminJob{}, false, ErrConflict
		}
		broker := s.samlBrokers[job.BrokerID]
		return broker, job, true, nil
	}
	for _, other := range s.samlBrokers {
		if other.ID != v.ID && other.State != SAMLBrokerDeleted && other.KeycloakAlias == v.KeycloakAlias {
			return v, IdentityAdminJob{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	if isUpdate {
		v.ResourceMeta = existing.ResourceMeta
		v.Revision++
		v.UpdatedAt = now
	} else {
		v.ResourceMeta = ResourceMeta{ID: s.id("saml"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	v.State = SAMLBrokerPendingApproval
	v.DesiredDigest = SAMLBrokerDesiredDigest(v)
	v.ObservedDigest = ""
	v.RequestedBy = actor
	v.LastError = ""
	job := IdentityAdminJob{ResourceMeta: ResourceMeta{ID: s.id("idjob"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OrganizationID: v.OrganizationID, BrokerID: v.ID, BrokerRevision: v.Revision, Kind: IdentityAdminUpsertSAML, State: IdentityAdminAwaitingApproval, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, DesiredDigest: v.DesiredDigest, RequestedBy: actor}
	s.samlBrokers[v.ID] = v
	s.identityAdminJobs[job.ID] = job
	s.idempotency[idem] = job.ID
	s.appendAuditLocked(actor, "saml_broker.change_requested", "samlBroker", v.ID, v.Revision, map[string]any{"jobId": job.ID, "desiredDigest": v.DesiredDigest, "authority": KeycloakSAMLBrokerAuthority})
	s.appendOutboxLocked("identityAdminJob", job.ID, "identity_admin.requested", job)
	return v, job, false, nil
}

func (s *MemoryStore) RequestSAMLBrokerDelete(_ context.Context, id string, expected int64, idempotencyKey, requestDigest, actor string) (SAMLBroker, IdentityAdminJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.samlBrokers[strings.TrimSpace(id)]
	if !ok {
		return v, IdentityAdminJob{}, false, ErrNotFound
	}
	if v.Revision != expected || v.State == SAMLBrokerDeleted {
		return v, IdentityAdminJob{}, false, ErrConflict
	}
	idempotencyKey, requestDigest, actor = strings.TrimSpace(idempotencyKey), strings.TrimSpace(requestDigest), strings.TrimSpace(actor)
	if idempotencyKey == "" || !validSHA256(requestDigest) || actor == "" {
		return v, IdentityAdminJob{}, false, ErrValidation
	}
	idem := "identityAdmin:" + v.OrganizationID + ":" + idempotencyKey
	if jobID := s.idempotency[idem]; jobID != "" {
		job, ok := s.identityAdminJobs[jobID]
		if !ok || job.RequestDigest != requestDigest {
			return v, IdentityAdminJob{}, false, ErrConflict
		}
		return s.samlBrokers[job.BrokerID], job, true, nil
	}
	now := nowUTC(s.now)
	v.Revision++
	v.UpdatedAt = now
	v.State = SAMLBrokerPendingApproval
	v.RequestedBy = actor
	v.LastError = ""
	job := IdentityAdminJob{ResourceMeta: ResourceMeta{ID: s.id("idjob"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OrganizationID: v.OrganizationID, BrokerID: v.ID, BrokerRevision: v.Revision, Kind: IdentityAdminDeleteSAML, State: IdentityAdminAwaitingApproval, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, DesiredDigest: v.DesiredDigest, RequestedBy: actor}
	s.samlBrokers[v.ID] = v
	s.identityAdminJobs[job.ID] = job
	s.idempotency[idem] = job.ID
	s.appendAuditLocked(actor, "saml_broker.delete_requested", "samlBroker", v.ID, v.Revision, map[string]any{"jobId": job.ID, "authority": KeycloakSAMLBrokerAuthority})
	s.appendOutboxLocked("identityAdminJob", job.ID, "identity_admin.requested", job)
	return v, job, false, nil
}

func (s *MemoryStore) GetSAMLBroker(_ context.Context, id string) (SAMLBroker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.samlBrokers[strings.TrimSpace(id)]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListSAMLBrokers(_ context.Context, organizationID string) ([]SAMLBroker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []SAMLBroker{}
	for _, v := range s.samlBrokers {
		if organizationID == "" || v.OrganizationID == organizationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) GetIdentityAdminJob(_ context.Context, id string) (IdentityAdminJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.identityAdminJobs[strings.TrimSpace(id)]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListIdentityAdminJobs(_ context.Context, organizationID string) ([]IdentityAdminJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []IdentityAdminJob{}
	for _, v := range s.identityAdminJobs {
		if organizationID == "" || v.OrganizationID == organizationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) ApproveIdentityAdminJob(_ context.Context, id string, expected int64, actor string) (IdentityAdminJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.identityAdminJobs[strings.TrimSpace(id)]
	if !ok {
		return v, ErrNotFound
	}
	actor = strings.TrimSpace(actor)
	if v.Revision != expected {
		return v, ErrConflict
	}
	if v.State != IdentityAdminAwaitingApproval || actor == "" || actor == v.RequestedBy {
		return v, ErrPrerequisite
	}
	broker, ok := s.samlBrokers[v.BrokerID]
	if !ok || broker.Revision != v.BrokerRevision || broker.DesiredDigest != v.DesiredDigest {
		return v, ErrConflict
	}
	now := nowUTC(s.now)
	v.State = IdentityAdminQueued
	v.ApprovedBy = actor
	t := now
	v.ApprovedAt = &t
	v.Revision++
	v.UpdatedAt = now
	broker.State = SAMLBrokerQueued
	broker.UpdatedAt = now
	s.identityAdminJobs[v.ID] = v
	s.samlBrokers[broker.ID] = broker
	s.appendAuditLocked(actor, "identity_admin.approved", "identityAdminJob", v.ID, v.Revision, map[string]any{"brokerId": v.BrokerID})
	s.appendOutboxLocked("identityAdminJob", v.ID, "identity_admin.approved", v)
	return v, nil
}

func (s *MemoryStore) ClaimIdentityAdminTask(_ context.Context, owner string, lease time.Duration, now time.Time) (IdentityAdminTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner = strings.TrimSpace(owner)
	if owner == "" || lease <= 0 {
		return IdentityAdminTask{}, ErrValidation
	}
	now = now.UTC()
	var selected *IdentityAdminJob
	for _, candidate := range s.identityAdminJobs {
		if candidate.State != IdentityAdminQueued && candidate.State != IdentityAdminRunning {
			continue
		}
		if candidate.TaskLeaseExpiresAt != nil && candidate.TaskLeaseExpiresAt.After(now) && candidate.TaskLeaseOwner != owner {
			continue
		}
		c := candidate
		if selected == nil || c.CreatedAt.Before(selected.CreatedAt) {
			selected = &c
		}
	}
	if selected == nil {
		return IdentityAdminTask{}, ErrNotFound
	}
	v := *selected
	broker, ok := s.samlBrokers[v.BrokerID]
	if !ok || broker.Revision != v.BrokerRevision || broker.DesiredDigest != v.DesiredDigest {
		return IdentityAdminTask{}, ErrConflict
	}
	v.State = IdentityAdminRunning
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseOwner = owner
	until := now.Add(lease)
	v.TaskLeaseExpiresAt = &until
	if v.StartedAt == nil {
		t := now
		v.StartedAt = &t
	}
	v.Revision++
	v.UpdatedAt = now
	broker.State = SAMLBrokerReconciling
	if v.Kind == IdentityAdminDeleteSAML {
		broker.State = SAMLBrokerDeleting
	}
	broker.UpdatedAt = now
	s.identityAdminJobs[v.ID] = v
	s.samlBrokers[broker.ID] = broker
	return IdentityAdminTask{Job: v, Broker: broker, FenceToken: v.TaskFenceToken, LeaseExpires: until}, nil
}

func (s *MemoryStore) CompleteIdentityAdminTask(_ context.Context, id, owner string, fence int64, observedDigest, actor string) (IdentityAdminJob, SAMLBroker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.identityAdminJobs[strings.TrimSpace(id)]
	if !ok {
		return job, SAMLBroker{}, ErrNotFound
	}
	broker, ok := s.samlBrokers[job.BrokerID]
	if !ok {
		return job, broker, ErrNotFound
	}
	if job.State != IdentityAdminRunning || job.TaskLeaseOwner != owner || job.TaskFenceToken != fence || broker.Revision != job.BrokerRevision {
		return job, broker, ErrConflict
	}
	observedDigest = strings.TrimSpace(observedDigest)
	if !validSHA256(observedDigest) {
		return job, broker, ErrValidation
	}
	now := nowUTC(s.now)
	job.State = IdentityAdminSucceeded
	job.TaskLeaseOwner = ""
	job.TaskLeaseExpiresAt = nil
	job.EvidenceDigest = IdentityAdminEvidenceDigest(job, broker, observedDigest)
	t := now
	job.FinishedAt = &t
	job.Revision++
	job.UpdatedAt = now
	broker.ObservedDigest = observedDigest
	broker.LastError = ""
	if job.Kind == IdentityAdminDeleteSAML {
		broker.State = SAMLBrokerDeleted
	} else {
		broker.State = SAMLBrokerReady
	}
	broker.UpdatedAt = now
	s.identityAdminJobs[job.ID] = job
	s.samlBrokers[broker.ID] = broker
	s.appendAuditLocked(actor, "identity_admin.completed", "identityAdminJob", job.ID, job.Revision, map[string]any{"brokerId": broker.ID, "evidenceDigest": job.EvidenceDigest})
	s.appendOutboxLocked("identityAdminJob", job.ID, "identity_admin.completed", job)
	return job, broker, nil
}

func (s *MemoryStore) FailIdentityAdminTask(_ context.Context, id, owner string, fence int64, message, actor string) (IdentityAdminJob, SAMLBroker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.identityAdminJobs[strings.TrimSpace(id)]
	if !ok {
		return job, SAMLBroker{}, ErrNotFound
	}
	broker, ok := s.samlBrokers[job.BrokerID]
	if !ok {
		return job, broker, ErrNotFound
	}
	if job.State != IdentityAdminRunning || job.TaskLeaseOwner != owner || job.TaskFenceToken != fence {
		return job, broker, ErrConflict
	}
	message = strings.TrimSpace(message)
	if len(message) > 1000 {
		message = message[:1000]
	}
	now := nowUTC(s.now)
	job.State = IdentityAdminFailed
	job.LastError = message
	job.TaskLeaseOwner = ""
	job.TaskLeaseExpiresAt = nil
	t := now
	job.FinishedAt = &t
	job.Revision++
	job.UpdatedAt = now
	broker.State = SAMLBrokerError
	broker.LastError = message
	broker.UpdatedAt = now
	s.identityAdminJobs[job.ID] = job
	s.samlBrokers[broker.ID] = broker
	s.appendAuditLocked(actor, "identity_admin.failed", "identityAdminJob", job.ID, job.Revision, map[string]any{"brokerId": broker.ID, "reason": message})
	return job, broker, nil
}

func ValidateIdentityAdminSnapshot(organizations map[string]Organization, brokers []SAMLBroker, jobs []IdentityAdminJob) error {
	brokerByID := make(map[string]SAMLBroker, len(brokers))
	for _, broker := range brokers {
		if _, ok := organizations[broker.OrganizationID]; !ok {
			return fmt.Errorf("%w: SAML broker organization %q is missing", ErrValidation, broker.OrganizationID)
		}
		normalized, err := NormalizeSAMLBroker(broker)
		if err != nil || normalized.KeycloakAlias != broker.KeycloakAlias || SAMLBrokerDesiredDigest(normalized) != broker.DesiredDigest {
			return fmt.Errorf("%w: invalid SAML broker %q", ErrValidation, broker.ID)
		}
		brokerByID[broker.ID] = broker
	}
	for _, job := range jobs {
		broker, ok := brokerByID[job.BrokerID]
		if !ok || broker.OrganizationID != job.OrganizationID || !validSHA256(job.RequestDigest) || !validSHA256(job.DesiredDigest) {
			return fmt.Errorf("%w: invalid identity admin job %q", ErrValidation, job.ID)
		}
		if job.ApprovedBy != "" && job.ApprovedBy == job.RequestedBy {
			return fmt.Errorf("%w: identity admin self-approval %q", ErrValidation, job.ID)
		}
	}
	return nil
}
