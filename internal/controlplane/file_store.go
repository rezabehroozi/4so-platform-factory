package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"platform.4so.io/factory/internal/durablefile"
)

// FileStore is a single-process development durability adapter. It atomically
// persists a checksummed authoritative snapshot after each successful mutation.
// Production deployments use the PostgreSQL authority defined in migrations/.
type FileStore struct {
	*MemoryStore
	path    string
	writeMu sync.Mutex
}

type stateEnvelope struct {
	SchemaVersion int                               `json:"schemaVersion"`
	Checksum      string                            `json:"checksum"`
	Snapshot      Snapshot                          `json:"snapshot"`
	Credentials   []ClusterImportCredentialSnapshot `json:"clusterImportCredentials,omitempty"`
}

type stateChecksumPayload struct {
	Snapshot    Snapshot                          `json:"snapshot"`
	Credentials []ClusterImportCredentialSnapshot `json:"clusterImportCredentials,omitempty"`
}

func snapshotChecksum(s Snapshot) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func stateChecksum(s Snapshot, credentials []ClusterImportCredentialSnapshot) (string, error) {
	raw, err := json.Marshal(stateChecksumPayload{Snapshot: s, Credentials: credentials})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func OpenFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("state path is required")
	}
	m := NewMemoryStore()
	f := &FileStore{MemoryStore: m, path: path}
	raw, err := os.ReadFile(path)
	if err == nil {
		var env stateEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("decode state envelope: %w", err)
		}
		var checksum string
		switch env.SchemaVersion {
		case 1:
			checksum, err = snapshotChecksum(env.Snapshot)
			// Schema v1 never persisted enrollment/agent credential digests because
			// those fields are intentionally excluded from normal resource JSON.
			// They cannot be reconstructed. Mark claimed clusters explicitly so the
			// operator sees the one-time re-enrollment requirement instead of an
			// unexplained post-restart 401. PostgreSQL production state is unaffected.
			claimed := map[string]struct{}{}
			for _, imp := range env.Snapshot.ClusterImports {
				if imp.State == ClusterImportClaimed && imp.ClusterID != "" {
					claimed[imp.ClusterID] = struct{}{}
				}
			}
			for i := range env.Snapshot.ManagedClusters {
				if _, ok := claimed[env.Snapshot.ManagedClusters[i].ID]; ok {
					env.Snapshot.ManagedClusters[i].ConnectionState = "REENROLLMENT_REQUIRED"
				}
			}
		case 2:
			checksum, err = stateChecksum(env.Snapshot, env.Credentials)
			env.Snapshot.ClusterImportCredentials = append([]ClusterImportCredentialSnapshot(nil), env.Credentials...)
		default:
			return nil, fmt.Errorf("unsupported state schema version %d", env.SchemaVersion)
		}
		if err != nil {
			return nil, err
		}
		if checksum != env.Checksum {
			return nil, fmt.Errorf("state snapshot checksum mismatch")
		}
		if err := m.Restore(env.Snapshot); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return f, nil
}

func (f *FileStore) persist(ctx context.Context) error {
	snap, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return err
	}
	credentials := append([]ClusterImportCredentialSnapshot(nil), snap.ClusterImportCredentials...)
	checksum, err := stateChecksum(snap, credentials)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(stateEnvelope{SchemaVersion: 2, Checksum: checksum, Snapshot: snap, Credentials: credentials}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return durablefile.Replace(f.path, raw, 0o750, 0o600)
}

func mutate[T any](f *FileStore, ctx context.Context, fn func() (T, error)) (T, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	v, err := fn()
	if err != nil {
		return v, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return v, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return v, nil
}
func mutate2[A any, B any](f *FileStore, ctx context.Context, fn func() (A, B, error)) (A, B, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		var a A
		var b B
		return a, b, err
	}
	a, b, err := fn()
	if err != nil {
		return a, b, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return a, b, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return a, b, nil
}

func mutateErr(f *FileStore, ctx context.Context, fn func() error) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	if err := f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return nil
}

func (f *FileStore) CreateOrganization(ctx context.Context, v Organization, a string) (Organization, error) {
	return mutate(f, ctx, func() (Organization, error) { return f.MemoryStore.CreateOrganization(ctx, v, a) })
}
func (f *FileStore) UpdateOrganization(ctx context.Context, id string, rev int64, d, n, a string) (Organization, error) {
	return mutate(f, ctx, func() (Organization, error) { return f.MemoryStore.UpdateOrganization(ctx, id, rev, d, n, a) })
}
func (f *FileStore) CreateProject(ctx context.Context, v Project, a string) (Project, error) {
	return mutate(f, ctx, func() (Project, error) { return f.MemoryStore.CreateProject(ctx, v, a) })
}
func (f *FileStore) UpsertOrganizationMembership(ctx context.Context, v OrganizationMembership, expected int64, a string) (OrganizationMembership, error) {
	return mutate(f, ctx, func() (OrganizationMembership, error) {
		return f.MemoryStore.UpsertOrganizationMembership(ctx, v, expected, a)
	})
}
func (f *FileStore) RevokeOrganizationMembership(ctx context.Context, org, subject string, rev int64, a string) (OrganizationMembership, error) {
	return mutate(f, ctx, func() (OrganizationMembership, error) {
		return f.MemoryStore.RevokeOrganizationMembership(ctx, org, subject, rev, a)
	})
}
func (f *FileStore) CreateBlueprintOverlay(ctx context.Context, v BlueprintOverlay, a string) (BlueprintOverlay, error) {
	return mutate(f, ctx, func() (BlueprintOverlay, error) { return f.MemoryStore.CreateBlueprintOverlay(ctx, v, a) })
}
func (f *FileStore) CreateBlueprintRevision(ctx context.Context, v BlueprintRevision, a string) (BlueprintRevision, error) {
	return mutate(f, ctx, func() (BlueprintRevision, error) { return f.MemoryStore.CreateBlueprintRevision(ctx, v, a) })
}
func (f *FileStore) CreateBlueprintReleaseWithRevision(ctx context.Context, revision BlueprintRevision, release BlueprintRelease, actor string) (BlueprintRevision, BlueprintRelease, error) {
	return mutate2(f, ctx, func() (BlueprintRevision, BlueprintRelease, error) {
		return f.MemoryStore.CreateBlueprintReleaseWithRevision(ctx, revision, release, actor)
	})
}
func (f *FileStore) UpdateBlueprintReleaseDraftWithRevision(ctx context.Context, id string, expected int64, revision BlueprintRevision, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (BlueprintRevision, BlueprintRelease, error) {
	return mutate2(f, ctx, func() (BlueprintRevision, BlueprintRelease, error) {
		return f.MemoryStore.UpdateBlueprintReleaseDraftWithRevision(ctx, id, expected, revision, executionReady, planStatus, upgradeFromIDs, actor)
	})
}
func (f *FileStore) CreateBlueprintRelease(ctx context.Context, v BlueprintRelease, a string) (BlueprintRelease, error) {
	return mutate(f, ctx, func() (BlueprintRelease, error) { return f.MemoryStore.CreateBlueprintRelease(ctx, v, a) })
}
func (f *FileStore) UpdateBlueprintReleaseDraft(ctx context.Context, id string, rev int64, revisionID, blueprintDigest, catalogDigest string, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (BlueprintRelease, error) {
	return mutate(f, ctx, func() (BlueprintRelease, error) {
		return f.MemoryStore.UpdateBlueprintReleaseDraft(ctx, id, rev, revisionID, blueprintDigest, catalogDigest, executionReady, planStatus, upgradeFromIDs, actor)
	})
}
func (f *FileStore) TransitionBlueprintRelease(ctx context.Context, id string, rev int64, to BlueprintLifecycleState, actor string) (BlueprintRelease, error) {
	return mutate(f, ctx, func() (BlueprintRelease, error) {
		return f.MemoryStore.TransitionBlueprintRelease(ctx, id, rev, to, actor)
	})
}
func (f *FileStore) CreateCatalogTrustKey(ctx context.Context, v CatalogTrustKey, a string) (CatalogTrustKey, error) {
	return mutate(f, ctx, func() (CatalogTrustKey, error) { return f.MemoryStore.CreateCatalogTrustKey(ctx, v, a) })
}
func (f *FileStore) RevokeCatalogTrustKey(ctx context.Context, id string, rev int64, a string) (CatalogTrustKey, error) {
	return mutate(f, ctx, func() (CatalogTrustKey, error) { return f.MemoryStore.RevokeCatalogTrustKey(ctx, id, rev, a) })
}
func (f *FileStore) CreateCatalogRevision(ctx context.Context, v CatalogRevision, a string) (CatalogRevision, error) {
	return mutate(f, ctx, func() (CatalogRevision, error) { return f.MemoryStore.CreateCatalogRevision(ctx, v, a) })
}
func (f *FileStore) CreateCatalogReleaseWithRevision(ctx context.Context, revision CatalogRevision, release CatalogRelease, actor string) (CatalogRevision, CatalogRelease, error) {
	return mutate2(f, ctx, func() (CatalogRevision, CatalogRelease, error) {
		return f.MemoryStore.CreateCatalogReleaseWithRevision(ctx, revision, release, actor)
	})
}
func (f *FileStore) UpdateCatalogReleaseDraftWithRevision(ctx context.Context, id string, expected int64, revision CatalogRevision, actor string) (CatalogRevision, CatalogRelease, error) {
	return mutate2(f, ctx, func() (CatalogRevision, CatalogRelease, error) {
		return f.MemoryStore.UpdateCatalogReleaseDraftWithRevision(ctx, id, expected, revision, actor)
	})
}
func (f *FileStore) CreateCatalogRelease(ctx context.Context, v CatalogRelease, a string) (CatalogRelease, error) {
	return mutate(f, ctx, func() (CatalogRelease, error) { return f.MemoryStore.CreateCatalogRelease(ctx, v, a) })
}
func (f *FileStore) UpdateCatalogReleaseDraft(ctx context.Context, id string, rev int64, revisionID, manifestDigest, actor string) (CatalogRelease, error) {
	return mutate(f, ctx, func() (CatalogRelease, error) {
		return f.MemoryStore.UpdateCatalogReleaseDraft(ctx, id, rev, revisionID, manifestDigest, actor)
	})
}
func (f *FileStore) SubmitCatalogReleaseReview(ctx context.Context, id string, rev int64, keyID, fingerprint, signature, actor string) (CatalogRelease, error) {
	return mutate(f, ctx, func() (CatalogRelease, error) {
		return f.MemoryStore.SubmitCatalogReleaseReview(ctx, id, rev, keyID, fingerprint, signature, actor)
	})
}
func (f *FileStore) TransitionCatalogRelease(ctx context.Context, id string, rev int64, to CatalogLifecycleState, actor string) (CatalogRelease, error) {
	return mutate(f, ctx, func() (CatalogRelease, error) { return f.MemoryStore.TransitionCatalogRelease(ctx, id, rev, to, actor) })
}
func (f *FileStore) CreateAssignment(ctx context.Context, v Assignment, a string) (Assignment, error) {
	return mutate(f, ctx, func() (Assignment, error) { return f.MemoryStore.CreateAssignment(ctx, v, a) })
}
func (f *FileStore) UpdateAssignment(ctx context.Context, id string, rev int64, rid string, g int64, a string) (Assignment, error) {
	return mutate(f, ctx, func() (Assignment, error) { return f.MemoryStore.UpdateAssignment(ctx, id, rev, rid, g, a) })
}
func (f *FileStore) CreateOperation(ctx context.Context, r OperationRequest, k, a, q string) (Operation, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return Operation{}, false, err
	}
	v, replay, err := f.MemoryStore.CreateOperation(ctx, r, k, a, q)
	if err != nil {
		return v, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
			return v, replay, fmt.Errorf("persist authoritative snapshot: %w", err)
		}
	}
	return v, replay, nil
}
func (f *FileStore) TransitionOperation(ctx context.Context, id string, rev int64, to OperationState, e, a string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) { return f.MemoryStore.TransitionOperation(ctx, id, rev, to, e, a) })
}
func (f *FileStore) ClaimOperation(ctx context.Context, id, w string, ttl time.Duration, at time.Time) (ClaimResult, error) {
	return mutate(f, ctx, func() (ClaimResult, error) { return f.MemoryStore.ClaimOperation(ctx, id, w, ttl, at) })
}
func (f *FileStore) RenewOperationLease(ctx context.Context, id, w string, fence int64, ttl time.Duration, at time.Time) (ClaimResult, error) {
	return mutate(f, ctx, func() (ClaimResult, error) { return f.MemoryStore.RenewOperationLease(ctx, id, w, fence, ttl, at) })
}
func (f *FileStore) ReleaseOperationLease(ctx context.Context, id, w string, fence int64) error {
	return mutateErr(f, ctx, func() error { return f.MemoryStore.ReleaseOperationLease(ctx, id, w, fence) })
}
func (f *FileStore) StartOperationAttempt(ctx context.Context, id string, rev int64, worker string, fence int64, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) {
		return f.MemoryStore.StartOperationAttempt(ctx, id, rev, worker, fence, actor)
	})
}
func (f *FileStore) BeginOperationVerification(ctx context.Context, id string, rev int64, worker string, fence int64, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) {
		return f.MemoryStore.BeginOperationVerification(ctx, id, rev, worker, fence, actor)
	})
}
func (f *FileStore) ReportOperationFailure(ctx context.Context, id string, rev int64, worker string, fence int64, report OperationFailureReport, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) {
		return f.MemoryStore.ReportOperationFailure(ctx, id, rev, worker, fence, report, actor)
	})
}
func (f *FileStore) CompleteOperation(ctx context.Context, id string, rev int64, worker string, fence int64, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) { return f.MemoryStore.CompleteOperation(ctx, id, rev, worker, fence, actor) })
}
func (f *FileStore) RequestOperationCancellation(ctx context.Context, id string, rev int64, actor, reason string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) {
		return f.MemoryStore.RequestOperationCancellation(ctx, id, rev, actor, reason)
	})
}
func (f *FileStore) AcknowledgeOperationCancellation(ctx context.Context, id string, rev int64, worker string, fence int64, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) {
		return f.MemoryStore.AcknowledgeOperationCancellation(ctx, id, rev, worker, fence, actor)
	})
}
func (f *FileStore) SetOperationCompensationPlan(ctx context.Context, id string, rev int64, plan []CompensationPlanStep, actor string) (Operation, []OperationCompensationStep, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return Operation{}, nil, err
	}
	op, steps, err := f.MemoryStore.SetOperationCompensationPlan(ctx, id, rev, plan, actor)
	if err != nil {
		return op, steps, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return op, steps, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return op, steps, nil
}
func (f *FileStore) ListOperationCompensationSteps(ctx context.Context, id string) ([]OperationCompensationStep, error) {
	return f.MemoryStore.ListOperationCompensationSteps(ctx, id)
}
func (f *FileStore) RecordOperationForwardStepCompleted(ctx context.Context, id, stepKey string, rev int64, worker string, fence int64, actor string) (OperationCompensationStep, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return OperationCompensationStep{}, Operation{}, err
	}
	step, op, err := f.MemoryStore.RecordOperationForwardStepCompleted(ctx, id, stepKey, rev, worker, fence, actor)
	if err != nil {
		return step, op, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return step, op, err
	}
	return step, op, nil
}
func (f *FileStore) BeginOperationCompensation(ctx context.Context, id string, rev int64, actor string) (Operation, error) {
	return mutate(f, ctx, func() (Operation, error) { return f.MemoryStore.BeginOperationCompensation(ctx, id, rev, actor) })
}
func (f *FileStore) ClaimNextOperationCompensationStep(ctx context.Context, id, worker string, fence int64, actor string) (OperationCompensationStep, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return OperationCompensationStep{}, Operation{}, err
	}
	step, op, callErr := f.MemoryStore.ClaimNextOperationCompensationStep(ctx, id, worker, fence, actor)
	if callErr != nil && op.ID == "" {
		return step, op, callErr
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return step, op, err
	}
	return step, op, callErr
}
func (f *FileStore) CompleteOperationCompensationStep(ctx context.Context, id, stepKey, worker string, fence int64, evidenceDigest, actor string) (OperationCompensationStep, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return OperationCompensationStep{}, Operation{}, err
	}
	step, op, err := f.MemoryStore.CompleteOperationCompensationStep(ctx, id, stepKey, worker, fence, evidenceDigest, actor)
	if err != nil {
		return step, op, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return step, op, err
	}
	return step, op, nil
}
func (f *FileStore) ReportOperationCompensationStepFailure(ctx context.Context, id, stepKey, worker string, fence int64, failure CompensationStepFailure, actor string) (OperationCompensationStep, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return OperationCompensationStep{}, Operation{}, err
	}
	step, op, err := f.MemoryStore.ReportOperationCompensationStepFailure(ctx, id, stepKey, worker, fence, failure, actor)
	if err != nil {
		return step, op, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return step, op, err
	}
	return step, op, nil
}
func (f *FileStore) AppendOperationStep(ctx context.Context, v OperationStep, a string) (OperationStep, error) {
	return mutate(f, ctx, func() (OperationStep, error) { return f.MemoryStore.AppendOperationStep(ctx, v, a) })
}
func (f *FileStore) AppendOperationStepTrace(ctx context.Context, v OperationStepTraceInput, worker string, fence int64, actor string) (OperationStepTrace, EvidenceMetadata, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return OperationStepTrace{}, EvidenceMetadata{}, err
	}
	trace, evidence, err := f.MemoryStore.AppendOperationStepTrace(ctx, v, worker, fence, actor)
	if err != nil {
		return trace, evidence, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return OperationStepTrace{}, EvidenceMetadata{}, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return trace, evidence, nil
}
func (f *FileStore) ListOperationStepTraces(ctx context.Context, operationID string) ([]OperationStepTrace, error) {
	return f.MemoryStore.ListOperationStepTraces(ctx, operationID)
}
func (f *FileStore) GetEvidencePayload(ctx context.Context, evidenceID string) (EvidenceMetadata, []byte, error) {
	return f.MemoryStore.GetEvidencePayload(ctx, evidenceID)
}
func (f *FileStore) ClaimOutbox(ctx context.Context, w string, l int, ttl time.Duration, at time.Time) ([]OutboxEvent, error) {
	return mutate(f, ctx, func() ([]OutboxEvent, error) { return f.MemoryStore.ClaimOutbox(ctx, w, l, ttl, at) })
}
func (f *FileStore) MarkOutboxPublished(ctx context.Context, id, w string, at time.Time) error {
	return mutateErr(f, ctx, func() error { return f.MemoryStore.MarkOutboxPublished(ctx, id, w, at) })
}
func (f *FileStore) AppendEvidence(ctx context.Context, v EvidenceMetadata, a string) (EvidenceMetadata, error) {
	return mutate(f, ctx, func() (EvidenceMetadata, error) { return f.MemoryStore.AppendEvidence(ctx, v, a) })
}

func (f *FileStore) Backend() string { return "development-file" }

func (f *FileStore) Health(ctx context.Context) error {
	if err := f.MemoryStore.Health(ctx); err != nil {
		return err
	}
	_, err := os.Stat(f.path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f *FileStore) Snapshot(ctx context.Context) (Snapshot, error) {
	return f.MemoryStore.Snapshot(ctx)
}

func (f *FileStore) CreateServiceAccount(ctx context.Context, v ServiceAccount, a string) (ServiceAccount, error) {
	return mutate(f, ctx, func() (ServiceAccount, error) { return f.MemoryStore.CreateServiceAccount(ctx, v, a) })
}
func (f *FileStore) RevokeServiceAccount(ctx context.Context, id string, rev int64, a string) (ServiceAccount, error) {
	return mutate(f, ctx, func() (ServiceAccount, error) { return f.MemoryStore.RevokeServiceAccount(ctx, id, rev, a) })
}
func (f *FileStore) CreateAPIToken(ctx context.Context, v APIToken, a string) (APIToken, error) {
	return mutate(f, ctx, func() (APIToken, error) { return f.MemoryStore.CreateAPIToken(ctx, v, a) })
}
func (f *FileStore) GetAPITokenByIdempotencyKey(ctx context.Context, serviceAccountID, key string) (APIToken, error) {
	return f.MemoryStore.GetAPITokenByIdempotencyKey(ctx, serviceAccountID, key)
}
func (f *FileStore) RevokeAPIToken(ctx context.Context, id string, rev int64, a string) (APIToken, error) {
	return mutate(f, ctx, func() (APIToken, error) { return f.MemoryStore.RevokeAPIToken(ctx, id, rev, a) })
}
func (f *FileStore) RotateAPIToken(ctx context.Context, oldID string, rev int64, replacement APIToken, a string) (APIToken, APIToken, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return APIToken{}, APIToken{}, err
	}
	old, next, err := f.MemoryStore.RotateAPIToken(ctx, oldID, rev, replacement, a)
	if err != nil {
		return old, next, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return old, next, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return old, next, nil
}

func (f *FileStore) CreateNotificationDestination(ctx context.Context, v NotificationDestination, actor string) (NotificationDestination, error) {
	return mutate(f, ctx, func() (NotificationDestination, error) {
		return f.MemoryStore.CreateNotificationDestination(ctx, v, actor)
	})
}
func (f *FileStore) UpdateNotificationDestination(ctx context.Context, id string, rev int64, v NotificationDestination, actor string) (NotificationDestination, error) {
	return mutate(f, ctx, func() (NotificationDestination, error) {
		return f.MemoryStore.UpdateNotificationDestination(ctx, id, rev, v, actor)
	})
}
func (f *FileStore) DisableNotificationDestination(ctx context.Context, id string, rev int64, actor string) (NotificationDestination, error) {
	return mutate(f, ctx, func() (NotificationDestination, error) {
		return f.MemoryStore.DisableNotificationDestination(ctx, id, rev, actor)
	})
}
func (f *FileStore) CreateNotificationRoute(ctx context.Context, v NotificationRoute, actor string) (NotificationRoute, error) {
	return mutate(f, ctx, func() (NotificationRoute, error) { return f.MemoryStore.CreateNotificationRoute(ctx, v, actor) })
}
func (f *FileStore) UpdateNotificationRoute(ctx context.Context, id string, rev int64, v NotificationRoute, actor string) (NotificationRoute, error) {
	return mutate(f, ctx, func() (NotificationRoute, error) {
		return f.MemoryStore.UpdateNotificationRoute(ctx, id, rev, v, actor)
	})
}
func (f *FileStore) RouteNotificationEvent(ctx context.Context, event NotificationEvent, actor string) (NotificationEvent, []NotificationDelivery, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return NotificationEvent{}, nil, false, err
	}
	value, deliveries, duplicate, err := f.MemoryStore.RouteNotificationEvent(ctx, event, actor)
	if err != nil {
		return value, deliveries, duplicate, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return value, deliveries, duplicate, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return value, deliveries, duplicate, nil
}
func (f *FileStore) ClaimNotificationHealthScanLease(ctx context.Context, worker string, ttl time.Duration, at time.Time) (bool, error) {
	// Health-scan leases are ephemeral coordination and intentionally are not
	// persisted into the development snapshot. A process restart may elect a
	// new scanner immediately without changing product authority.
	return f.MemoryStore.ClaimNotificationHealthScanLease(ctx, worker, ttl, at)
}

func (f *FileStore) ClaimNotificationDeliveries(ctx context.Context, worker string, limit int, ttl time.Duration, at time.Time) ([]NotificationDelivery, error) {
	return mutate(f, ctx, func() ([]NotificationDelivery, error) {
		return f.MemoryStore.ClaimNotificationDeliveries(ctx, worker, limit, ttl, at)
	})
}
func (f *FileStore) ReportNotificationDelivery(ctx context.Context, id, worker string, at time.Time, result NotificationDeliveryResult) (NotificationDelivery, NotificationDeliveryAttempt, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return NotificationDelivery{}, NotificationDeliveryAttempt{}, err
	}
	delivery, attempt, err := f.MemoryStore.ReportNotificationDelivery(ctx, id, worker, at, result)
	if err != nil {
		return delivery, attempt, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return delivery, attempt, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return delivery, attempt, nil
}
func (f *FileStore) RetryNotificationDelivery(ctx context.Context, id string, rev int64, actor string) (NotificationDelivery, error) {
	return mutate(f, ctx, func() (NotificationDelivery, error) {
		return f.MemoryStore.RetryNotificationDelivery(ctx, id, rev, actor)
	})
}

func (f *FileStore) CreateGitCredential(ctx context.Context, v GitCredential, a string) (GitCredential, error) {
	return mutate(f, ctx, func() (GitCredential, error) { return f.MemoryStore.CreateGitCredential(ctx, v, a) })
}
func (f *FileStore) RotateGitCredential(ctx context.Context, id string, rev int64, v GitCredential, a string) (GitCredential, GitCredential, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return GitCredential{}, GitCredential{}, err
	}
	old, repl, err := f.MemoryStore.RotateGitCredential(ctx, id, rev, v, a)
	if err != nil {
		return old, repl, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return old, repl, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return old, repl, nil
}
func (f *FileStore) RevokeGitCredential(ctx context.Context, id string, rev int64, a string) (GitCredential, error) {
	return mutate(f, ctx, func() (GitCredential, error) { return f.MemoryStore.RevokeGitCredential(ctx, id, rev, a) })
}
func (f *FileStore) CreateGitProvider(ctx context.Context, v GitProvider, a string) (GitProvider, error) {
	return mutate(f, ctx, func() (GitProvider, error) { return f.MemoryStore.CreateGitProvider(ctx, v, a) })
}
func (f *FileStore) UpdateGitProviderCredential(ctx context.Context, id string, rev int64, credentialID, a string) (GitProvider, error) {
	return mutate(f, ctx, func() (GitProvider, error) {
		return f.MemoryStore.UpdateGitProviderCredential(ctx, id, rev, credentialID, a)
	})
}

func (f *FileStore) CreateOIDCGroupMapping(ctx context.Context, v OIDCGroupMapping, a string) (OIDCGroupMapping, error) {
	return mutate(f, ctx, func() (OIDCGroupMapping, error) { return f.MemoryStore.CreateOIDCGroupMapping(ctx, v, a) })
}
func (f *FileStore) RevokeOIDCGroupMapping(ctx context.Context, id string, rev int64, a string) (OIDCGroupMapping, error) {
	return mutate(f, ctx, func() (OIDCGroupMapping, error) { return f.MemoryStore.RevokeOIDCGroupMapping(ctx, id, rev, a) })
}
func (f *FileStore) AppendSecurityAudit(ctx context.Context, in SecurityAuditInput) (SecurityAuditEvent, error) {
	return mutate(f, ctx, func() (SecurityAuditEvent, error) { return f.MemoryStore.AppendSecurityAudit(ctx, in) })
}
