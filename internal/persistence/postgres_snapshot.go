package persistence

import (
	"context"
	"errors"
	"sort"

	"platform.4so.io/factory/internal/controlplane"
)

// snapshotSupplementalReader is the stable read-side contract required to make
// the PostgreSQL diagnostic snapshot semantically equivalent to MemoryStore.
// Snapshot consumers include scoped audit, support timelines, health scanning
// and control-plane summaries, so omitting a resource family is a runtime
// correctness defect rather than a cosmetic diagnostics gap.
type snapshotSupplementalReader interface {
	ListNotificationDestinations(context.Context, string) ([]controlplane.NotificationDestination, error)
	ListNotificationRoutes(context.Context, string, string) ([]controlplane.NotificationRoute, error)
	ListNotificationEvents(context.Context, string, string, int) ([]controlplane.NotificationEvent, error)
	ListNotificationDeliveries(context.Context, string, string, controlplane.NotificationDeliveryState, int) ([]controlplane.NotificationDelivery, error)
	ListNotificationDeliveryAttempts(context.Context, string) ([]controlplane.NotificationDeliveryAttempt, error)
	ListAgentCertificates(context.Context, string) ([]controlplane.AgentCertificate, error)
	ListRecoveryCheckpoints(context.Context, string, string) ([]controlplane.RecoveryCheckpoint, error)
	ListGitCredentials(context.Context) ([]controlplane.GitCredential, error)
	ListGitProviders(context.Context) ([]controlplane.GitProvider, error)
	ListGitPullRequests(context.Context, string, string) ([]controlplane.GitPullRequest, error)
	ListManagedGitRevisions(context.Context, string, string) ([]controlplane.ManagedGitRevision, error)
	GetEntitlement(context.Context, string) (controlplane.Entitlement, error)
	GetOEMProfile(context.Context, string) (controlplane.OEMProfile, error)
	ListTenants(context.Context, string, string) ([]controlplane.TenantEnvironment, error)
	ListProviderProfiles(context.Context, string, string) ([]controlplane.ProviderProfile, error)
	ListProviderClusters(context.Context, string, string) ([]controlplane.ProviderCluster, error)
}

func populateSupplementalSnapshot(ctx context.Context, reader snapshotSupplementalReader, snapshot *controlplane.Snapshot, organizations []controlplane.Organization, imports []controlplane.ClusterImport) error {
	var err error
	if snapshot.NotificationDestinations, err = reader.ListNotificationDestinations(ctx, ""); err != nil {
		return err
	}
	if snapshot.NotificationRoutes, err = reader.ListNotificationRoutes(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.NotificationEvents, err = reader.ListNotificationEvents(ctx, "", "", 0); err != nil {
		return err
	}
	if snapshot.NotificationDeliveries, err = reader.ListNotificationDeliveries(ctx, "", "", "", 0); err != nil {
		return err
	}
	snapshot.NotificationAttempts = nil
	for _, delivery := range snapshot.NotificationDeliveries {
		attempts, e := reader.ListNotificationDeliveryAttempts(ctx, delivery.ID)
		if e != nil {
			return e
		}
		snapshot.NotificationAttempts = append(snapshot.NotificationAttempts, attempts...)
	}
	if snapshot.AgentCertificates, err = reader.ListAgentCertificates(ctx, ""); err != nil {
		return err
	}
	if snapshot.RecoveryCheckpoints, err = reader.ListRecoveryCheckpoints(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.GitCredentials, err = reader.ListGitCredentials(ctx); err != nil {
		return err
	}
	if snapshot.GitProviders, err = reader.ListGitProviders(ctx); err != nil {
		return err
	}
	if snapshot.GitPullRequests, err = reader.ListGitPullRequests(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.ManagedGitRevisions, err = reader.ListManagedGitRevisions(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.Tenants, err = reader.ListTenants(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.ProviderProfiles, err = reader.ListProviderProfiles(ctx, "", ""); err != nil {
		return err
	}
	if snapshot.ProviderClusters, err = reader.ListProviderClusters(ctx, "", ""); err != nil {
		return err
	}

	snapshot.ClusterImportCredentials = make([]controlplane.ClusterImportCredentialSnapshot, 0, len(imports))
	for _, v := range imports {
		snapshot.ClusterImportCredentials = append(snapshot.ClusterImportCredentials, controlplane.ClusterImportCredentialSnapshot{ImportID: v.ID, TokenDigest: v.TokenDigest, AgentTokenDigest: v.AgentTokenDigest})
	}
	snapshot.Entitlements = nil
	snapshot.OEMProfiles = nil
	for _, org := range organizations {
		entitlement, e := reader.GetEntitlement(ctx, org.ID)
		if e == nil {
			snapshot.Entitlements = append(snapshot.Entitlements, entitlement)
		} else if !errors.Is(e, controlplane.ErrNotFound) {
			return e
		}
		oem, e := reader.GetOEMProfile(ctx, org.ID)
		if e == nil {
			snapshot.OEMProfiles = append(snapshot.OEMProfiles, oem)
		} else if !errors.Is(e, controlplane.ErrNotFound) {
			return e
		}
	}
	sort.Slice(snapshot.NotificationEvents, func(i, j int) bool { return snapshot.NotificationEvents[i].ID < snapshot.NotificationEvents[j].ID })
	sort.Slice(snapshot.NotificationDeliveries, func(i, j int) bool {
		return snapshot.NotificationDeliveries[i].ID < snapshot.NotificationDeliveries[j].ID
	})
	sort.Slice(snapshot.NotificationAttempts, func(i, j int) bool { return snapshot.NotificationAttempts[i].ID < snapshot.NotificationAttempts[j].ID })
	sort.Slice(snapshot.AgentCertificates, func(i, j int) bool { return snapshot.AgentCertificates[i].ID < snapshot.AgentCertificates[j].ID })
	sort.Slice(snapshot.RecoveryCheckpoints, func(i, j int) bool { return snapshot.RecoveryCheckpoints[i].ID < snapshot.RecoveryCheckpoints[j].ID })
	sort.Slice(snapshot.GitCredentials, func(i, j int) bool { return snapshot.GitCredentials[i].ID < snapshot.GitCredentials[j].ID })
	sort.Slice(snapshot.GitProviders, func(i, j int) bool { return snapshot.GitProviders[i].ID < snapshot.GitProviders[j].ID })
	sort.Slice(snapshot.GitPullRequests, func(i, j int) bool { return snapshot.GitPullRequests[i].ID < snapshot.GitPullRequests[j].ID })
	sort.Slice(snapshot.ManagedGitRevisions, func(i, j int) bool { return snapshot.ManagedGitRevisions[i].ID < snapshot.ManagedGitRevisions[j].ID })
	sort.Slice(snapshot.Tenants, func(i, j int) bool { return snapshot.Tenants[i].ID < snapshot.Tenants[j].ID })
	sort.Slice(snapshot.ProviderProfiles, func(i, j int) bool { return snapshot.ProviderProfiles[i].ID < snapshot.ProviderProfiles[j].ID })
	sort.Slice(snapshot.ProviderClusters, func(i, j int) bool { return snapshot.ProviderClusters[i].ID < snapshot.ProviderClusters[j].ID })
	sort.Slice(snapshot.Entitlements, func(i, j int) bool {
		return snapshot.Entitlements[i].OrganizationID < snapshot.Entitlements[j].OrganizationID
	})
	sort.Slice(snapshot.OEMProfiles, func(i, j int) bool {
		return snapshot.OEMProfiles[i].OrganizationID < snapshot.OEMProfiles[j].OrganizationID
	})
	return nil
}

func (s *PostgresStore) snapshotSecurityAudit(ctx context.Context) ([]controlplane.SecurityAuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,id,occurred_at,method_version,category,decision,actor_id,authentication,request_method,request_path,status_code,reason_code,request_id,scope_type,scope_id,effective_role,mapping_digest,previous_digest,event_digest FROM security_audit_events ORDER BY sequence ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.SecurityAuditEvent{}
	for rows.Next() {
		var v controlplane.SecurityAuditEvent
		if err := rows.Scan(&v.Sequence, &v.ID, &v.OccurredAt, &v.MethodVersion, &v.Category, &v.Decision, &v.ActorID, &v.Authentication, &v.Method, &v.Path, &v.StatusCode, &v.ReasonCode, &v.RequestID, &v.ScopeType, &v.ScopeID, &v.EffectiveRole, &v.MappingDigest, &v.PreviousDigest, &v.Digest); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		if err := controlplane.ValidateSecurityAuditChain(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *PostgresStore) snapshotAudit(ctx context.Context) ([]controlplane.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,COALESCE(request_id,''),metadata FROM audit_events ORDER BY occurred_at ASC,id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.AuditEvent{}
	for rows.Next() {
		var v controlplane.AuditEvent
		var metadata []byte
		if err := rows.Scan(&v.ID, &v.OccurredAt, &v.ActorID, &v.Action, &v.ResourceType, &v.ResourceID, &v.Revision, &v.RequestID, &metadata); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := decodeJSONColumn(metadata, &v.Metadata, "snapshotAudit.Metadata"); err != nil {
				return nil, err
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
