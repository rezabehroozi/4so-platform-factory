package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

const clusterImportColumns = `id,revision,project_id,name,display_name,state,token_digest,agent_token_digest,COALESCE(agent_service_account,''),expires_at,approved_at,claimed_at,COALESCE(cluster_id,''),requested_by,approved_by,created_at,updated_at`
const managedClusterColumns = `id,revision,project_id,import_id,name,display_name,external_uid,connection_state,distribution,kubernetes_version,agent_version,last_seen_at,inventory_updated_at,inventory_observed_at,labels,capabilities,inventory_digest,mutation_rbac_basis_digest,mutation_rbac_issued_for_digest,target_rbac_revocation_ack_digest,target_rbac_revocation_acknowledged_at,target_rbac_revocation_acknowledged_by,created_at,updated_at`

func scanClusterImport(row interface{ Scan(...any) error }) (controlplane.ClusterImport, error) {
	var v controlplane.ClusterImport
	var state string
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.Name, &v.DisplayName, &state, &v.TokenDigest, &v.AgentTokenDigest, &v.AgentServiceAccount, &v.ExpiresAt, &v.ApprovedAt, &v.ClaimedAt, &v.ClusterID, &v.RequestedBy, &v.ApprovedBy, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ClusterImportState(state)
	return v, err
}
func scanManagedCluster(row interface{ Scan(...any) error }) (controlplane.ManagedCluster, error) {
	var v controlplane.ManagedCluster
	var labels, cap []byte
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.ImportID, &v.Name, &v.DisplayName, &v.ExternalUID, &v.ConnectionState, &v.Distribution, &v.KubernetesVersion, &v.AgentVersion, &v.LastSeenAt, &v.InventoryUpdatedAt, &v.InventoryObservedAt, &labels, &cap, &v.InventoryDigest, &v.MutationRBACBasisDigest, &v.MutationRBACIssuedForDigest, &v.TargetRBACRevocationAcknowledgedDigest, &v.TargetRBACRevocationAcknowledgedAt, &v.TargetRBACRevocationAcknowledgedBy, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		if decodeErr := decodeJSONColumn(labels, &v.Labels, "postgres_fleet.Labels"); decodeErr != nil {
			return v, decodeErr
		}
		if decodeErr := decodeJSONColumn(cap, &v.Capabilities, "postgres_fleet.Capabilities"); decodeErr != nil {
			return v, decodeErr
		}
		v.ProviderClusterID = strings.TrimSpace(v.Labels[controlplane.TargetNodeProviderBindingLabel])
	}
	return v, err
}
func secureDigestEqual(a, b string) bool { return a == b && strings.HasPrefix(a, "sha256:") }

func postgresClusterImportEffectivelyExpired(v controlplane.ClusterImport, now time.Time) bool {
	return (v.State == controlplane.ClusterImportPendingApproval || v.State == controlplane.ClusterImportApproved) && !v.ExpiresAt.After(now)
}

func effectivePostgresClusterImport(v controlplane.ClusterImport, now time.Time) controlplane.ClusterImport {
	if postgresClusterImportEffectivelyExpired(v, now) {
		v.State = controlplane.ClusterImportExpired
		v.TokenDigest = "sha256:expired"
	}
	return v
}

func (s *PostgresStore) materializeExpiredClusterImportTx(ctx context.Context, tx *sql.Tx, v controlplane.ClusterImport, now time.Time) (controlplane.ClusterImport, error) {
	if !postgresClusterImportEffectivelyExpired(v, now) {
		return v, nil
	}
	v.State = controlplane.ClusterImportExpired
	v.TokenDigest = "sha256:expired"
	v.Revision++
	v.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE cluster_imports SET revision=$2,state='EXPIRED',token_digest=$3,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, v.TokenDigest, now); err != nil {
		return controlplane.ClusterImport{}, err
	}
	if err := s.appendAuditTx(ctx, tx, "system", "cluster_import.expired", "clusterImport", v.ID, v.Revision, "", map[string]any{"projectId": v.ProjectID}); err != nil {
		return controlplane.ClusterImport{}, err
	}
	if err := s.appendOutboxTx(ctx, tx, "clusterImport", v.ID, "cluster_import.expired", v); err != nil {
		return controlplane.ClusterImport{}, err
	}
	return v, nil
}

func (s *PostgresStore) validateClusterAgentTx(ctx context.Context, tx *sql.Tx, clusterID, tokenDigest string) error {
	var stored string
	if e := tx.QueryRowContext(ctx, `SELECT ci.agent_token_digest FROM cluster_imports ci JOIN managed_clusters mc ON mc.import_id=ci.id WHERE mc.id=$1`, clusterID).Scan(&stored); e != nil {
		return mapDBError(e)
	}
	if !secureTokenEqual(stored, tokenDigest) {
		return controlplane.ErrValidation
	}
	cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1`, clusterID))
	if e != nil {
		return mapDBError(e)
	}
	if !controlplane.ClusterTaskAdmitted(cluster) {
		return controlplane.ErrPrerequisite
	}
	return nil
}

func (s *PostgresStore) validateFreshClusterAgentTx(ctx context.Context, tx *sql.Tx, clusterID, tokenDigest string) error {
	if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
		return e
	}
	cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1`, clusterID))
	if e != nil {
		return mapDBError(e)
	}
	if !controlplane.ClusterTaskClaimAdmittedAt(cluster, utcNow(s.now)) {
		return controlplane.ErrPrerequisite
	}
	return nil
}
func (s *PostgresStore) hasUnacknowledgedRevokedClusterForUIDTx(ctx context.Context, tx *sql.Tx, externalUID, exceptClusterID string) (bool, error) {
	uid := strings.TrimSpace(externalUID)
	if uid == "" {
		return false, nil
	}
	q := `SELECT ` + managedClusterColumns + ` FROM managed_clusters WHERE external_uid=$1 AND connection_state='REVOKED'`
	args := []any{uid}
	if strings.TrimSpace(exceptClusterID) != "" {
		q += ` AND id<>$2`
		args = append(args, exceptClusterID)
	}
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return false, mapDBError(err)
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanManagedCluster(rows)
		if err != nil {
			return false, err
		}
		if !controlplane.ClusterTargetRBACRevocationAcknowledged(c) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *PostgresStore) CreateClusterImport(ctx context.Context, v controlplane.ClusterImport, actor string) (controlplane.ClusterImport, error) {
	now := utcNow(s.now)
	if v.ProjectID == "" || strings.TrimSpace(v.Name) == "" || strings.TrimSpace(v.DisplayName) == "" || !strings.HasPrefix(v.TokenDigest, "sha256:") || v.ExpiresAt.IsZero() || !v.ExpiresAt.After(now) {
		return v, fmt.Errorf("%w: invalid cluster import", controlplane.ErrValidation)
	}
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("imp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.AgentServiceAccount = controlplane.FleetAgentServiceAccountName(v.ID)
	v.Name = normalizedName(v.Name)
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	v.State = controlplane.ClusterImportPendingApproval
	v.RequestedBy = actor
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		existing, e := scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE project_id=$1 AND lower(name)=lower($2) AND state NOT IN ('EXPIRED','REVOKED') ORDER BY created_at,id LIMIT 1 FOR UPDATE`, v.ProjectID, v.Name))
		if e == nil {
			existing, e = s.materializeExpiredClusterImportTx(ctx, tx, existing, now)
			if e != nil {
				return e
			}
			if existing.State != controlplane.ClusterImportExpired {
				return controlplane.ErrDuplicateName
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return mapDBError(e)
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO cluster_imports(id,project_id,revision,name,display_name,state,token_digest,agent_service_account,expires_at,requested_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, v.ID, v.ProjectID, v.Name, v.DisplayName, string(v.State), v.TokenDigest, v.AgentServiceAccount, v.ExpiresAt, v.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_import.created", "clusterImport", v.ID, 1, "", map[string]any{"projectId": v.ProjectID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "clusterImport", v.ID, "cluster_import.created", v)
	})
	return v, err
}
func (s *PostgresStore) ApproveClusterImport(ctx context.Context, id string, expected int64, actor string) (controlplane.ClusterImport, error) {
	var out controlplane.ClusterImport
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ClusterImportPendingApproval || !v.ExpiresAt.After(utcNow(s.now)) {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State = controlplane.ClusterImportApproved
		v.ApprovedAt = &now
		v.ApprovedBy = actor
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE cluster_imports SET revision=$2,state=$3,approved_at=$4,approved_by=$5,updated_at=$4 WHERE id=$1`, id, v.Revision, string(v.State), now, actor)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_import.approved", "clusterImport", id, v.Revision, "", nil); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterImport", id, "cluster_import.approved", v)
	})
	return out, err
}
func (s *PostgresStore) RevokeClusterImport(ctx context.Context, id string, expected int64, actor string) (controlplane.ClusterImport, error) {
	var out controlplane.ClusterImport
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ClusterImportPendingApproval && v.State != controlplane.ClusterImportApproved {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if postgresClusterImportEffectivelyExpired(v, now) {
			return controlplane.ErrInvalidTransition
		}
		v.State = controlplane.ClusterImportRevoked
		v.TokenDigest = "sha256:revoked"
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE cluster_imports SET revision=$2,state=$3,token_digest=$4,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), "sha256:revoked", now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_import.revoked", "clusterImport", id, v.Revision, "", map[string]any{"projectId": v.ProjectID}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterImport", id, "cluster_import.revoked", v)
	})
	return out, err
}

func (s *PostgresStore) GetClusterImport(ctx context.Context, id string) (controlplane.ClusterImport, error) {
	v, e := scanClusterImport(s.db.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1`, id))
	if e != nil {
		return v, mapDBError(e)
	}
	return effectivePostgresClusterImport(v, utcNow(s.now)), nil
}
func (s *PostgresStore) ListClusterImports(ctx context.Context, pid string) ([]controlplane.ClusterImport, error) {
	q := `SELECT ` + clusterImportColumns + ` FROM cluster_imports`
	var args []any
	if pid != "" {
		q += ` WHERE project_id=$1`
		args = append(args, pid)
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	now := utcNow(s.now)
	var out []controlplane.ClusterImport
	for rows.Next() {
		v, e := scanClusterImport(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, effectivePostgresClusterImport(v, now))
	}
	return out, rows.Err()
}
func (s *PostgresStore) ClaimClusterImport(ctx context.Context, id, tokenDigest, agentTokenDigest, externalUID, agentVersion string) (controlplane.ClusterImport, controlplane.ManagedCluster, error) {
	normalizedExternalUID := strings.TrimSpace(externalUID)
	if normalizedExternalUID == "" || !strings.HasPrefix(agentTokenDigest, "sha256:") {
		return controlplane.ClusterImport{}, controlplane.ManagedCluster{}, controlplane.ErrValidation
	}
	var imp controlplane.ClusterImport
	var cluster controlplane.ManagedCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if !secureDigestEqual(v.TokenDigest, tokenDigest) {
			return controlplane.ErrValidation
		}
		if v.State == controlplane.ClusterImportClaimed {
			c, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1`, v.ClusterID))
			if e == nil && secureTokenEqual(strings.TrimSpace(c.ExternalUID), normalizedExternalUID) && secureDigestEqual(v.AgentTokenDigest, agentTokenDigest) {
				imp, cluster = v, c
				return nil
			}
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if v.State != controlplane.ClusterImportApproved || !v.ExpiresAt.After(now) {
			return controlplane.ErrInvalidTransition
		}
		blocked, e := s.hasUnacknowledgedRevokedClusterForUIDTx(ctx, tx, normalizedExternalUID, "")
		if e != nil {
			return e
		}
		if blocked {
			return fmt.Errorf("%w: target-side RBAC revocation fence must be acknowledged before physical cluster re-enrollment", controlplane.ErrPrerequisite)
		}
		cluster = controlplane.ManagedCluster{ResourceMeta: controlplane.ResourceMeta{ID: s.id("clu"), Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: v.ProjectID, ImportID: v.ID, Name: v.Name, DisplayName: v.DisplayName, ExternalUID: normalizedExternalUID, ConnectionState: "CONNECTED", AgentVersion: strings.TrimSpace(agentVersion), LastSeenAt: &now, Labels: map[string]string{}}
		labels, _ := json.Marshal(cluster.Labels)
		caps, _ := json.Marshal(cluster.Capabilities)
		_, e = tx.ExecContext(ctx, `INSERT INTO managed_clusters(id,project_id,import_id,revision,name,display_name,external_uid,connection_state,agent_version,last_seen_at,labels,capabilities,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,'CONNECTED',$7,$8,$9,$10,$8,$8)`, cluster.ID, cluster.ProjectID, cluster.ImportID, cluster.Name, cluster.DisplayName, cluster.ExternalUID, cluster.AgentVersion, now, labels, caps)
		if e != nil {
			return mapDBError(e)
		}
		v.State = controlplane.ClusterImportClaimed
		v.AgentTokenDigest = agentTokenDigest
		v.ClusterID = cluster.ID
		v.ClaimedAt = &now
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE cluster_imports SET revision=$2,state=$3,agent_token_digest=$4,cluster_id=$5,claimed_at=$6,updated_at=$6 WHERE id=$1`, id, v.Revision, string(v.State), agentTokenDigest, cluster.ID, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "cluster_import.claimed", "clusterImport", id, v.Revision, "", map[string]any{"clusterId": cluster.ID}); e != nil {
			return e
		}
		imp = v
		return s.appendOutboxTx(ctx, tx, "managedCluster", cluster.ID, "managed_cluster.connected", cluster)
	})
	return imp, cluster, err
}
func (s *PostgresStore) UpsertClusterInventory(ctx context.Context, clusterID, agentTokenDigest, externalUID string, inv controlplane.ClusterInventory) (controlplane.ManagedCluster, controlplane.ClusterInventory, error) {
	var c controlplane.ManagedCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var stored string
		e := tx.QueryRowContext(ctx, `SELECT ci.agent_token_digest FROM cluster_imports ci JOIN managed_clusters mc ON mc.import_id=ci.id WHERE mc.id=$1 FOR UPDATE`, clusterID).Scan(&stored)
		if e != nil {
			return mapDBError(e)
		}
		if !secureDigestEqual(stored, agentTokenDigest) {
			return controlplane.ErrValidation
		}
		c, e = scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		observedExternalUID := strings.TrimSpace(externalUID)
		identityContinuityVerified := observedExternalUID != "" && secureTokenEqual(strings.TrimSpace(c.ExternalUID), observedExternalUID)
		if observedExternalUID != "" && !identityContinuityVerified {
			return controlplane.ErrValidation
		}
		inv = controlplane.NormalizeClusterInventoryIdentityAuthority(inv, identityContinuityVerified)
		now := utcNow(s.now)
		if e = controlplane.ValidateClusterInventoryObservationEpoch(c, inv.ObservedAt, now); e != nil {
			return e
		}
		if e = controlplane.ValidateClusterInventoryAPISurface(inv); e != nil {
			return e
		}
		inv = controlplane.NormalizeClusterInventoryForAdmission(inv)
		basisDigest := controlplane.ClusterInventoryMutationBasisDigest(inv)
		var imp controlplane.ClusterImport
		imp, e = scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1`, c.ImportID))
		if e != nil {
			return mapDBError(e)
		}
		inv = controlplane.NormalizeClusterInventoryMutationAuthority(inv, c, imp, identityContinuityVerified, basisDigest)
		inv.Digest = controlplane.ClusterInventoryDigest(inv)
		inv.ObservedAt = inv.ObservedAt.UTC()
		inv.ResourceMeta = controlplane.ResourceMeta{ID: s.id("inv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		inv.ClusterID = clusterID
		nodes, _ := json.Marshal(inv.Nodes)
		addons, _ := json.Marshal(inv.AddOns)
		storageClasses, _ := json.Marshal(inv.StorageClasses)
		capacity, _ := json.Marshal(inv.Capacity)
		certificates, _ := json.Marshal(inv.Certificates)
		networking, _ := json.Marshal(inv.Networking)
		workloadExplorer, _ := json.Marshal(inv.WorkloadExplorer)
		apiResources, _ := json.Marshal(inv.APIResources)
		crds, _ := json.Marshal(inv.CRDs)
		caps, _ := json.Marshal(inv.Capabilities)
		_, e = tx.ExecContext(ctx, `INSERT INTO cluster_inventory_snapshots(id,cluster_id,revision,observed_at,distribution,distribution_evidence_method,distribution_evidence_uid,distribution_evidence_version,kubernetes_version,nodes,addons,storage_classes,capacity,certificates,networking,workload_explorer,api_resources,crds,api_discovery_complete,crd_discovery_complete,schema_discovery_version,schema_discovery_digest,schema_discovery_complete,capabilities,digest,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$25) ON CONFLICT(cluster_id,digest) DO NOTHING`, inv.ID, clusterID, inv.ObservedAt, inv.Distribution, inv.DistributionEvidenceMethod, inv.DistributionEvidenceUID, inv.DistributionEvidenceVersion, inv.KubernetesVersion, nodes, addons, storageClasses, capacity, certificates, networking, workloadExplorer, apiResources, crds, inv.APIDiscoveryComplete, inv.CRDDiscoveryComplete, inv.SchemaDiscoveryVersion, inv.SchemaDiscoveryDigest, inv.SchemaDiscoveryComplete, caps, inv.Digest, now)
		if e != nil {
			return e
		}
		c.Distribution = inv.Distribution
		c.KubernetesVersion = inv.KubernetesVersion
		issuedForCurrentBasis := controlplane.ClusterHasCapability(c, controlplane.TargetMutationRBACActivationIssuedCapability) && c.MutationRBACIssuedForDigest == basisDigest
		c.Capabilities = controlplane.ClusterCapabilitiesWithServerMutationAuthority(inv, c, identityContinuityVerified, basisDigest)
		if !issuedForCurrentBasis {
			c.MutationRBACIssuedForDigest = ""
		}
		c.MutationRBACBasisDigest = basisDigest
		c.InventoryDigest = inv.Digest
		c.ConnectionState = "CONNECTED"
		c.LastSeenAt = &now
		c.InventoryUpdatedAt = &now
		observedAt := inv.ObservedAt
		c.InventoryObservedAt = &observedAt
		c.Revision++
		c.UpdatedAt = now
		labels, _ := json.Marshal(c.Labels)
		caps, _ = json.Marshal(c.Capabilities)
		_, e = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,connection_state='CONNECTED',distribution=$3,kubernetes_version=$4,last_seen_at=$5,inventory_updated_at=$5,inventory_observed_at=$6,labels=$7,capabilities=$8,inventory_digest=$9,mutation_rbac_basis_digest=$10,mutation_rbac_issued_for_digest=$11,updated_at=$5 WHERE id=$1`, clusterID, c.Revision, c.Distribution, c.KubernetesVersion, now, c.InventoryObservedAt, labels, caps, c.InventoryDigest, c.MutationRBACBasisDigest, c.MutationRBACIssuedForDigest)
		if e != nil {
			return e
		}
		return s.appendAuditTx(ctx, tx, "cluster-agent", "cluster.inventory.updated", "managedCluster", clusterID, c.Revision, "", map[string]any{"digest": inv.Digest, "nodes": len(inv.Nodes)})
	})
	return c, inv, err
}
func (s *PostgresStore) AuthorizeClusterMutationRBACActivation(ctx context.Context, clusterID, actor string) (controlplane.ManagedCluster, controlplane.ClusterImport, error) {
	var cluster controlplane.ManagedCluster
	var imp controlplane.ClusterImport
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		cluster, e = scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		imp, e = scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1`, cluster.ImportID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, utcNow(s.now)) || !controlplane.ClusterHasCapability(cluster, controlplane.TargetIdentityContinuityCapability) || !controlplane.ClusterMutationAdmissionEligible(cluster) {
			return controlplane.ErrPrerequisite
		}
		blocked, e := s.hasUnacknowledgedRevokedClusterForUIDTx(ctx, tx, cluster.ExternalUID, cluster.ID)
		if e != nil {
			return e
		}
		if blocked {
			return fmt.Errorf("%w: predecessor target-side RBAC revocation fence is not acknowledged", controlplane.ErrPrerequisite)
		}
		if strings.TrimSpace(imp.AgentServiceAccount) != "" {
			if imp.AgentServiceAccount != controlplane.FleetAgentServiceAccountName(imp.ID) || !controlplane.ClusterHasCapability(cluster, controlplane.TargetEnrollmentPrincipalIsolatedCapability) {
				return controlplane.ErrPrerequisite
			}
		}
		if strings.TrimSpace(cluster.MutationRBACBasisDigest) == "" || !strings.HasPrefix(cluster.MutationRBACBasisDigest, "sha256:") {
			return controlplane.ErrPrerequisite
		}
		if controlplane.ClusterMutationRBACActivationCurrent(cluster) {
			return nil
		}
		now := utcNow(s.now)
		cluster.Capabilities = controlplane.DedupeClusterCapabilities(append(cluster.Capabilities, controlplane.TargetMutationRBACActivationIssuedCapability, controlplane.TargetMutationRBACEverIssuedCapability))
		cluster.MutationRBACIssuedForDigest = cluster.MutationRBACBasisDigest
		cluster.Revision++
		cluster.UpdatedAt = now
		caps, _ := json.Marshal(cluster.Capabilities)
		if _, e = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,capabilities=$3,mutation_rbac_issued_for_digest=$4,updated_at=$5 WHERE id=$1`, clusterID, cluster.Revision, caps, cluster.MutationRBACIssuedForDigest, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster.mutation_rbac_activation.authorized", "managedCluster", clusterID, cluster.Revision, "", map[string]any{"inventoryDigest": cluster.InventoryDigest, "importId": imp.ID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "managedCluster", clusterID, "managed_cluster.mutation_rbac_activation_authorized", cluster)
	})
	return cluster, imp, err
}

func (s *PostgresStore) HeartbeatCluster(ctx context.Context, clusterID, agentTokenDigest, externalUID, agentVersion string) (controlplane.ManagedCluster, error) {
	var c controlplane.ManagedCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var stored string
		e := tx.QueryRowContext(ctx, `SELECT ci.agent_token_digest FROM cluster_imports ci JOIN managed_clusters mc ON mc.import_id=ci.id WHERE mc.id=$1 FOR UPDATE`, clusterID).Scan(&stored)
		if e != nil {
			return mapDBError(e)
		}
		if !secureDigestEqual(stored, agentTokenDigest) {
			return controlplane.ErrValidation
		}
		c, e = scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return e
		}
		observedExternalUID := strings.TrimSpace(externalUID)
		if observedExternalUID == "" {
			return nil
		}
		if !secureTokenEqual(strings.TrimSpace(c.ExternalUID), observedExternalUID) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		c.Revision++
		c.AgentVersion = agentVersion
		c.LastSeenAt = &now
		c.ConnectionState = "CONNECTED"
		c.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,agent_version=$3,last_seen_at=$4,connection_state='CONNECTED',updated_at=$4 WHERE id=$1`, clusterID, c.Revision, agentVersion, now)
		return e
	})
	return c, err
}
func (s *PostgresStore) RevokeManagedCluster(ctx context.Context, clusterID string, expected int64, actor string) (controlplane.ManagedCluster, controlplane.ClusterImport, error) {
	var cluster controlplane.ManagedCluster
	var imp controlplane.ClusterImport
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		c, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		if c.Revision != expected {
			return controlplane.ErrConflict
		}
		v, e := scanClusterImport(tx.QueryRowContext(ctx, `SELECT `+clusterImportColumns+` FROM cluster_imports WHERE id=$1 FOR UPDATE`, c.ImportID))
		if e != nil {
			return mapDBError(e)
		}
		if v.State == controlplane.ClusterImportRevoked || c.ConnectionState == "REVOKED" {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if controlplane.ClusterMayHaveTargetMutationRBAC(c) {
			c.Capabilities = controlplane.DedupeClusterCapabilities(append(c.Capabilities, controlplane.TargetMutationRBACEverIssuedCapability))
		}
		c.TargetRBACRevocationAcknowledgedDigest = ""
		c.TargetRBACRevocationAcknowledgedAt = nil
		c.TargetRBACRevocationAcknowledgedBy = ""
		v.State = controlplane.ClusterImportRevoked
		v.AgentTokenDigest = ""
		v.Revision++
		v.UpdatedAt = now
		c.ConnectionState = "REVOKED"
		c.Revision++
		c.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE cluster_imports SET revision=$2,state=$3,agent_token_digest='',updated_at=$4 WHERE id=$1`, v.ID, v.Revision, string(v.State), now); e != nil {
			return e
		}
		caps, _ := json.Marshal(c.Capabilities)
		if _, e = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,connection_state='REVOKED',capabilities=$3,target_rbac_revocation_ack_digest='',target_rbac_revocation_acknowledged_at=NULL,target_rbac_revocation_acknowledged_by='',updated_at=$4 WHERE id=$1`, c.ID, c.Revision, caps, now); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE agent_certificates SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE cluster_id=$1 AND state='ACTIVE'`, c.ID, actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "managed_cluster.revoked", "managedCluster", c.ID, c.Revision, "", map[string]any{"importId": v.ID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "managedCluster", c.ID, "managed_cluster.revoked", c); e != nil {
			return e
		}
		cluster, imp = c, v
		return nil
	})
	return cluster, imp, err
}

func (s *PostgresStore) AcknowledgeManagedClusterTargetRBACRevocation(ctx context.Context, clusterID string, expected int64, fenceDigest, actor string) (controlplane.ManagedCluster, error) {
	var cluster controlplane.ManagedCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		cluster, e = scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		if cluster.Revision != expected {
			return controlplane.ErrConflict
		}
		if cluster.ConnectionState != "REVOKED" {
			return controlplane.ErrInvalidTransition
		}
		expectedDigest := controlplane.ClusterTargetRBACRevocationFenceDigest(cluster)
		if !strings.HasPrefix(strings.TrimSpace(fenceDigest), "sha256:") || !secureTokenEqual(strings.TrimSpace(fenceDigest), expectedDigest) {
			return controlplane.ErrValidation
		}
		if controlplane.ClusterTargetRBACRevocationAcknowledged(cluster) {
			return nil
		}
		now := utcNow(s.now)
		cluster.TargetRBACRevocationAcknowledgedDigest = expectedDigest
		cluster.TargetRBACRevocationAcknowledgedAt = &now
		cluster.TargetRBACRevocationAcknowledgedBy = strings.TrimSpace(actor)
		cluster.Revision++
		cluster.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,target_rbac_revocation_ack_digest=$3,target_rbac_revocation_acknowledged_at=$4,target_rbac_revocation_acknowledged_by=$5,updated_at=$4 WHERE id=$1`, clusterID, cluster.Revision, expectedDigest, now, cluster.TargetRBACRevocationAcknowledgedBy); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "managed_cluster.target_rbac_revocation_acknowledged", "managedCluster", clusterID, cluster.Revision, "", map[string]any{"fenceDigest": expectedDigest, "externalUid": cluster.ExternalUID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "managedCluster", clusterID, "managed_cluster.target_rbac_revocation_acknowledged", cluster)
	})
	return cluster, err
}

func (s *PostgresStore) GetManagedCluster(ctx context.Context, id string) (controlplane.ManagedCluster, error) {
	v, e := scanManagedCluster(s.db.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListManagedClusters(ctx context.Context, pid string) ([]controlplane.ManagedCluster, error) {
	q := `SELECT ` + managedClusterColumns + ` FROM managed_clusters`
	var args []any
	if pid != "" {
		q += ` WHERE project_id=$1`
		args = append(args, pid)
	}
	q += ` ORDER BY name,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []controlplane.ManagedCluster
	for rows.Next() {
		v, e := scanManagedCluster(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) GetLatestClusterInventory(ctx context.Context, id string) (controlplane.ClusterInventory, error) {
	var v controlplane.ClusterInventory
	var nodes, addons, storageClasses, capacity, certificates, networking, workloadExplorer, apiResources, crds, caps []byte
	e := s.db.QueryRowContext(ctx, `SELECT id,revision,cluster_id,observed_at,distribution,distribution_evidence_method,distribution_evidence_uid,distribution_evidence_version,kubernetes_version,nodes,addons,storage_classes,capacity,certificates,networking,workload_explorer,api_resources,crds,api_discovery_complete,crd_discovery_complete,schema_discovery_version,schema_discovery_digest,schema_discovery_complete,capabilities,digest,created_at,updated_at FROM cluster_inventory_snapshots WHERE cluster_id=$1 ORDER BY observed_at DESC,id DESC LIMIT 1`, id).Scan(&v.ID, &v.Revision, &v.ClusterID, &v.ObservedAt, &v.Distribution, &v.DistributionEvidenceMethod, &v.DistributionEvidenceUID, &v.DistributionEvidenceVersion, &v.KubernetesVersion, &nodes, &addons, &storageClasses, &capacity, &certificates, &networking, &workloadExplorer, &apiResources, &crds, &v.APIDiscoveryComplete, &v.CRDDiscoveryComplete, &v.SchemaDiscoveryVersion, &v.SchemaDiscoveryDigest, &v.SchemaDiscoveryComplete, &caps, &v.Digest, &v.CreatedAt, &v.UpdatedAt)
	if e != nil {
		return v, mapDBError(e)
	}
	if decodeErr := decodeJSONColumn(nodes, &v.Nodes, "postgres_fleet.Nodes"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(addons, &v.AddOns, "postgres_fleet.AddOns"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(storageClasses, &v.StorageClasses, "postgres_fleet.StorageClasses"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(capacity, &v.Capacity, "postgres_fleet.Capacity"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(certificates, &v.Certificates, "postgres_fleet.Certificates"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(networking, &v.Networking, "postgres_fleet.Networking"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(workloadExplorer, &v.WorkloadExplorer, "postgres_fleet.WorkloadExplorer"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(apiResources, &v.APIResources, "postgres_fleet.APIResources"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(crds, &v.CRDs, "postgres_fleet.CRDs"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(caps, &v.Capabilities, "postgres_fleet.Capabilities"); decodeErr != nil {
		return v, decodeErr
	}
	return v, nil
}

var _ = errors.Is
var _ = time.Second
