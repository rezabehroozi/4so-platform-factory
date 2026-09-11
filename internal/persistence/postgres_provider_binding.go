package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *PostgresStore) BindManagedClusterProvider(ctx context.Context, clusterID string, expected int64, providerClusterID, actor string) (controlplane.ManagedCluster, error) {
	var out controlplane.ManagedCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cluster, err := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, strings.TrimSpace(clusterID)))
		if err != nil {
			return mapDBError(err)
		}
		if expected <= 0 || cluster.Revision != expected {
			return controlplane.ErrConflict
		}
		provider, err := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR SHARE`, strings.TrimSpace(providerClusterID)))
		if err != nil {
			return mapDBError(err)
		}
		profile, err := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1 FOR SHARE`, provider.ProviderProfileID))
		if err != nil {
			return mapDBError(err)
		}
		if cluster.ProjectID == "" || provider.ProjectID != cluster.ProjectID || profile.ProjectID != cluster.ProjectID {
			return controlplane.ErrNotFound
		}
		if provider.State != controlplane.ProviderClusterActive || provider.ProviderProfileID != profile.ID {
			return fmt.Errorf("%w: provider cluster must be ACTIVE with its admitted profile", controlplane.ErrPrerequisite)
		}
		if !strings.EqualFold(strings.TrimSpace(profile.Adapter), "cluster-api-topology-v1beta2") {
			return fmt.Errorf("%w: provider binding requires the admitted Cluster API topology adapter", controlplane.ErrPrerequisite)
		}
		if provider.Desired.WorkerReplicas < 1 || provider.Desired.WorkerReplicas > profile.MaxWorkerReplicas {
			return fmt.Errorf("%w: provider cluster worker topology is outside the admitted profile", controlplane.ErrPrerequisite)
		}
		if cluster.ProviderClusterID != "" && cluster.ProviderClusterID != provider.ID {
			return fmt.Errorf("%w: target is already bound to a different provider cluster", controlplane.ErrConflict)
		}
		if cluster.ProviderClusterID == provider.ID {
			out = cluster
			return nil
		}
		var other string
		qerr := tx.QueryRowContext(ctx, `SELECT id FROM managed_clusters WHERE labels->>'platform.4so.io/provider-cluster-id'=$1 AND id<>$2 AND connection_state<>'REVOKED' LIMIT 1`, provider.ID, cluster.ID).Scan(&other)
		if qerr == nil {
			return fmt.Errorf("%w: provider cluster is already bound to another active target", controlplane.ErrConflict)
		}
		if qerr != sql.ErrNoRows {
			return mapDBError(qerr)
		}
		now := utcNow(s.now)
		cluster.ProviderClusterID = provider.ID
		if cluster.Labels == nil {
			cluster.Labels = map[string]string{}
		}
		cluster.Labels[controlplane.TargetNodeProviderBindingLabel] = provider.ID
		labels, _ := json.Marshal(cluster.Labels)
		cluster.Revision++
		cluster.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE managed_clusters SET revision=$2,labels=$3,updated_at=$4 WHERE id=$1`, cluster.ID, cluster.Revision, labels, now); err != nil {
			return mapDBError(err)
		}
		if err = s.appendAuditTx(ctx, tx, strings.TrimSpace(actor), "managed_cluster.provider_bound", "managedCluster", cluster.ID, cluster.Revision, "", map[string]any{"providerClusterId": provider.ID, "authority": controlplane.TargetNodeProviderBindingAuthority}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "managedCluster", cluster.ID, "managed_cluster.provider_bound", cluster); err != nil {
			return err
		}
		out = cluster
		return nil
	})
	return out, err
}
