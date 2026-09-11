package controlplane

import (
	"context"
	"fmt"
	"strings"
)

const (
	TargetNodeProviderBindingAuthority = "TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1"
	TargetNodeProviderBindingLabel     = "platform.4so.io/provider-cluster-id"
)

func validateProviderBinding(cluster ManagedCluster, provider ProviderCluster, profile ProviderProfile) error {
	if cluster.ProjectID == "" || provider.ProjectID != cluster.ProjectID || profile.ProjectID != cluster.ProjectID {
		return ErrNotFound
	}
	if strings.EqualFold(strings.TrimSpace(cluster.ConnectionState), "REVOKED") {
		return fmt.Errorf("%w: revoked target cannot acquire provider lifecycle authority", ErrPrerequisite)
	}
	if strings.TrimSpace(provider.ManagementClusterID) == strings.TrimSpace(cluster.ID) {
		return fmt.Errorf("%w: management cluster cannot bind to a provider cluster that it manages", ErrPrerequisite)
	}
	if provider.State != ProviderClusterActive || provider.ProviderProfileID != profile.ID {
		return fmt.Errorf("%w: provider cluster must be ACTIVE with its admitted profile", ErrPrerequisite)
	}
	if !strings.EqualFold(strings.TrimSpace(profile.Adapter), "cluster-api-topology-v1beta2") {
		return fmt.Errorf("%w: provider binding requires the admitted Cluster API ClusterClass adapter", ErrPrerequisite)
	}
	if provider.Desired.WorkerReplicas < 1 || provider.Desired.WorkerReplicas > profile.MaxWorkerReplicas {
		return fmt.Errorf("%w: provider cluster worker topology is outside the admitted profile", ErrPrerequisite)
	}
	return nil
}

func (s *MemoryStore) BindManagedClusterProvider(_ context.Context, clusterID string, expected int64, providerClusterID, actor string) (ManagedCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[strings.TrimSpace(clusterID)]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	if expected <= 0 || cluster.Revision != expected {
		return ManagedCluster{}, ErrConflict
	}
	provider, ok := s.providerClusters[strings.TrimSpace(providerClusterID)]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	profile, ok := s.providerProfiles[provider.ProviderProfileID]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	if err := validateProviderBinding(cluster, provider, profile); err != nil {
		return ManagedCluster{}, err
	}
	if cluster.ProviderClusterID != "" && cluster.ProviderClusterID != provider.ID {
		return ManagedCluster{}, fmt.Errorf("%w: target is already bound to a different provider cluster", ErrConflict)
	}
	if cluster.ProviderClusterID == provider.ID {
		return cloneManagedCluster(cluster), nil
	}
	for _, existing := range s.managedClusters {
		if existing.ID != cluster.ID && existing.ProviderClusterID == provider.ID && existing.ConnectionState != "REVOKED" {
			return ManagedCluster{}, fmt.Errorf("%w: provider cluster is already bound to another active target", ErrConflict)
		}
	}
	cluster.ProviderClusterID = provider.ID
	if cluster.Labels == nil {
		cluster.Labels = map[string]string{}
	}
	cluster.Labels[TargetNodeProviderBindingLabel] = provider.ID
	cluster.Revision++
	cluster.UpdatedAt = nowUTC(s.now)
	s.managedClusters[cluster.ID] = cluster
	s.appendAuditLocked(strings.TrimSpace(actor), "managed_cluster.provider_bound", "managedCluster", cluster.ID, cluster.Revision, map[string]any{"providerClusterId": provider.ID, "authority": TargetNodeProviderBindingAuthority})
	s.appendOutboxLocked("managedCluster", cluster.ID, "managed_cluster.provider_bound", cluster)
	return cloneManagedCluster(cluster), nil
}
