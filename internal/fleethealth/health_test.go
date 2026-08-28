package fleethealth

import (
	"platform.4so.io/factory/internal/controlplane"
	"testing"
	"time"
)

func TestSupportPolicyAndStaleHealth(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	if got := SupportFor("v1.34.9+rke2r1", now); got.Status != "EOL_SOON" || got.EndOfLife.Format("2006-01-02") != "2026-10-27" {
		t.Fatalf("unexpected support result: %#v", got)
	}
	seen := now.Add(-time.Minute)
	cluster := controlplane.ManagedCluster{ResourceMeta: controlplane.ResourceMeta{ID: "clu-1"}, ProjectID: "prj-1", Name: "prod", DisplayName: "Prod", ConnectionState: "CONNECTED", KubernetesVersion: "v1.34.9", LastSeenAt: &seen}
	inv := controlplane.ClusterInventory{ObservedAt: now.Add(-20 * time.Minute), KubernetesVersion: "v1.34.9", Nodes: []controlplane.ClusterNode{{Name: "n1", Ready: true}}, StorageClasses: []controlplane.ClusterStorageClass{{Name: "fast", Provisioner: "csi.example", Default: true}}, Networking: controlplane.ClusterNetworking{CNI: "cilium", IngressControllers: []string{"ingress-nginx/controller"}}}
	health := Evaluate(cluster, inv, nil, now)
	if health.InventoryState != "STALE" || health.Health != "STALE" {
		t.Fatalf("unexpected stale health: %#v", health)
	}
	if health.DefaultStorageClass != "fast" {
		t.Fatalf("default storage class missing: %#v", health)
	}
}

func TestEOLAndCertificateExpiryAreCritical(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	seen := now
	cluster := controlplane.ManagedCluster{ResourceMeta: controlplane.ResourceMeta{ID: "clu-2"}, ProjectID: "prj-1", Name: "legacy", ConnectionState: "CONNECTED", KubernetesVersion: "v1.33.13", LastSeenAt: &seen}
	inv := controlplane.ClusterInventory{ObservedAt: now, KubernetesVersion: "v1.33.13", Nodes: []controlplane.ClusterNode{{Name: "n1", Ready: true}}, Certificates: []controlplane.ClusterCertificateObservation{{Name: "kubernetes-api-server", Fingerprint: "sha256:a", NotAfter: now.Add(-time.Hour)}}}
	health := Evaluate(cluster, inv, []controlplane.AgentCertificate{{State: controlplane.AgentCertificateActive, Fingerprint: "sha256:b", NotAfter: now.Add(10 * 24 * time.Hour)}}, now)
	if health.KubernetesSupport.Status != "EOL" || health.Health != "CRITICAL" {
		t.Fatalf("expected critical EOL health: %#v", health)
	}
}
