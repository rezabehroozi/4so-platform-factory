package bootstrap

import (
	"context"
	"fmt"
	"time"
)

const ocmManifestPath = "/var/lib/4so-platform-installer/bundle/fleet/ocm-install.yaml"

func (r *Runner) deployFleetHub(ctx context.Context, bundle BundleManifest) error {
	if bundle.Spec.Workloads.OCMManifest.Path == "" {
		return nil
	}
	source, err := safeBundlePath(r.bundleDir, bundle.Spec.Workloads.OCMManifest.Path)
	if err != nil {
		return err
	}
	if err = r.system.CopyFile(source, ocmManifestPath, 0o600); err != nil {
		return err
	}
	raw, err := r.readFile(ocmManifestPath)
	if err != nil {
		return err
	}
	if err = r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-ocm.yaml", raw, 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	return waitUntil(ctx, 5*time.Second, 10*time.Minute, func() error {
		if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "get", "clustermanager", "cluster-manager"}, nil); err != nil {
			return fmt.Errorf("OCM ClusterManager is not available: %w", err)
		}
		return nil
	})
}

func (r *Runner) verifyFleetHub(ctx context.Context) error {
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	checks := [][]string{
		{"--kubeconfig", kubeconfig, "-n", "open-cluster-management-hub", "get", "deployment"},
		{"--kubeconfig", kubeconfig, "get", "crd", "managedclusters.cluster.open-cluster-management.io"},
		{"--kubeconfig", kubeconfig, "get", "crd", "managedclusteraddons.addon.open-cluster-management.io"},
	}
	for _, args := range checks {
		if err := r.system.Run(ctx, kubectl, args, nil); err != nil {
			return err
		}
	}
	return nil
}
