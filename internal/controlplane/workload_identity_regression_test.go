package controlplane

import "testing"

func TestNormalizeClusterWorkloadExplorerPreservesExactResourceIdentity(t *testing.T) {
	value, err := NormalizeClusterWorkloadExplorer(ClusterWorkloadExplorer{
		Complete: true,
		Workloads: []ClusterWorkloadObservation{{APIVersion: " apps/v1 ", UID: " deploy-uid ", Kind: " Deployment ", Namespace: " app ", Name: " web "}},
		Services: []ClusterServiceObservation{{APIVersion: " v1 ", UID: " svc-uid ", Namespace: " app ", Name: " web ", Type: "ClusterIP"}},
		Ingresses: []ClusterIngressObservation{{APIVersion: " networking.k8s.io/v1 ", UID: " ingress-uid ", Namespace: " app ", Name: " web "}},
		PVCs: []ClusterPVCObservation{{APIVersion: " v1 ", UID: " pvc-uid ", Namespace: " app ", Name: " data "}},
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name, apiVersion, uid string
	}{
		{"workload", value.Workloads[0].APIVersion, value.Workloads[0].UID},
		{"service", value.Services[0].APIVersion, value.Services[0].UID},
		{"ingress", value.Ingresses[0].APIVersion, value.Ingresses[0].UID},
		{"pvc", value.PVCs[0].APIVersion, value.PVCs[0].UID},
	}
	wantVersions := []string{"apps/v1", "v1", "networking.k8s.io/v1", "v1"}
	wantUIDs := []string{"deploy-uid", "svc-uid", "ingress-uid", "pvc-uid"}
	for i, check := range checks {
		if check.apiVersion != wantVersions[i] || check.uid != wantUIDs[i] {
			t.Fatalf("%s identity drift: apiVersion=%q uid=%q", check.name, check.apiVersion, check.uid)
		}
	}
}
