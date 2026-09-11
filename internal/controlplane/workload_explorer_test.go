package controlplane

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeClusterWorkloadExplorerBoundsAndCanonicalizes(t *testing.T) {
	value, err := NormalizeClusterWorkloadExplorer(ClusterWorkloadExplorer{Complete: true, Workloads: []ClusterWorkloadObservation{{Kind: " Deployment ", Namespace: " app ", Name: " web ", Images: []string{"z:v1", "a:v1", "a:v1"}}}, Services: []ClusterServiceObservation{{Namespace: "app", Name: "svc", ExternalIPs: []string{"10.0.0.2", "10.0.0.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if value.Authority != WorkloadExplorerAuthorityMethod || value.Workloads[0].Kind != "Deployment" || value.Workloads[0].Namespace != "app" || len(value.Workloads[0].Images) != 2 || value.Workloads[0].Images[0] != "a:v1" {
		t.Fatalf("unexpected normalized value: %#v", value)
	}
	over := ClusterWorkloadExplorer{Workloads: make([]ClusterWorkloadObservation, WorkloadExplorerItemLimit+1)}
	if _, err := NormalizeClusterWorkloadExplorer(over); err == nil {
		t.Fatal("oversized workload explorer payload accepted")
	}
}

func TestNormalizeClusterWorkloadExplorerEventOrderHasDeterministicTieBreakers(t *testing.T) {
	observed := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	a := ClusterEventObservation{Namespace: "app", Type: "Warning", Reason: "Probe", RegardingKind: "Deployment", RegardingName: "web", Message: "first", Count: 1, LastObservedAt: observed}
	b := ClusterEventObservation{Namespace: "app", Type: "Warning", Reason: "Probe", RegardingKind: "Deployment", RegardingName: "api", Message: "second", Count: 1, LastObservedAt: observed}
	left, err := NormalizeClusterWorkloadExplorer(ClusterWorkloadExplorer{Complete: true, Events: []ClusterEventObservation{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NormalizeClusterWorkloadExplorer(ClusterWorkloadExplorer{Complete: true, Events: []ClusterEventObservation{b, a}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left.Events, right.Events) {
		t.Fatalf("equal event sets normalized differently: left=%#v right=%#v", left.Events, right.Events)
	}
}
