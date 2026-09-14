package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func TestProjectServiceHealthFailsClosedOnMissingAndStaleCoverage(t *testing.T) {
	now := time.Date(2026, 9, 14, 7, 0, 0, 0, time.UTC)
	clusters := []controlplane.ManagedCluster{{ID: "clu-b", ProjectID: "prj-a"}, {ID: "clu-a", ProjectID: "prj-a"}}
	observations := []reliability.HealthObservation{
		{ProjectID: "prj-a", ClusterID: "clu-a", Health: "HEALTHY", ObservedAt: now.Add(-time.Minute), SourceDigest: "sha256:secret-a"},
		{ProjectID: "prj-other", ClusterID: "clu-b", Health: "HEALTHY", ObservedAt: now.Add(-time.Minute), SourceDigest: "sha256:foreign"},
	}
	projection := projectServiceHealth("prj-a", now, clusters, observations, false)
	if projection.CoverageStatus != serviceHealthCoverageUnknown {
		t.Fatalf("coverage=%q want UNKNOWN: %#v", projection.CoverageStatus, projection)
	}
	if len(projection.Clusters) != 2 || projection.Clusters[0].ClusterID != "clu-a" || projection.Clusters[0].Health != "HEALTHY" {
		t.Fatalf("deterministic healthy projection missing: %#v", projection.Clusters)
	}
	if projection.Clusters[1].ClusterID != "clu-b" || projection.Clusters[1].Health != serviceHealthCoverageUnknown {
		t.Fatalf("missing observation must be UNKNOWN: %#v", projection.Clusters)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-a") || strings.Contains(string(raw), "sourceDigest") {
		t.Fatalf("service-health projection leaked raw observation evidence: %s", raw)
	}
}

func TestProjectServiceHealthRejectsStaleOrUnrecognizedLatestObservation(t *testing.T) {
	now := time.Date(2026, 9, 14, 7, 0, 0, 0, time.UTC)
	clusters := []controlplane.ManagedCluster{{ID: "clu-a", ProjectID: "prj-a"}, {ID: "clu-b", ProjectID: "prj-a"}}
	observations := []reliability.HealthObservation{
		{ProjectID: "prj-a", ClusterID: "clu-a", Health: "HEALTHY", ObservedAt: now.Add(-serviceHealthStaleAfter-time.Second)},
		{ProjectID: "prj-a", ClusterID: "clu-b", Health: "MAGIC", ObservedAt: now.Add(-time.Minute)},
	}
	projection := projectServiceHealth("prj-a", now, clusters, observations, false)
	for _, item := range projection.Clusters {
		if item.Health != serviceHealthCoverageUnknown || item.CoverageStatus != serviceHealthCoverageUnknown {
			t.Fatalf("invalid observation claimed authoritative health: %#v", item)
		}
	}
}

func TestProjectServiceHealthTruncationInvalidatesClaims(t *testing.T) {
	now := time.Date(2026, 9, 14, 7, 0, 0, 0, time.UTC)
	clusters := []controlplane.ManagedCluster{{ID: "clu-a", ProjectID: "prj-a"}}
	observations := []reliability.HealthObservation{{ProjectID: "prj-a", ClusterID: "clu-a", Health: "HEALTHY", ObservedAt: now.Add(-time.Minute)}}
	projection := projectServiceHealth("prj-a", now, clusters, observations, true)
	if !projection.Truncated || projection.CoverageStatus != serviceHealthCoverageUnknown || projection.Clusters[0].Health != serviceHealthCoverageUnknown {
		t.Fatalf("truncated projection must fail closed: %#v", projection)
	}
}
