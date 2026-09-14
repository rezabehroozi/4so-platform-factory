package reliability

import (
	"testing"
	"time"
)

func TestHealthObservationIdentityIsDeterministicAndContentBound(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	base := HealthObservation{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Health: "DEGRADED", ObservedAt: now, SourceDigest: "sha256:abc"}
	first, err := ObservationIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ObservationIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("identity must be deterministic: first=%q second=%q", first, second)
	}
	changed := base
	changed.SourceDigest = "sha256:def"
	third, err := ObservationIdentity(changed)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatalf("identity must bind source digest: %q", third)
	}
}

func TestIncidentLifecycleRequiresActorAndResolutionSummary(t *testing.T) {
	incident := Incident{ID: "inc-1", OrganizationID: "org-1", ProjectID: "prj-1", Severity: "CRITICAL", State: IncidentOpen, Revision: 1}
	if _, err := TransitionIncident(incident, IncidentActionAcknowledge, "", ""); err == nil {
		t.Fatal("acknowledge without actor must fail")
	}
	ack, err := TransitionIncident(incident, IncidentActionAcknowledge, "user-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if ack.State != IncidentAcknowledged || ack.Revision != 2 || ack.AcknowledgedBy != "user-1" {
		t.Fatalf("unexpected acknowledged incident: %#v", ack)
	}
	if _, err := TransitionIncident(ack, IncidentActionResolve, "user-1", ""); err == nil {
		t.Fatal("resolve without summary must fail")
	}
	resolved, err := TransitionIncident(ack, IncidentActionResolve, "user-2", "service recovered")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != IncidentResolved || resolved.Revision != 3 || resolved.ResolvedBy != "user-2" || resolved.ResolutionSummary != "service recovered" {
		t.Fatalf("unexpected resolved incident: %#v", resolved)
	}
	if _, err := TransitionIncident(resolved, IncidentActionAcknowledge, "user-3", ""); err == nil {
		t.Fatal("resolved incident must not reopen through acknowledge")
	}
}

func TestSLOPolicyRejectsInvalidObjectiveAndWindow(t *testing.T) {
	valid := SLOPolicy{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 60}
	if err := ValidateSLOPolicy(valid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for name, policy := range map[string]SLOPolicy{
		"zero-objective":        {OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 0, WindowSeconds: 3600, ObservationIntervalSeconds: 60},
		"objective-over-10000": {OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 10001, WindowSeconds: 3600, ObservationIntervalSeconds: 60},
		"zero-window":           {OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 0, ObservationIntervalSeconds: 60},
		"zero-interval":         {OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 0},
	} {
		if err := ValidateSLOPolicy(policy); err == nil {
			t.Fatalf("%s must fail validation", name)
		}
	}
}

func TestSLOPolicyRequiresExplicitClusterTarget(t *testing.T) {
	policy := SLOPolicy{OrganizationID: "org-1", ProjectID: "prj-1", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 60}
	if err := ValidateSLOPolicy(policy); err == nil {
		t.Fatal("SLO policy without a cluster target must fail closed")
	}
}

func TestErrorBudgetIsUnknownWhenObservationCoverageIsIncomplete(t *testing.T) {
	start := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	policy := SLOPolicy{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 60}
	observations := []HealthObservation{
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Health: "HEALTHY", ObservedAt: start, SourceDigest: "sha256:a"},
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-1", Health: "CRITICAL", ObservedAt: start.Add(30 * time.Minute), SourceDigest: "sha256:b"},
	}
	projection, err := ProjectErrorBudget(policy, observations, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if projection.CoverageStatus != CoverageUnknown {
		t.Fatalf("coverage=%s want=%s", projection.CoverageStatus, CoverageUnknown)
	}
	if projection.RemainingBudgetBasisPoints != nil || projection.BurnRatioMilli != nil {
		t.Fatalf("unknown coverage must not publish numeric budget claims: %#v", projection)
	}
}

func TestErrorBudgetIgnoresObservationsFromOtherClusters(t *testing.T) {
	start := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Minute)
	policy := SLOPolicy{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-target", Name: "api", ObjectiveBasisPoints: 9990, WindowSeconds: 120, ObservationIntervalSeconds: 60}
	observations := []HealthObservation{
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-target", Health: "HEALTHY", ObservedAt: start, SourceDigest: "sha256:a"},
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-target", Health: "HEALTHY", ObservedAt: start.Add(time.Minute), SourceDigest: "sha256:b"},
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-other", Health: "CRITICAL", ObservedAt: start, SourceDigest: "sha256:c"},
		{OrganizationID: "org-1", ProjectID: "prj-1", ClusterID: "clu-other", Health: "CRITICAL", ObservedAt: start.Add(time.Minute), SourceDigest: "sha256:d"},
	}
	projection, err := ProjectErrorBudget(policy, observations, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if projection.CoverageStatus != CoverageComplete || projection.ObservedObservations != 2 || projection.BadObservations != 0 {
		t.Fatalf("foreign cluster observations poisoned target SLO coverage: %#v", projection)
	}
	if projection.RemainingBudgetBasisPoints == nil || projection.BurnRatioMilli == nil || *projection.BurnRatioMilli != 0 {
		t.Fatalf("complete target coverage must publish a zero-burn budget projection: %#v", projection)
	}
}
