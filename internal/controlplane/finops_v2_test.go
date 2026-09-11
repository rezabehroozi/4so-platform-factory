package controlplane

import (
	"testing"
	"time"
)

func TestNormalizeFinOpsBudgetPolicyRejectsInvalidThresholdsAndIsDeterministic(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	policy, err := NormalizeFinOpsBudgetPolicy(FinOpsBudgetPolicy{
		OrganizationID: " org_1 ", ProjectID: " prj_1 ", Name: "monthly", Version: "1", Currency: "eur",
		EffectiveFrom: start, LimitMicros: 100_000_000, WarningBasisPoints: 8000, CriticalBasisPoints: 10000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Authority != FinOpsBudgetPolicyAuthority || policy.OrganizationID != "org_1" || policy.ProjectID != "prj_1" || policy.Currency != "EUR" || policy.Digest == "" {
		t.Fatalf("unexpected normalized budget policy: %#v", policy)
	}
	again, err := NormalizeFinOpsBudgetPolicy(policy)
	if err != nil || again.Digest != policy.Digest {
		t.Fatalf("budget digest must be deterministic: %#v %v", again, err)
	}
	bad := policy
	bad.WarningBasisPoints = 11000
	bad.CriticalBasisPoints = 10000
	if _, err := NormalizeFinOpsBudgetPolicy(bad); err == nil {
		t.Fatal("expected invalid threshold order rejection")
	}
}

func completeUsageForV2(org, project, event string, start, end time.Time, cpuMicros, memoryMicros int64) FinOpsUsageMeasurement {
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: cpuMicros}
	metrics[FinOpsMemoryGiBHour] = FinOpsMetricSample{Available: true, QuantityMicros: memoryMicros}
	v, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{
		OrganizationID: org, ProjectID: project, Source: "meter", SourceEventID: event,
		WindowStart: start, WindowEnd: end, Metrics: metrics,
	})
	if err != nil {
		panic(err)
	}
	return v
}

func fullRateForV2(org string, start time.Time) FinOpsRateCard {
	v, err := NormalizeFinOpsRateCard(FinOpsRateCard{
		OrganizationID: org, Name: "standard", Version: "1", Currency: "EUR", EffectiveFrom: start,
		Rates: map[FinOpsUsageMetric]int64{
			FinOpsCPUCoreHour: 1_000_000, FinOpsMemoryGiBHour: 100_000,
			FinOpsStorageGiBHour: 10_000, FinOpsAcceleratorHour: 5_000_000,
		},
	})
	if err != nil {
		panic(err)
	}
	v.ID = "frc_1"
	return v
}

func TestBuildFinOpsInsightsFailsClosedWhenShowbackIncomplete(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: false}
	usage, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{OrganizationID: "org_1", ProjectID: "prj_1", Source: "meter", SourceEventID: "u1", WindowStart: start, WindowEnd: start.Add(24 * time.Hour), Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	insight, err := BuildFinOpsInsights(FinOpsInsightQuery{OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR", WindowStart: start, ObservedThrough: start.Add(24 * time.Hour), ForecastEnd: start.Add(30 * 24 * time.Hour)}, []FinOpsUsageMeasurement{usage}, []FinOpsRateCard{fullRateForV2("org_1", start)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if insight.Forecast.Status != FinOpsInsightUnknown || insight.Forecast.ProjectedCostMicros != nil {
		t.Fatalf("incomplete telemetry must not produce numeric forecast: %#v", insight.Forecast)
	}
	if insight.Anomaly.Status != FinOpsInsightUnknown {
		t.Fatalf("anomaly must fail closed: %#v", insight.Anomaly)
	}
}

func TestBuildFinOpsInsightsForecastBudgetAnomalyAndRightsizing(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	observed := start.Add(4 * 24 * time.Hour)
	forecastEnd := start.Add(8 * 24 * time.Hour)
	// Baseline: 3 days at 1 CPU core-hour / hour; recent day doubles to 2.
	usage := []FinOpsUsageMeasurement{
		completeUsageForV2("org_1", "prj_1", "d1", start, start.Add(24*time.Hour), 24_000_000, 48_000_000),
		completeUsageForV2("org_1", "prj_1", "d2", start.Add(24*time.Hour), start.Add(48*time.Hour), 24_000_000, 48_000_000),
		completeUsageForV2("org_1", "prj_1", "d3", start.Add(48*time.Hour), start.Add(72*time.Hour), 24_000_000, 48_000_000),
		completeUsageForV2("org_1", "prj_1", "d4", start.Add(72*time.Hour), observed, 48_000_000, 96_000_000),
	}
	policy, err := NormalizeFinOpsBudgetPolicy(FinOpsBudgetPolicy{OrganizationID: "org_1", ProjectID: "prj_1", Name: "monthly", Version: "1", Currency: "EUR", EffectiveFrom: start, LimitMicros: 250_000_000, WarningBasisPoints: 8000, CriticalBasisPoints: 10000})
	if err != nil {
		t.Fatal(err)
	}
	policy.ID = "fbp_1"
	capMetrics := allCapacityMetrics(0)
	capMetrics[FinOpsCPUCore] = FinOpsMetricSample{Available: true, QuantityMicros: 20_000_000}
	capMetrics[FinOpsMemoryGiB] = FinOpsMetricSample{Available: true, QuantityMicros: 100_000_000}
	capObs, err := NormalizeFinOpsCapacityObservation(FinOpsCapacityObservation{OrganizationID: "org_1", ProjectID: "prj_1", Source: "inventory", SourceEventID: "cap1", ObservedAt: observed, Metrics: capMetrics})
	if err != nil {
		t.Fatal(err)
	}

	insight, err := BuildFinOpsInsights(FinOpsInsightQuery{OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR", WindowStart: start, ObservedThrough: observed, ForecastEnd: forecastEnd}, usage, []FinOpsRateCard{fullRateForV2("org_1", start)}, []FinOpsCapacityObservation{capObs}, []FinOpsBudgetPolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if insight.Forecast.Status != FinOpsInsightReady || insight.Forecast.ProjectedCostMicros == nil || *insight.Forecast.ProjectedCostMicros <= insight.Showback.KnownCostMicros {
		t.Fatalf("expected complete numeric forecast: %#v showback=%#v", insight.Forecast, insight.Showback)
	}
	if len(insight.Budgets) != 1 || insight.Budgets[0].Status == FinOpsInsightUnknown || insight.Budgets[0].ProjectedBasisPoints <= 0 {
		t.Fatalf("expected evaluated budget: %#v", insight.Budgets)
	}
	if insight.Anomaly.Status != FinOpsInsightReady || insight.Anomaly.Severity != "HIGH" || insight.Anomaly.RatioBasisPoints < 20000 {
		t.Fatalf("expected high spend-rate anomaly: %#v", insight.Anomaly)
	}
	if len(insight.Rightsizing) != 2 {
		t.Fatalf("expected cpu/memory rightsizing: %#v", insight.Rightsizing)
	}
	for _, r := range insight.Rightsizing {
		if r.Automatable {
			t.Fatalf("rightsizing must never auto-apply: %#v", r)
		}
		if r.Status != FinOpsInsightReady {
			t.Fatalf("expected evidence-backed rightsizing: %#v", r)
		}
	}
}

func TestBuildFinOpsInsightsRightsizingRejectsStaleCapacityEvidence(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	observed := start.Add(4 * 24 * time.Hour)
	usage := []FinOpsUsageMeasurement{
		completeUsageForV2("org_1", "prj_1", "u1", start, observed, 96_000_000, 192_000_000),
	}
	capMetrics := allCapacityMetrics(0)
	capMetrics[FinOpsCPUCore] = FinOpsMetricSample{Available: true, QuantityMicros: 20_000_000}
	capMetrics[FinOpsMemoryGiB] = FinOpsMetricSample{Available: true, QuantityMicros: 100_000_000}
	stale, err := NormalizeFinOpsCapacityObservation(FinOpsCapacityObservation{
		OrganizationID: "org_1", ProjectID: "prj_1", Source: "inventory", SourceEventID: "stale-cap",
		ObservedAt: observed.Add(-25 * time.Hour), Metrics: capMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	stale.ID = "fco_stale"
	insight, err := BuildFinOpsInsights(FinOpsInsightQuery{
		OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR",
		WindowStart: start, ObservedThrough: observed, ForecastEnd: observed.Add(24 * time.Hour),
	}, usage, []FinOpsRateCard{fullRateForV2("org_1", start)}, []FinOpsCapacityObservation{stale}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(insight.Rightsizing) != 2 {
		t.Fatalf("rightsizing=%#v", insight.Rightsizing)
	}
	for _, rec := range insight.Rightsizing {
		if rec.Status != FinOpsInsightUnknown || rec.Action != "UNKNOWN" || rec.EvidenceObservationID != "" {
			t.Fatalf("stale capacity must fail closed: %#v", rec)
		}
		if rec.Reason != "fresh project aggregate capacity observation is unavailable" {
			t.Fatalf("unexpected stale-capacity reason: %#v", rec)
		}
	}
}
