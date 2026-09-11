package controlplane

import (
	"strings"
	"testing"
	"time"
)

func allUsageMetrics(value int64) map[FinOpsUsageMetric]FinOpsMetricSample {
	return map[FinOpsUsageMetric]FinOpsMetricSample{
		FinOpsCPUCoreHour:     {Available: true, QuantityMicros: value},
		FinOpsMemoryGiBHour:   {Available: true, QuantityMicros: value},
		FinOpsStorageGiBHour:  {Available: true, QuantityMicros: value},
		FinOpsAcceleratorHour: {Available: true, QuantityMicros: value},
	}
}

func allCapacityMetrics(value int64) map[FinOpsCapacityMetric]FinOpsMetricSample {
	return map[FinOpsCapacityMetric]FinOpsMetricSample{
		FinOpsCPUCore:     {Available: true, QuantityMicros: value},
		FinOpsMemoryGiB:   {Available: true, QuantityMicros: value},
		FinOpsStorageGiB:  {Available: true, QuantityMicros: value},
		FinOpsAccelerator: {Available: true, QuantityMicros: value},
	}
}

func TestNormalizeFinOpsUsageDistinguishesMissingFromExplicitZero(t *testing.T) {
	start := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	base := FinOpsUsageMeasurement{
		OrganizationID: "org_1", ProjectID: "prj_1", Source: "prometheus", SourceEventID: "window-1",
		WindowStart: start, WindowEnd: start.Add(time.Hour), Metrics: allUsageMetrics(0),
	}
	explicit, err := NormalizeFinOpsUsageMeasurement(base)
	if err != nil {
		t.Fatal(err)
	}
	missingInput := base
	missingInput.Metrics = allUsageMetrics(0)
	missingInput.Metrics[FinOpsStorageGiBHour] = FinOpsMetricSample{Available: false}
	missing, err := NormalizeFinOpsUsageMeasurement(missingInput)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Digest == missing.Digest {
		t.Fatal("missing telemetry and explicit zero produced the same digest")
	}
	if !explicit.Metrics[FinOpsStorageGiBHour].Available || missing.Metrics[FinOpsStorageGiBHour].Available {
		t.Fatalf("availability truth lost: explicit=%+v missing=%+v", explicit.Metrics[FinOpsStorageGiBHour], missing.Metrics[FinOpsStorageGiBHour])
	}
}

func TestNormalizeFinOpsUsageRequiresExplicitStateForAllMetrics(t *testing.T) {
	start := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	_, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{
		OrganizationID: "org_1", ProjectID: "prj_1", Source: "meter", SourceEventID: "partial",
		WindowStart: start, WindowEnd: start.Add(time.Hour),
		Metrics: map[FinOpsUsageMetric]FinOpsMetricSample{FinOpsCPUCoreHour: {Available: true, QuantityMicros: 1}},
	})
	if err == nil {
		t.Fatal("partial metric state was admitted")
	}
}

func TestNormalizeFinOpsRateCardAndCapacityAreDeterministic(t *testing.T) {
	at := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	card, err := NormalizeFinOpsRateCard(FinOpsRateCard{
		OrganizationID: " org_1 ", Name: " Standard ", Version: "2026.09", Currency: "eur", EffectiveFrom: at,
		Rates: map[FinOpsUsageMetric]int64{
			FinOpsStorageGiBHour: 10000, FinOpsCPUCoreHour: 250000,
			FinOpsMemoryGiBHour: 30000, FinOpsAcceleratorHour: 5000000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if card.Currency != "EUR" || card.OrganizationID != "org_1" || card.Digest == "" {
		t.Fatalf("normalized card=%+v", card)
	}
	same, err := NormalizeFinOpsRateCard(card)
	if err != nil || same.Digest != card.Digest {
		t.Fatalf("rate card digest is not stable: %v %q %q", err, card.Digest, same.Digest)
	}

	obs, err := NormalizeFinOpsCapacityObservation(FinOpsCapacityObservation{
		OrganizationID: "org_1", ProjectID: "prj_1", ClusterID: "cluster_1", Source: "inventory", SourceEventID: "cap-1",
		ObservedAt: at, Metrics: allCapacityMetrics(1_000_000),
	})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Digest == "" || !obs.Metrics[FinOpsCPUCore].Available {
		t.Fatalf("capacity=%+v", obs)
	}
}

func TestBuildFinOpsShowbackDoesNotRenderMissingTelemetryAsZeroCost(t *testing.T) {
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: 2_000_000}
	metrics[FinOpsStorageGiBHour] = FinOpsMetricSample{Available: false}
	measurement, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{
		OrganizationID: "org_1", ProjectID: "prj_1", ClusterID: "cluster_a", WorkspaceID: "ws_a", Namespace: "payments",
		Source: "meter", SourceEventID: "u1", WindowStart: start, WindowEnd: start.Add(time.Hour), Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	card, err := NormalizeFinOpsRateCard(FinOpsRateCard{
		OrganizationID: "org_1", Name: "standard", Version: "1", Currency: "EUR", EffectiveFrom: start.Add(-time.Hour), EffectiveUntil: ptrTime(start.Add(24 * time.Hour)),
		Rates: map[FinOpsUsageMetric]int64{FinOpsCPUCoreHour: 1_500_000, FinOpsMemoryGiBHour: 100_000, FinOpsStorageGiBHour: 10_000, FinOpsAcceleratorHour: 5_000_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR", GroupBy: FinOpsGroupNamespace, WindowStart: start, WindowEnd: start.Add(2 * time.Hour)}, []FinOpsUsageMeasurement{measurement}, []FinOpsRateCard{card})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("showback incorrectly complete with missing telemetry")
	}
	if result.TotalCostMicros != nil {
		t.Fatalf("missing telemetry rendered as total cost %d", *result.TotalCostMicros)
	}
	if result.KnownCostMicros != 3_000_000 {
		t.Fatalf("known cost=%d want=3000000", result.KnownCostMicros)
	}
	if len(result.Groups) != 1 || result.Groups[0].Key != "payments" || result.Groups[0].TotalCostMicros != nil {
		t.Fatalf("groups=%+v", result.Groups)
	}
	if len(result.MissingTelemetry) == 0 {
		t.Fatalf("missing telemetry not surfaced: %+v", result)
	}
}

func TestBuildFinOpsShowbackAggregatesByDimensionWithIntegerMoney(t *testing.T) {
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	card, err := NormalizeFinOpsRateCard(FinOpsRateCard{
		OrganizationID: "org_1", Name: "standard", Version: "1", Currency: "EUR", EffectiveFrom: start,
		Rates: map[FinOpsUsageMetric]int64{FinOpsCPUCoreHour: 2_500_000, FinOpsMemoryGiBHour: 0, FinOpsStorageGiBHour: 0, FinOpsAcceleratorHour: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	makeUsage := func(event, ns string, cpu int64) FinOpsUsageMeasurement {
		metrics := allUsageMetrics(0)
		metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: cpu}
		v, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{OrganizationID: "org_1", ProjectID: "prj_1", ClusterID: "cluster_a", WorkspaceID: "ws_a", Namespace: ns, Source: "meter", SourceEventID: event, WindowStart: start, WindowEnd: start.Add(time.Hour), Metrics: metrics})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	result, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR", GroupBy: FinOpsGroupNamespace, WindowStart: start, WindowEnd: start.Add(2 * time.Hour)}, []FinOpsUsageMeasurement{makeUsage("u1", "payments", 1_000_000), makeUsage("u2", "search", 2_000_000)}, []FinOpsRateCard{card})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.TotalCostMicros == nil || *result.TotalCostMicros != 7_500_000 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Groups) != 2 {
		t.Fatalf("groups=%+v", result.Groups)
	}
}

func TestBuildFinOpsShowbackRequiresOneRateCardToCoverWholeMeasurement(t *testing.T) {
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: 1_000_000}
	usage, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{OrganizationID: "org_1", ProjectID: "prj_1", Source: "meter", SourceEventID: "cross", WindowStart: start, WindowEnd: start.Add(2 * time.Hour), Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	end := start.Add(time.Hour)
	card, err := NormalizeFinOpsRateCard(FinOpsRateCard{OrganizationID: "org_1", Name: "first", Version: "1", Currency: "EUR", EffectiveFrom: start, EffectiveUntil: &end, Rates: map[FinOpsUsageMetric]int64{FinOpsCPUCoreHour: 1_000_000}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: "org_1", ProjectID: "prj_1", Currency: "EUR", GroupBy: FinOpsGroupProject, WindowStart: start, WindowEnd: start.Add(3 * time.Hour)}, []FinOpsUsageMeasurement{usage}, []FinOpsRateCard{card})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.TotalCostMicros != nil || len(result.MissingRateCardMeasurements) != 1 {
		t.Fatalf("boundary gap not fail-closed: %+v", result)
	}
}

func ptrTime(v time.Time) *time.Time { return &v }

func TestFinOpsChargebackCSVIsDeterministicAndOmitsIncompleteTotal(t *testing.T) {
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: 1_000_000}
	metrics[FinOpsMemoryGiBHour] = FinOpsMetricSample{Available: false, QuantityMicros: 0}
	usage, err := NormalizeFinOpsUsageMeasurement(FinOpsUsageMeasurement{OrganizationID: "org-a", ProjectID: "project-a", Source: "meter", SourceEventID: "evt-export", WindowStart: start, WindowEnd: start.Add(time.Hour), Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	card, err := NormalizeFinOpsRateCard(FinOpsRateCard{OrganizationID: "org-a", Name: "standard", Version: "1", Currency: "EUR", EffectiveFrom: start, Rates: map[FinOpsUsageMetric]int64{FinOpsCPUCoreHour: 1_000_000, FinOpsMemoryGiBHour: 100_000, FinOpsStorageGiBHour: 10_000, FinOpsAcceleratorHour: 5_000_000}})
	if err != nil {
		t.Fatal(err)
	}
	showback, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: "org-a", ProjectID: "project-a", Currency: "EUR", GroupBy: FinOpsGroupProject, WindowStart: start, WindowEnd: start.Add(time.Hour)}, []FinOpsUsageMeasurement{usage}, []FinOpsRateCard{card})
	if err != nil {
		t.Fatal(err)
	}
	first, digest1, err := FinOpsChargebackCSV(showback)
	if err != nil {
		t.Fatal(err)
	}
	second, digest2, err := FinOpsChargebackCSV(showback)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || digest1 != digest2 {
		t.Fatal("chargeback CSV is not deterministic")
	}
	if !strings.Contains(string(first), "known_cost_micros,total_cost_micros,complete") {
		t.Fatalf("unexpected CSV: %s", first)
	}
	if strings.Contains(string(first), ",1000000,true\n") {
		t.Fatalf("incomplete export exposed a total: %s", first)
	}
	if !strings.HasPrefix(digest1, "sha256:") {
		t.Fatalf("bad digest %q", digest1)
	}
}
