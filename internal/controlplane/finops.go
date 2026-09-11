package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	FinOpsRateCardAuthority            = "FINOPS_RATE_CARD_AUTHORITY_V1"
	FinOpsUsageMeasurementAuthority    = "FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1"
	FinOpsCapacityObservationAuthority = "FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1"
	FinOpsChargebackAuthority          = "FINOPS_CHARGEBACK_AUTHORITY_V1"
)

type FinOpsUsageMetric string

const (
	FinOpsCPUCoreHour     FinOpsUsageMetric = "CPU_CORE_HOUR"
	FinOpsMemoryGiBHour   FinOpsUsageMetric = "MEMORY_GIB_HOUR"
	FinOpsStorageGiBHour  FinOpsUsageMetric = "STORAGE_GIB_HOUR"
	FinOpsAcceleratorHour FinOpsUsageMetric = "ACCELERATOR_HOUR"
)

var finOpsUsageMetrics = []FinOpsUsageMetric{FinOpsCPUCoreHour, FinOpsMemoryGiBHour, FinOpsStorageGiBHour, FinOpsAcceleratorHour}

type FinOpsCapacityMetric string

const (
	FinOpsCPUCore     FinOpsCapacityMetric = "CPU_CORE"
	FinOpsMemoryGiB   FinOpsCapacityMetric = "MEMORY_GIB"
	FinOpsStorageGiB  FinOpsCapacityMetric = "STORAGE_GIB"
	FinOpsAccelerator FinOpsCapacityMetric = "ACCELERATOR"
)

var finOpsCapacityMetrics = []FinOpsCapacityMetric{FinOpsCPUCore, FinOpsMemoryGiB, FinOpsStorageGiB, FinOpsAccelerator}

type FinOpsMetricSample struct {
	Available      bool  `json:"available"`
	QuantityMicros int64 `json:"quantityMicros"`
}

type FinOpsRateCard struct {
	ResourceMeta
	Authority      string                      `json:"authority"`
	OrganizationID string                      `json:"organizationId"`
	Name           string                      `json:"name"`
	Version        string                      `json:"version"`
	Currency       string                      `json:"currency"`
	EffectiveFrom  time.Time                   `json:"effectiveFrom"`
	EffectiveUntil *time.Time                  `json:"effectiveUntil,omitempty"`
	Rates          map[FinOpsUsageMetric]int64 `json:"rates"`
	Digest         string                      `json:"digest"`
}

type FinOpsUsageMeasurement struct {
	ResourceMeta
	Authority      string                                   `json:"authority"`
	OrganizationID string                                   `json:"organizationId"`
	ProjectID      string                                   `json:"projectId"`
	ClusterID      string                                   `json:"clusterId,omitempty"`
	WorkspaceID    string                                   `json:"workspaceId,omitempty"`
	Namespace      string                                   `json:"namespace,omitempty"`
	Source         string                                   `json:"source"`
	SourceEventID  string                                   `json:"sourceEventId"`
	WindowStart    time.Time                                `json:"windowStart"`
	WindowEnd      time.Time                                `json:"windowEnd"`
	Metrics        map[FinOpsUsageMetric]FinOpsMetricSample `json:"metrics"`
	Digest         string                                   `json:"digest"`
}

type FinOpsCapacityObservation struct {
	ResourceMeta
	Authority      string                                      `json:"authority"`
	OrganizationID string                                      `json:"organizationId"`
	ProjectID      string                                      `json:"projectId"`
	ClusterID      string                                      `json:"clusterId,omitempty"`
	Source         string                                      `json:"source"`
	SourceEventID  string                                      `json:"sourceEventId"`
	ObservedAt     time.Time                                   `json:"observedAt"`
	Metrics        map[FinOpsCapacityMetric]FinOpsMetricSample `json:"metrics"`
	Digest         string                                      `json:"digest"`
}

type FinOpsGroupBy string

const (
	FinOpsGroupProject   FinOpsGroupBy = "PROJECT"
	FinOpsGroupCluster   FinOpsGroupBy = "CLUSTER"
	FinOpsGroupWorkspace FinOpsGroupBy = "WORKSPACE"
	FinOpsGroupNamespace FinOpsGroupBy = "NAMESPACE"
)

type FinOpsShowbackQuery struct {
	OrganizationID string        `json:"organizationId"`
	ProjectID      string        `json:"projectId,omitempty"`
	Currency       string        `json:"currency"`
	GroupBy        FinOpsGroupBy `json:"groupBy"`
	WindowStart    time.Time     `json:"windowStart"`
	WindowEnd      time.Time     `json:"windowEnd"`
}

type FinOpsMetricCharge struct {
	Metric             FinOpsUsageMetric `json:"metric"`
	QuantityMicros     int64             `json:"quantityMicros"`
	PriceMicrosPerUnit int64             `json:"priceMicrosPerUnit"`
	KnownCostMicros    int64             `json:"knownCostMicros"`
	Complete           bool              `json:"complete"`
	MissingTelemetry   bool              `json:"missingTelemetry"`
	MissingRate        bool              `json:"missingRate"`
}

type FinOpsShowbackGroup struct {
	Key                  string               `json:"key"`
	AttributionComplete  bool                 `json:"attributionComplete"`
	KnownCostMicros      int64                `json:"knownCostMicros"`
	TotalCostMicros      *int64               `json:"totalCostMicros,omitempty"`
	Complete             bool                 `json:"complete"`
	MeasurementCount     int                  `json:"measurementCount"`
	Charges              []FinOpsMetricCharge `json:"charges"`
	MissingTelemetry     []FinOpsUsageMetric  `json:"missingTelemetry,omitempty"`
	MissingRates         []FinOpsUsageMetric  `json:"missingRates,omitempty"`
	MissingRateCardCount int                  `json:"missingRateCardCount,omitempty"`
}

type FinOpsShowback struct {
	Authority                   string                `json:"authority"`
	OrganizationID              string                `json:"organizationId"`
	ProjectID                   string                `json:"projectId,omitempty"`
	Currency                    string                `json:"currency"`
	GroupBy                     FinOpsGroupBy         `json:"groupBy"`
	WindowStart                 time.Time             `json:"windowStart"`
	WindowEnd                   time.Time             `json:"windowEnd"`
	MeasurementCount            int                   `json:"measurementCount"`
	KnownCostMicros             int64                 `json:"knownCostMicros"`
	TotalCostMicros             *int64                `json:"totalCostMicros,omitempty"`
	Complete                    bool                  `json:"complete"`
	AttributionComplete         bool                  `json:"attributionComplete"`
	MissingTelemetry            []FinOpsUsageMetric   `json:"missingTelemetry,omitempty"`
	MissingRates                []FinOpsUsageMetric   `json:"missingRates,omitempty"`
	MissingRateCardMeasurements []string              `json:"missingRateCardMeasurements,omitempty"`
	RateCardIDs                 []string              `json:"rateCardIds,omitempty"`
	Groups                      []FinOpsShowbackGroup `json:"groups"`
	Digest                      string                `json:"digest"`
}

var finOpsCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
var finOpsSourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func finOpsSHA(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeFinOpsInterval(from time.Time, until *time.Time) (time.Time, *time.Time, error) {
	if from.IsZero() {
		return time.Time{}, nil, fmt.Errorf("%w: effectiveFrom is required", ErrValidation)
	}
	from = from.UTC().Truncate(time.Microsecond)
	if until == nil {
		return from, nil, nil
	}
	u := until.UTC().Truncate(time.Microsecond)
	if !u.After(from) {
		return time.Time{}, nil, fmt.Errorf("%w: effectiveUntil must be after effectiveFrom", ErrValidation)
	}
	return from, &u, nil
}

func validUsageMetric(metric FinOpsUsageMetric) bool {
	for _, v := range finOpsUsageMetrics {
		if metric == v {
			return true
		}
	}
	return false
}
func validCapacityMetric(metric FinOpsCapacityMetric) bool {
	for _, v := range finOpsCapacityMetrics {
		if metric == v {
			return true
		}
	}
	return false
}

func NormalizeFinOpsRateCard(in FinOpsRateCard) (FinOpsRateCard, error) {
	in.Authority = FinOpsRateCardAuthority
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.Name = strings.TrimSpace(in.Name)
	in.Version = strings.TrimSpace(in.Version)
	in.Currency = strings.ToUpper(strings.TrimSpace(in.Currency))
	if in.OrganizationID == "" || in.Name == "" || in.Version == "" {
		return FinOpsRateCard{}, fmt.Errorf("%w: organizationId, name and version are required", ErrValidation)
	}
	if len(in.Name) > 120 || len(in.Version) > 64 {
		return FinOpsRateCard{}, fmt.Errorf("%w: FinOps rate-card name/version is too long", ErrValidation)
	}
	if !finOpsCurrencyPattern.MatchString(in.Currency) {
		return FinOpsRateCard{}, fmt.Errorf("%w: currency must be a three-letter ISO-style code", ErrValidation)
	}
	var err error
	in.EffectiveFrom, in.EffectiveUntil, err = normalizeFinOpsInterval(in.EffectiveFrom, in.EffectiveUntil)
	if err != nil {
		return FinOpsRateCard{}, err
	}
	if len(in.Rates) == 0 {
		return FinOpsRateCard{}, fmt.Errorf("%w: at least one FinOps rate is required", ErrValidation)
	}
	rates := make(map[FinOpsUsageMetric]int64, len(in.Rates))
	for metric, price := range in.Rates {
		if !validUsageMetric(metric) || price < 0 {
			return FinOpsRateCard{}, fmt.Errorf("%w: invalid FinOps rate %q", ErrValidation, metric)
		}
		rates[metric] = price
	}
	in.Rates = rates
	type rateKV struct {
		Metric             FinOpsUsageMetric `json:"metric"`
		PriceMicrosPerUnit int64             `json:"priceMicrosPerUnit"`
	}
	ordered := make([]rateKV, 0, len(rates))
	for metric, price := range rates {
		ordered = append(ordered, rateKV{metric, price})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Metric < ordered[j].Metric })
	in.Digest = finOpsSHA(struct {
		Authority      string     `json:"authority"`
		OrganizationID string     `json:"organizationId"`
		Name           string     `json:"name"`
		Version        string     `json:"version"`
		Currency       string     `json:"currency"`
		EffectiveFrom  time.Time  `json:"effectiveFrom"`
		EffectiveUntil *time.Time `json:"effectiveUntil,omitempty"`
		Rates          []rateKV   `json:"rates"`
	}{in.Authority, in.OrganizationID, in.Name, in.Version, in.Currency, in.EffectiveFrom, in.EffectiveUntil, ordered})
	return in, nil
}

func normalizeFinOpsSource(source, event string) (string, string, error) {
	source = strings.TrimSpace(source)
	event = strings.TrimSpace(event)
	if !finOpsSourcePattern.MatchString(source) || event == "" || len(event) > 200 || strings.ContainsAny(event, "\r\n\x00") {
		return "", "", fmt.Errorf("%w: bounded source and sourceEventId are required", ErrValidation)
	}
	return source, event, nil
}

func NormalizeFinOpsUsageMeasurement(in FinOpsUsageMeasurement) (FinOpsUsageMeasurement, error) {
	in.Authority = FinOpsUsageMeasurementAuthority
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ClusterID = strings.TrimSpace(in.ClusterID)
	in.WorkspaceID = strings.TrimSpace(in.WorkspaceID)
	in.Namespace = strings.TrimSpace(in.Namespace)
	if in.OrganizationID == "" || in.ProjectID == "" {
		return FinOpsUsageMeasurement{}, fmt.Errorf("%w: organizationId and projectId are required", ErrValidation)
	}
	if len(in.Namespace) > 253 {
		return FinOpsUsageMeasurement{}, fmt.Errorf("%w: namespace is too long", ErrValidation)
	}
	var err error
	in.Source, in.SourceEventID, err = normalizeFinOpsSource(in.Source, in.SourceEventID)
	if err != nil {
		return FinOpsUsageMeasurement{}, err
	}
	if in.WindowStart.IsZero() || in.WindowEnd.IsZero() || !in.WindowEnd.After(in.WindowStart) {
		return FinOpsUsageMeasurement{}, fmt.Errorf("%w: a positive usage window is required", ErrValidation)
	}
	in.WindowStart = in.WindowStart.UTC().Truncate(time.Microsecond)
	in.WindowEnd = in.WindowEnd.UTC().Truncate(time.Microsecond)
	if len(in.Metrics) != len(finOpsUsageMetrics) {
		return FinOpsUsageMeasurement{}, fmt.Errorf("%w: explicit state for all FinOps usage metrics is required", ErrValidation)
	}
	metrics := make(map[FinOpsUsageMetric]FinOpsMetricSample, len(finOpsUsageMetrics))
	type metricKV struct {
		Metric         FinOpsUsageMetric `json:"metric"`
		Available      bool              `json:"available"`
		QuantityMicros int64             `json:"quantityMicros"`
	}
	ordered := make([]metricKV, 0, len(finOpsUsageMetrics))
	for _, metric := range finOpsUsageMetrics {
		sample, ok := in.Metrics[metric]
		if !ok || sample.QuantityMicros < 0 || (!sample.Available && sample.QuantityMicros != 0) {
			return FinOpsUsageMeasurement{}, fmt.Errorf("%w: invalid or missing metric state %q", ErrValidation, metric)
		}
		metrics[metric] = sample
		ordered = append(ordered, metricKV{metric, sample.Available, sample.QuantityMicros})
	}
	for metric := range in.Metrics {
		if !validUsageMetric(metric) {
			return FinOpsUsageMeasurement{}, fmt.Errorf("%w: unsupported usage metric %q", ErrValidation, metric)
		}
	}
	in.Metrics = metrics
	in.Digest = finOpsSHA(struct {
		Authority, OrganizationID, ProjectID, ClusterID, WorkspaceID, Namespace, Source, SourceEventID string
		WindowStart, WindowEnd                                                                         time.Time
		Metrics                                                                                        []metricKV
	}{in.Authority, in.OrganizationID, in.ProjectID, in.ClusterID, in.WorkspaceID, in.Namespace, in.Source, in.SourceEventID, in.WindowStart, in.WindowEnd, ordered})
	return in, nil
}

func NormalizeFinOpsCapacityObservation(in FinOpsCapacityObservation) (FinOpsCapacityObservation, error) {
	in.Authority = FinOpsCapacityObservationAuthority
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ClusterID = strings.TrimSpace(in.ClusterID)
	if in.OrganizationID == "" || in.ProjectID == "" {
		return FinOpsCapacityObservation{}, fmt.Errorf("%w: organizationId and projectId are required", ErrValidation)
	}
	var err error
	in.Source, in.SourceEventID, err = normalizeFinOpsSource(in.Source, in.SourceEventID)
	if err != nil {
		return FinOpsCapacityObservation{}, err
	}
	if in.ObservedAt.IsZero() {
		return FinOpsCapacityObservation{}, fmt.Errorf("%w: observedAt is required", ErrValidation)
	}
	in.ObservedAt = in.ObservedAt.UTC().Truncate(time.Microsecond)
	if len(in.Metrics) != len(finOpsCapacityMetrics) {
		return FinOpsCapacityObservation{}, fmt.Errorf("%w: explicit state for all FinOps capacity metrics is required", ErrValidation)
	}
	metrics := make(map[FinOpsCapacityMetric]FinOpsMetricSample, len(finOpsCapacityMetrics))
	type metricKV struct {
		Metric         FinOpsCapacityMetric `json:"metric"`
		Available      bool                 `json:"available"`
		QuantityMicros int64                `json:"quantityMicros"`
	}
	ordered := make([]metricKV, 0, len(finOpsCapacityMetrics))
	for _, metric := range finOpsCapacityMetrics {
		sample, ok := in.Metrics[metric]
		if !ok || sample.QuantityMicros < 0 || (!sample.Available && sample.QuantityMicros != 0) {
			return FinOpsCapacityObservation{}, fmt.Errorf("%w: invalid or missing capacity metric state %q", ErrValidation, metric)
		}
		metrics[metric] = sample
		ordered = append(ordered, metricKV{metric, sample.Available, sample.QuantityMicros})
	}
	for metric := range in.Metrics {
		if !validCapacityMetric(metric) {
			return FinOpsCapacityObservation{}, fmt.Errorf("%w: unsupported capacity metric %q", ErrValidation, metric)
		}
	}
	in.Metrics = metrics
	in.Digest = finOpsSHA(struct {
		Authority, OrganizationID, ProjectID, ClusterID, Source, SourceEventID string
		ObservedAt                                                             time.Time
		Metrics                                                                []metricKV
	}{in.Authority, in.OrganizationID, in.ProjectID, in.ClusterID, in.Source, in.SourceEventID, in.ObservedAt, ordered})
	return in, nil
}

func finOpsIntervalsOverlap(aFrom time.Time, aUntil *time.Time, bFrom time.Time, bUntil *time.Time) bool {
	aEnd := time.Unix(1<<62, 0)
	if aUntil != nil {
		aEnd = *aUntil
	}
	bEnd := time.Unix(1<<62, 0)
	if bUntil != nil {
		bEnd = *bUntil
	}
	return aFrom.Before(bEnd) && bFrom.Before(aEnd)
}

func finOpsRateCovers(card FinOpsRateCard, usage FinOpsUsageMeasurement, currency string) bool {
	if card.OrganizationID != usage.OrganizationID || card.Currency != currency || usage.WindowStart.Before(card.EffectiveFrom) {
		return false
	}
	return card.EffectiveUntil == nil || !usage.WindowEnd.After(*card.EffectiveUntil)
}

func finOpsCostMicros(quantityMicros, priceMicros int64) (int64, error) {
	if quantityMicros < 0 || priceMicros < 0 {
		return 0, fmt.Errorf("%w: negative FinOps arithmetic input", ErrValidation)
	}
	product := new(big.Int).Mul(big.NewInt(quantityMicros), big.NewInt(priceMicros))
	// HALF_UP at one currency micro-unit.
	product.Add(product, big.NewInt(500_000))
	product.Div(product, big.NewInt(1_000_000))
	if !product.IsInt64() {
		return 0, fmt.Errorf("%w: FinOps cost overflows int64", ErrValidation)
	}
	return product.Int64(), nil
}

func finOpsGroupKey(group FinOpsGroupBy, usage FinOpsUsageMeasurement) (string, bool, error) {
	switch group {
	case FinOpsGroupProject:
		return usage.ProjectID, true, nil
	case FinOpsGroupCluster:
		if usage.ClusterID == "" {
			return "UNATTRIBUTED", false, nil
		}
		return usage.ClusterID, true, nil
	case FinOpsGroupWorkspace:
		if usage.WorkspaceID == "" {
			return "UNATTRIBUTED", false, nil
		}
		return usage.WorkspaceID, true, nil
	case FinOpsGroupNamespace:
		if usage.Namespace == "" {
			return "UNATTRIBUTED", false, nil
		}
		return usage.Namespace, true, nil
	default:
		return "", false, fmt.Errorf("%w: groupBy must be PROJECT, CLUSTER, WORKSPACE or NAMESPACE", ErrValidation)
	}
}

func dedupeFinOpsUsageMetrics(values []FinOpsUsageMetric) []FinOpsUsageMetric {
	set := map[FinOpsUsageMetric]bool{}
	for _, v := range values {
		set[v] = true
	}
	out := make([]FinOpsUsageMetric, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func BuildFinOpsShowback(query FinOpsShowbackQuery, measurements []FinOpsUsageMeasurement, cards []FinOpsRateCard) (FinOpsShowback, error) {
	query.OrganizationID = strings.TrimSpace(query.OrganizationID)
	query.ProjectID = strings.TrimSpace(query.ProjectID)
	query.Currency = strings.ToUpper(strings.TrimSpace(query.Currency))
	if query.OrganizationID == "" || !finOpsCurrencyPattern.MatchString(query.Currency) || query.WindowStart.IsZero() || query.WindowEnd.IsZero() || !query.WindowEnd.After(query.WindowStart) {
		return FinOpsShowback{}, fmt.Errorf("%w: organization, currency and positive showback window are required", ErrValidation)
	}
	query.WindowStart = query.WindowStart.UTC().Truncate(time.Microsecond)
	query.WindowEnd = query.WindowEnd.UTC().Truncate(time.Microsecond)
	if _, _, err := finOpsGroupKey(query.GroupBy, FinOpsUsageMeasurement{ProjectID: "probe", ClusterID: "probe", WorkspaceID: "probe", Namespace: "probe"}); err != nil {
		return FinOpsShowback{}, err
	}
	normalizedCards := make([]FinOpsRateCard, 0, len(cards))
	for _, raw := range cards {
		c, err := NormalizeFinOpsRateCard(raw)
		if err != nil {
			return FinOpsShowback{}, err
		}
		if c.OrganizationID == query.OrganizationID && c.Currency == query.Currency {
			normalizedCards = append(normalizedCards, c)
		}
	}
	for i := range normalizedCards {
		for j := i + 1; j < len(normalizedCards); j++ {
			if finOpsIntervalsOverlap(normalizedCards[i].EffectiveFrom, normalizedCards[i].EffectiveUntil, normalizedCards[j].EffectiveFrom, normalizedCards[j].EffectiveUntil) {
				return FinOpsShowback{}, fmt.Errorf("%w: overlapping FinOps rate cards make chargeback ambiguous", ErrValidation)
			}
		}
	}

	type groupAcc struct {
		value  FinOpsShowbackGroup
		charge map[FinOpsUsageMetric]*FinOpsMetricCharge
	}
	groups := map[string]*groupAcc{}
	result := FinOpsShowback{Authority: FinOpsChargebackAuthority, OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, Currency: query.Currency, GroupBy: query.GroupBy, WindowStart: query.WindowStart, WindowEnd: query.WindowEnd, Complete: true, AttributionComplete: true}
	rateIDs := map[string]bool{}
	for _, raw := range measurements {
		u, err := NormalizeFinOpsUsageMeasurement(raw)
		if err != nil {
			return FinOpsShowback{}, err
		}
		if u.OrganizationID != query.OrganizationID || (query.ProjectID != "" && u.ProjectID != query.ProjectID) {
			continue
		}
		if u.WindowStart.Before(query.WindowStart) || u.WindowEnd.After(query.WindowEnd) {
			continue
		}
		key, attributed, err := finOpsGroupKey(query.GroupBy, u)
		if err != nil {
			return FinOpsShowback{}, err
		}
		g := groups[key]
		if g == nil {
			g = &groupAcc{value: FinOpsShowbackGroup{Key: key, AttributionComplete: attributed, Complete: true}, charge: map[FinOpsUsageMetric]*FinOpsMetricCharge{}}
			groups[key] = g
		}
		if !attributed {
			g.value.AttributionComplete = false
			result.AttributionComplete = false
		}
		g.value.MeasurementCount++
		result.MeasurementCount++
		var covering *FinOpsRateCard
		for i := range normalizedCards {
			if finOpsRateCovers(normalizedCards[i], u, query.Currency) {
				if covering != nil {
					return FinOpsShowback{}, fmt.Errorf("%w: multiple rate cards cover usage measurement", ErrValidation)
				}
				covering = &normalizedCards[i]
			}
		}
		if covering == nil {
			result.Complete = false
			g.value.Complete = false
			g.value.MissingRateCardCount++
			result.MissingRateCardMeasurements = append(result.MissingRateCardMeasurements, u.ID)
			continue
		}
		if covering.ID != "" {
			rateIDs[covering.ID] = true
		}
		for _, metric := range finOpsUsageMetrics {
			sample := u.Metrics[metric]
			c := g.charge[metric]
			if c == nil {
				c = &FinOpsMetricCharge{Metric: metric, Complete: true}
				g.charge[metric] = c
			}
			c.QuantityMicros += sample.QuantityMicros
			if !sample.Available {
				c.Complete = false
				c.MissingTelemetry = true
				g.value.Complete = false
				result.Complete = false
				g.value.MissingTelemetry = append(g.value.MissingTelemetry, metric)
				result.MissingTelemetry = append(result.MissingTelemetry, metric)
				continue
			}
			price, ok := covering.Rates[metric]
			if !ok && sample.QuantityMicros > 0 {
				c.Complete = false
				c.MissingRate = true
				g.value.Complete = false
				result.Complete = false
				g.value.MissingRates = append(g.value.MissingRates, metric)
				result.MissingRates = append(result.MissingRates, metric)
				continue
			}
			if !ok {
				price = 0
			}
			if c.PriceMicrosPerUnit != 0 && c.PriceMicrosPerUnit != price { // multiple rate cards in one group can legitimately differ; cost remains additive but one display price is ambiguous.
				c.PriceMicrosPerUnit = 0
			} else if c.PriceMicrosPerUnit == 0 {
				c.PriceMicrosPerUnit = price
			}
			cost, err := finOpsCostMicros(sample.QuantityMicros, price)
			if err != nil {
				return FinOpsShowback{}, err
			}
			c.KnownCostMicros += cost
			g.value.KnownCostMicros += cost
			result.KnownCostMicros += cost
		}
	}
	result.MissingTelemetry = dedupeFinOpsUsageMetrics(result.MissingTelemetry)
	result.MissingRates = dedupeFinOpsUsageMetrics(result.MissingRates)
	sort.Strings(result.MissingRateCardMeasurements)
	for id := range rateIDs {
		result.RateCardIDs = append(result.RateCardIDs, id)
	}
	sort.Strings(result.RateCardIDs)
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		g.value.MissingTelemetry = dedupeFinOpsUsageMetrics(g.value.MissingTelemetry)
		g.value.MissingRates = dedupeFinOpsUsageMetrics(g.value.MissingRates)
		for _, metric := range finOpsUsageMetrics {
			if c := g.charge[metric]; c != nil {
				g.value.Charges = append(g.value.Charges, *c)
			}
		}
		if g.value.Complete {
			total := g.value.KnownCostMicros
			g.value.TotalCostMicros = &total
		}
		result.Groups = append(result.Groups, g.value)
	}
	if result.Complete {
		total := result.KnownCostMicros
		result.TotalCostMicros = &total
	}
	result.Digest = finOpsSHA(struct {
		Authority, OrganizationID, ProjectID, Currency string
		GroupBy                                        FinOpsGroupBy
		WindowStart, WindowEnd                         time.Time
		MeasurementCount                               int
		KnownCostMicros                                int64
		Complete, AttributionComplete                  bool
		MissingTelemetry, MissingRates                 []FinOpsUsageMetric
		MissingRateCardMeasurements, RateCardIDs       []string
		Groups                                         []FinOpsShowbackGroup
	}{result.Authority, result.OrganizationID, result.ProjectID, result.Currency, result.GroupBy, result.WindowStart, result.WindowEnd, result.MeasurementCount, result.KnownCostMicros, result.Complete, result.AttributionComplete, result.MissingTelemetry, result.MissingRates, result.MissingRateCardMeasurements, result.RateCardIDs, result.Groups})
	return result, nil
}

// FinOpsChargebackCSV renders a deterministic export projection. Incomplete
// showback never receives a numeric total; callers can still export known cost
// alongside the explicit complete=false state without turning missing telemetry
// into zero spend.
func FinOpsChargebackCSV(showback FinOpsShowback) ([]byte, string, error) {
	if showback.Authority != FinOpsChargebackAuthority || strings.TrimSpace(showback.Digest) == "" {
		return nil, "", fmt.Errorf("%w: normalized FinOps showback is required", ErrValidation)
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	header := []string{"authority", "organization_id", "project_id", "currency", "group_by", "group_key", "known_cost_micros", "total_cost_micros", "complete", "attribution_complete", "measurement_count", "showback_digest"}
	if err := w.Write(header); err != nil {
		return nil, "", err
	}
	groups := append([]FinOpsShowbackGroup(nil), showback.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
	if len(groups) == 0 {
		groups = []FinOpsShowbackGroup{{Key: "TOTAL", KnownCostMicros: showback.KnownCostMicros, TotalCostMicros: showback.TotalCostMicros, Complete: showback.Complete, AttributionComplete: showback.AttributionComplete, MeasurementCount: showback.MeasurementCount}}
	}
	for _, group := range groups {
		total := ""
		if group.Complete && group.TotalCostMicros != nil {
			total = strconv.FormatInt(*group.TotalCostMicros, 10)
		}
		row := []string{showback.Authority, showback.OrganizationID, showback.ProjectID, showback.Currency, string(showback.GroupBy), group.Key, strconv.FormatInt(group.KnownCostMicros, 10), total, strconv.FormatBool(group.Complete), strconv.FormatBool(group.AttributionComplete), strconv.Itoa(group.MeasurementCount), showback.Digest}
		if err := w.Write(row); err != nil {
			return nil, "", err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", err
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return append([]byte(nil), raw...), "sha256:" + hex.EncodeToString(sum[:]), nil
}
