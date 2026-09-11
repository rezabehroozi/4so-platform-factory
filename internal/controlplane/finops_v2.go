package controlplane

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

const (
	FinOpsBudgetPolicyAuthority = "FINOPS_BUDGET_POLICY_AUTHORITY_V1"
	FinOpsInsightAuthority      = "FINOPS_FORECAST_ANOMALY_RIGHTSIZING_AUTHORITY_V1"
)

type FinOpsInsightStatus string

const (
	FinOpsInsightReady   FinOpsInsightStatus = "READY"
	FinOpsInsightUnknown FinOpsInsightStatus = "UNKNOWN"
)

type FinOpsBudgetPolicy struct {
	ResourceMeta
	Authority           string     `json:"authority"`
	OrganizationID      string     `json:"organizationId"`
	ProjectID           string     `json:"projectId,omitempty"`
	Name                string     `json:"name"`
	Version             string     `json:"version"`
	Currency            string     `json:"currency"`
	EffectiveFrom       time.Time  `json:"effectiveFrom"`
	EffectiveUntil      *time.Time `json:"effectiveUntil,omitempty"`
	LimitMicros         int64      `json:"limitMicros"`
	WarningBasisPoints  int64      `json:"warningBasisPoints"`
	CriticalBasisPoints int64      `json:"criticalBasisPoints"`
	Digest              string     `json:"digest"`
}

func NormalizeFinOpsBudgetPolicy(in FinOpsBudgetPolicy) (FinOpsBudgetPolicy, error) {
	in.Authority = FinOpsBudgetPolicyAuthority
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.Name = strings.TrimSpace(in.Name)
	in.Version = strings.TrimSpace(in.Version)
	in.Currency = strings.ToUpper(strings.TrimSpace(in.Currency))
	if in.OrganizationID == "" || in.Name == "" || in.Version == "" {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: organizationId, name and version are required", ErrValidation)
	}
	if len(in.Name) > 120 || len(in.Version) > 64 {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: FinOps budget-policy name/version is too long", ErrValidation)
	}
	if !finOpsCurrencyPattern.MatchString(in.Currency) {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: currency must be a three-letter ISO-style code", ErrValidation)
	}
	var err error
	in.EffectiveFrom, in.EffectiveUntil, err = normalizeFinOpsInterval(in.EffectiveFrom, in.EffectiveUntil)
	if err != nil {
		return FinOpsBudgetPolicy{}, err
	}
	if in.LimitMicros <= 0 {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: budget limitMicros must be positive", ErrValidation)
	}
	if in.WarningBasisPoints <= 0 || in.CriticalBasisPoints <= in.WarningBasisPoints || in.CriticalBasisPoints > 100000 {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: budget thresholds must be positive, ordered basis points", ErrValidation)
	}
	in.Digest = finOpsSHA(struct {
		Authority, OrganizationID, ProjectID, Name, Version, Currency string
		EffectiveFrom                                                 time.Time
		EffectiveUntil                                                *time.Time
		LimitMicros, WarningBasisPoints, CriticalBasisPoints          int64
	}{in.Authority, in.OrganizationID, in.ProjectID, in.Name, in.Version, in.Currency, in.EffectiveFrom, in.EffectiveUntil, in.LimitMicros, in.WarningBasisPoints, in.CriticalBasisPoints})
	return in, nil
}

type FinOpsInsightQuery struct {
	OrganizationID  string    `json:"organizationId"`
	ProjectID       string    `json:"projectId,omitempty"`
	Currency        string    `json:"currency"`
	WindowStart     time.Time `json:"windowStart"`
	ObservedThrough time.Time `json:"observedThrough"`
	ForecastEnd     time.Time `json:"forecastEnd"`
}

type FinOpsForecast struct {
	Status              FinOpsInsightStatus `json:"status"`
	Reason              string              `json:"reason,omitempty"`
	Confidence          string              `json:"confidence,omitempty"`
	KnownCostMicros     int64               `json:"knownCostMicros"`
	ProjectedCostMicros *int64              `json:"projectedCostMicros,omitempty"`
	ObservedSeconds     int64               `json:"observedSeconds"`
	ForecastSeconds     int64               `json:"forecastSeconds"`
}

type FinOpsBudgetEvaluation struct {
	PolicyID             string              `json:"policyId"`
	Name                 string              `json:"name"`
	Version              string              `json:"version"`
	Status               FinOpsInsightStatus `json:"status"`
	Severity             string              `json:"severity"`
	Reason               string              `json:"reason,omitempty"`
	LimitMicros          int64               `json:"limitMicros"`
	KnownCostMicros      int64               `json:"knownCostMicros"`
	ProjectedCostMicros  *int64              `json:"projectedCostMicros,omitempty"`
	KnownBasisPoints     int64               `json:"knownBasisPoints"`
	ProjectedBasisPoints int64               `json:"projectedBasisPoints"`
	WarningBasisPoints   int64               `json:"warningBasisPoints"`
	CriticalBasisPoints  int64               `json:"criticalBasisPoints"`
}

type FinOpsSpendAnomaly struct {
	Status                   FinOpsInsightStatus `json:"status"`
	Severity                 string              `json:"severity"`
	Reason                   string              `json:"reason,omitempty"`
	BaselineHourlyMicros     int64               `json:"baselineHourlyMicros"`
	RecentHourlyMicros       int64               `json:"recentHourlyMicros"`
	RatioBasisPoints         int64               `json:"ratioBasisPoints"`
	BaselineMeasurementCount int                 `json:"baselineMeasurementCount"`
	RecentMeasurementCount   int                 `json:"recentMeasurementCount"`
}

type FinOpsRightsizingRecommendation struct {
	Metric                 FinOpsCapacityMetric `json:"metric"`
	Status                 FinOpsInsightStatus  `json:"status"`
	Action                 string               `json:"action"`
	Reason                 string               `json:"reason,omitempty"`
	UtilizationBasisPoints int64                `json:"utilizationBasisPoints"`
	CapacityMicros         int64                `json:"capacityMicros"`
	AverageDemandMicros    int64                `json:"averageDemandMicros"`
	Automatable            bool                 `json:"automatable"`
	EvidenceObservationID  string               `json:"evidenceObservationId,omitempty"`
}

type FinOpsInsights struct {
	Authority       string                            `json:"authority"`
	OrganizationID  string                            `json:"organizationId"`
	ProjectID       string                            `json:"projectId,omitempty"`
	Currency        string                            `json:"currency"`
	WindowStart     time.Time                         `json:"windowStart"`
	ObservedThrough time.Time                         `json:"observedThrough"`
	ForecastEnd     time.Time                         `json:"forecastEnd"`
	Showback        FinOpsShowback                    `json:"showback"`
	Forecast        FinOpsForecast                    `json:"forecast"`
	Budgets         []FinOpsBudgetEvaluation          `json:"budgets"`
	Anomaly         FinOpsSpendAnomaly                `json:"anomaly"`
	Rightsizing     []FinOpsRightsizingRecommendation `json:"rightsizing"`
	Digest          string                            `json:"digest"`
}

func scaleIntHalfUp(value, numerator, denominator int64) (int64, error) {
	if value < 0 || numerator < 0 || denominator <= 0 {
		return 0, fmt.Errorf("%w: invalid non-negative ratio arithmetic", ErrValidation)
	}
	product := new(big.Int).Mul(big.NewInt(value), big.NewInt(numerator))
	half := new(big.Int).Div(big.NewInt(denominator), big.NewInt(2))
	product.Add(product, half)
	product.Div(product, big.NewInt(denominator))
	if !product.IsInt64() {
		return 0, fmt.Errorf("%w: FinOps ratio overflows int64", ErrValidation)
	}
	return product.Int64(), nil
}

func basisPoints(numerator, denominator int64) (int64, error) {
	if denominator <= 0 {
		return 0, fmt.Errorf("%w: denominator must be positive", ErrValidation)
	}
	return scaleIntHalfUp(numerator, 10000, denominator)
}

func normalizeFinOpsInsightQuery(in FinOpsInsightQuery) (FinOpsInsightQuery, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.Currency = strings.ToUpper(strings.TrimSpace(in.Currency))
	if in.OrganizationID == "" || !finOpsCurrencyPattern.MatchString(in.Currency) {
		return FinOpsInsightQuery{}, fmt.Errorf("%w: organization and currency are required", ErrValidation)
	}
	if in.WindowStart.IsZero() || in.ObservedThrough.IsZero() || in.ForecastEnd.IsZero() {
		return FinOpsInsightQuery{}, fmt.Errorf("%w: windowStart, observedThrough and forecastEnd are required", ErrValidation)
	}
	in.WindowStart = in.WindowStart.UTC().Truncate(time.Microsecond)
	in.ObservedThrough = in.ObservedThrough.UTC().Truncate(time.Microsecond)
	in.ForecastEnd = in.ForecastEnd.UTC().Truncate(time.Microsecond)
	if !in.ObservedThrough.After(in.WindowStart) || in.ForecastEnd.Before(in.ObservedThrough) {
		return FinOpsInsightQuery{}, fmt.Errorf("%w: FinOps insight time window is invalid", ErrValidation)
	}
	return in, nil
}

func buildFinOpsForecast(query FinOpsInsightQuery, showback FinOpsShowback) FinOpsForecast {
	observedSeconds := int64(query.ObservedThrough.Sub(query.WindowStart) / time.Second)
	forecastSeconds := int64(query.ForecastEnd.Sub(query.WindowStart) / time.Second)
	out := FinOpsForecast{Status: FinOpsInsightUnknown, KnownCostMicros: showback.KnownCostMicros, ObservedSeconds: observedSeconds, ForecastSeconds: forecastSeconds}
	if !showback.Complete {
		out.Reason = "showback is incomplete because measured telemetry or rate coverage is missing"
		return out
	}
	if showback.MeasurementCount == 0 {
		out.Reason = "no measured usage is available in the observed window"
		return out
	}
	projected, err := scaleIntHalfUp(showback.KnownCostMicros, forecastSeconds, observedSeconds)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.Status = FinOpsInsightReady
	out.ProjectedCostMicros = &projected
	switch {
	case observedSeconds >= int64((14*24*time.Hour)/time.Second):
		out.Confidence = "HIGH"
	case observedSeconds >= int64((72*time.Hour)/time.Second):
		out.Confidence = "MEDIUM"
	default:
		out.Confidence = "LOW"
	}
	return out
}

func budgetCovers(policy FinOpsBudgetPolicy, query FinOpsInsightQuery) bool {
	if policy.OrganizationID != query.OrganizationID || policy.ProjectID != query.ProjectID || policy.Currency != query.Currency {
		return false
	}
	if query.WindowStart.Before(policy.EffectiveFrom) {
		return false
	}
	if policy.EffectiveUntil != nil && query.ForecastEnd.After(*policy.EffectiveUntil) {
		return false
	}
	return true
}

func buildBudgetEvaluations(query FinOpsInsightQuery, showback FinOpsShowback, forecast FinOpsForecast, policies []FinOpsBudgetPolicy) ([]FinOpsBudgetEvaluation, error) {
	out := []FinOpsBudgetEvaluation{}
	for _, raw := range policies {
		policy, err := NormalizeFinOpsBudgetPolicy(raw)
		if err != nil {
			return nil, err
		}
		policy.ID = raw.ID
		if !budgetCovers(policy, query) {
			continue
		}
		ev := FinOpsBudgetEvaluation{PolicyID: policy.ID, Name: policy.Name, Version: policy.Version, Status: FinOpsInsightUnknown, Severity: "UNKNOWN", LimitMicros: policy.LimitMicros, KnownCostMicros: showback.KnownCostMicros, WarningBasisPoints: policy.WarningBasisPoints, CriticalBasisPoints: policy.CriticalBasisPoints}
		knownBP, err := basisPoints(showback.KnownCostMicros, policy.LimitMicros)
		if err != nil {
			return nil, err
		}
		ev.KnownBasisPoints = knownBP
		if forecast.Status != FinOpsInsightReady || forecast.ProjectedCostMicros == nil {
			ev.Reason = "budget forecast unavailable because cost evidence is incomplete"
			out = append(out, ev)
			continue
		}
		ev.Status = FinOpsInsightReady
		ev.ProjectedCostMicros = forecast.ProjectedCostMicros
		projectedBP, err := basisPoints(*forecast.ProjectedCostMicros, policy.LimitMicros)
		if err != nil {
			return nil, err
		}
		ev.ProjectedBasisPoints = projectedBP
		switch {
		case projectedBP >= policy.CriticalBasisPoints:
			ev.Severity = "CRITICAL"
		case projectedBP >= policy.WarningBasisPoints:
			ev.Severity = "WARNING"
		default:
			ev.Severity = "OK"
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func buildSpendAnomaly(query FinOpsInsightQuery, usage []FinOpsUsageMeasurement, cards []FinOpsRateCard) FinOpsSpendAnomaly {
	out := FinOpsSpendAnomaly{Status: FinOpsInsightUnknown, Severity: "UNKNOWN"}
	recentStart := query.ObservedThrough.Add(-24 * time.Hour)
	if recentStart.Sub(query.WindowStart) < 24*time.Hour {
		out.Reason = "at least 48 hours of observed window are required for spend-rate anomaly detection"
		return out
	}
	baseline, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, Currency: query.Currency, GroupBy: FinOpsGroupProject, WindowStart: query.WindowStart, WindowEnd: recentStart}, usage, cards)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	recent, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, Currency: query.Currency, GroupBy: FinOpsGroupProject, WindowStart: recentStart, WindowEnd: query.ObservedThrough}, usage, cards)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.BaselineMeasurementCount = baseline.MeasurementCount
	out.RecentMeasurementCount = recent.MeasurementCount
	if !baseline.Complete || !recent.Complete || baseline.MeasurementCount == 0 || recent.MeasurementCount == 0 {
		out.Reason = "complete measured cost is required in both baseline and recent windows"
		return out
	}
	baselineHours := int64(recentStart.Sub(query.WindowStart) / time.Hour)
	recentHours := int64(query.ObservedThrough.Sub(recentStart) / time.Hour)
	if baselineHours <= 0 || recentHours <= 0 {
		out.Reason = "invalid anomaly comparison window"
		return out
	}
	baselineHourly, err := scaleIntHalfUp(baseline.KnownCostMicros, 1, baselineHours)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	recentHourly, err := scaleIntHalfUp(recent.KnownCostMicros, 1, recentHours)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.BaselineHourlyMicros = baselineHourly
	out.RecentHourlyMicros = recentHourly
	if baselineHourly == 0 {
		if recentHourly == 0 {
			out.Status = FinOpsInsightReady
			out.Severity = "NORMAL"
			out.RatioBasisPoints = 10000
		} else {
			out.Reason = "baseline spend rate is zero; ratio is undefined"
		}
		return out
	}
	ratio, err := basisPoints(recentHourly, baselineHourly)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.Status = FinOpsInsightReady
	out.RatioBasisPoints = ratio
	switch {
	case ratio >= 20000:
		out.Severity = "HIGH"
	case ratio >= 15000:
		out.Severity = "MEDIUM"
	default:
		out.Severity = "NORMAL"
	}
	return out
}

func latestAggregateCapacity(query FinOpsInsightQuery, observations []FinOpsCapacityObservation) *FinOpsCapacityObservation {
	var latest *FinOpsCapacityObservation
	for _, raw := range observations {
		obs, err := NormalizeFinOpsCapacityObservation(raw)
		if err != nil {
			continue
		}
		obs.ID = raw.ID
		if obs.OrganizationID != query.OrganizationID || obs.ProjectID != query.ProjectID || obs.ClusterID != "" || obs.ObservedAt.After(query.ObservedThrough) || query.ObservedThrough.Sub(obs.ObservedAt) > 24*time.Hour {
			continue
		}
		if latest == nil || obs.ObservedAt.After(latest.ObservedAt) {
			v := obs
			latest = &v
		}
	}
	return latest
}

func buildRightsizing(query FinOpsInsightQuery, usage []FinOpsUsageMeasurement, observations []FinOpsCapacityObservation) []FinOpsRightsizingRecommendation {
	pairs := []struct {
		capacity FinOpsCapacityMetric
		usage    FinOpsUsageMetric
	}{{FinOpsCPUCore, FinOpsCPUCoreHour}, {FinOpsMemoryGiB, FinOpsMemoryGiBHour}}
	latest := latestAggregateCapacity(query, observations)
	observedHours := int64(query.ObservedThrough.Sub(query.WindowStart) / time.Hour)
	if observedHours <= 0 {
		observedHours = 1
	}
	out := make([]FinOpsRightsizingRecommendation, 0, len(pairs))
	for _, pair := range pairs {
		rec := FinOpsRightsizingRecommendation{Metric: pair.capacity, Status: FinOpsInsightUnknown, Action: "UNKNOWN", Automatable: false}
		if latest == nil {
			rec.Reason = "fresh project aggregate capacity observation is unavailable"
			out = append(out, rec)
			continue
		}
		sample, ok := latest.Metrics[pair.capacity]
		if !ok || !sample.Available || sample.QuantityMicros <= 0 {
			rec.Reason = "capacity evidence is unavailable for this metric"
			out = append(out, rec)
			continue
		}
		var total int64
		complete := true
		count := 0
		for _, raw := range usage {
			u, err := NormalizeFinOpsUsageMeasurement(raw)
			if err != nil || u.OrganizationID != query.OrganizationID || u.ProjectID != query.ProjectID || u.WindowStart.Before(query.WindowStart) || u.WindowEnd.After(query.ObservedThrough) {
				continue
			}
			metric := u.Metrics[pair.usage]
			if !metric.Available {
				complete = false
				break
			}
			if total > (1<<63-1)-metric.QuantityMicros {
				complete = false
				break
			}
			total += metric.QuantityMicros
			count++
		}
		if !complete || count == 0 {
			rec.Reason = "complete measured usage is unavailable for this metric"
			out = append(out, rec)
			continue
		}
		average, err := scaleIntHalfUp(total, 1, observedHours)
		if err != nil {
			rec.Reason = err.Error()
			out = append(out, rec)
			continue
		}
		utilization, err := basisPoints(average, sample.QuantityMicros)
		if err != nil {
			rec.Reason = err.Error()
			out = append(out, rec)
			continue
		}
		rec.Status = FinOpsInsightReady
		rec.CapacityMicros = sample.QuantityMicros
		rec.AverageDemandMicros = average
		rec.UtilizationBasisPoints = utilization
		rec.EvidenceObservationID = latest.ID
		switch {
		case utilization < 3000:
			rec.Action = "REVIEW_DOWNSIZE"
		case utilization > 8500:
			rec.Action = "REVIEW_SCALE_UP"
		default:
			rec.Action = "NO_CHANGE"
		}
		out = append(out, rec)
	}
	return out
}

func BuildFinOpsInsights(rawQuery FinOpsInsightQuery, usage []FinOpsUsageMeasurement, cards []FinOpsRateCard, observations []FinOpsCapacityObservation, policies []FinOpsBudgetPolicy) (FinOpsInsights, error) {
	query, err := normalizeFinOpsInsightQuery(rawQuery)
	if err != nil {
		return FinOpsInsights{}, err
	}
	showback, err := BuildFinOpsShowback(FinOpsShowbackQuery{OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, Currency: query.Currency, GroupBy: FinOpsGroupProject, WindowStart: query.WindowStart, WindowEnd: query.ObservedThrough}, usage, cards)
	if err != nil {
		return FinOpsInsights{}, err
	}
	forecast := buildFinOpsForecast(query, showback)
	budgets, err := buildBudgetEvaluations(query, showback, forecast, policies)
	if err != nil {
		return FinOpsInsights{}, err
	}
	result := FinOpsInsights{Authority: FinOpsInsightAuthority, OrganizationID: query.OrganizationID, ProjectID: query.ProjectID, Currency: query.Currency, WindowStart: query.WindowStart, ObservedThrough: query.ObservedThrough, ForecastEnd: query.ForecastEnd, Showback: showback, Forecast: forecast, Budgets: budgets, Anomaly: buildSpendAnomaly(query, usage, cards), Rightsizing: buildRightsizing(query, usage, observations)}
	result.Digest = finOpsSHA(struct {
		Authority, OrganizationID, ProjectID, Currency string
		WindowStart, ObservedThrough, ForecastEnd      time.Time
		ShowbackDigest                                 string
		Forecast                                       FinOpsForecast
		Budgets                                        []FinOpsBudgetEvaluation
		Anomaly                                        FinOpsSpendAnomaly
		Rightsizing                                    []FinOpsRightsizingRecommendation
	}{result.Authority, result.OrganizationID, result.ProjectID, result.Currency, result.WindowStart, result.ObservedThrough, result.ForecastEnd, result.Showback.Digest, result.Forecast, result.Budgets, result.Anomaly, result.Rightsizing})
	return result, nil
}
