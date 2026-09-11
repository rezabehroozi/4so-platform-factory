package releasereadiness

import (
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/targetmodel"
)

const (
	StatusComplete     = "complete"
	StatusBlocked      = "blocked"
	StatusPending      = "pending"
	StatusNotEvaluated = "not-evaluated"
)

type Phase struct {
	ID           string         `json:"id"`
	Status       string         `json:"status"`
	BlockerCount int            `json:"blockerCount"`
	BlockerCodes map[string]int `json:"blockerCodes,omitempty"`
	Metrics      map[string]int `json:"metrics,omitempty"`
}

type Report struct {
	APIVersion                    string                     `json:"apiVersion"`
	Kind                          string                     `json:"kind"`
	PlanID                        string                     `json:"planId"`
	Blueprint                     string                     `json:"blueprint"`
	BlueprintVersion              string                     `json:"blueprintVersion"`
	PlanStatus                    string                     `json:"planStatus"`
	DeploymentExecutable          bool                       `json:"deploymentExecutable"`
	ProductReleaseReady           bool                       `json:"productReleaseReady"`
	PhysicalRuntimeStatus         string                     `json:"physicalRuntimeStatus"`
	TotalBlockers                 int                        `json:"totalBlockers"`
	ProductReleaseBlockers        int                        `json:"productReleaseBlockers"`
	RoadmapFeatureBlockers        int                        `json:"roadmapFeatureBlockers"`
	DeploymentContextBlockers     int                        `json:"deploymentContextBlockers"`
	ProductBlockerCodes           map[string]int             `json:"productBlockerCodes"`
	RoadmapFeatureBlockerCodes    map[string]int             `json:"roadmapFeatureBlockerCodes"`
	DeploymentContextBlockerCodes map[string]int             `json:"deploymentContextBlockerCodes"`
	UnclassifiedProductBlockers   int                        `json:"unclassifiedProductBlockers"`
	EnabledComponents             int                        `json:"enabledComponents"`
	UpstreamAdmission             AdmissionStats             `json:"upstreamAdmission"`
	ProgramRoadmap                targetmodel.ProgramRoadmap `json:"programRoadmap"`
	Phases                        []Phase                    `json:"phases"`
}

type AdmissionStats struct {
	Applicable          int            `json:"applicable"`
	Ready               int            `json:"readyForAcquisition"`
	ReviewRequired      int            `json:"reviewRequired"`
	RuntimeBlocked      int            `json:"runtimeBlocked"`
	StatusCounts        map[string]int `json:"statusCounts,omitempty"`
	RuntimeStatusCounts map[string]int `json:"runtimeStatusCounts,omitempty"`
}

var sourceCodes = map[string]struct{}{
	"COMPONENT_VERSION_NOT_PINNED": {},
	"COMPONENT_SOURCE_UNRESOLVED":  {},
	"SOURCE_LOCK_MISSING":          {},
}

var runtimeCodes = map[string]struct{}{
	"COMPONENT_NOT_RUNTIME_CERTIFIED": {},
	"CERTIFICATION_EVIDENCE_MISSING":  {},
}

var deploymentContextCodes = map[string]struct{}{
	"GIT_REVISION_NOT_IMMUTABLE":  {},
	"GIT_ENDPOINT_NOT_CONFIGURED": {},
	"OCI_ENDPOINT_NOT_CONFIGURED": {},
}

var certificationAuthorityCodes = map[string]struct{}{
	"CERTIFICATION_AUTHORITY_UNVERIFIED": {},
}

func Build(plan domain.DeploymentPlan, admission catalog.UpstreamAdmission, components map[string]catalog.Component) (Report, error) {
	if err := catalog.ValidateUpstreamAdmission(admission, components); err != nil {
		return Report{}, fmt.Errorf("validate upstream admission authority: %w", err)
	}
	enabled := make(map[string]domain.PlanStep, len(plan.Steps))
	exactVersion := 0
	sourceResolved := 0
	sourceLocked := 0
	runtimeCertified := 0
	evidenceBound := 0
	for _, step := range plan.Steps {
		enabled[step.Component] = step
		if isExactVersion(step.ReleaseConstraint) {
			exactVersion++
		}
		if step.SourceResolved {
			sourceResolved++
		}
		if strings.TrimSpace(step.SourceLockDigest) != "" {
			sourceLocked++
		}
		status := strings.ToLower(strings.TrimSpace(step.CertificationStatus))
		if status == "target-runtime-certified" || status == "upgrade-certified" {
			runtimeCertified++
		}
		if strings.TrimSpace(step.CertificationEvidence) != "" {
			evidenceBound++
		}
	}

	admissionStats := AdmissionStats{StatusCounts: map[string]int{}, RuntimeStatusCounts: map[string]int{}}
	admissionNames := make(map[string]struct{}, len(admission.Spec.Components))
	for _, row := range admission.Spec.Components {
		name := strings.TrimSpace(row.Component)
		admissionNames[name] = struct{}{}
		step, applies := enabled[name]
		if !applies || step.SourceResolved {
			continue
		}
		admissionStats.Applicable++
		status := strings.TrimSpace(row.Status)
		admissionStats.StatusCounts[status]++
		runtimeStatus := strings.TrimSpace(row.RuntimeStatus)
		admissionStats.RuntimeStatusCounts[runtimeStatus]++
		if runtimeStatus != "eligible-after-source-resolution" {
			admissionStats.RuntimeBlocked++
		}
		if status == "ready-for-acquisition" {
			admissionStats.Ready++
		} else {
			admissionStats.ReviewRequired++
		}
	}
	for name, step := range enabled {
		if step.SourceResolved {
			continue
		}
		if _, found := admissionNames[name]; !found {
			return Report{}, fmt.Errorf("unresolved enabled component %q has no upstream admission authority", name)
		}
	}

	sourceBlockers := countsFor(plan.Blockers, sourceCodes)
	runtimeBlockers := countsFor(plan.Blockers, runtimeCodes)
	deploymentBlockers := countsFor(plan.Blockers, deploymentContextCodes)
	authorityBlockers := countsFor(plan.Blockers, certificationAuthorityCodes)
	known := mergeCodeSets(sourceCodes, runtimeCodes, deploymentContextCodes, certificationAuthorityCodes)
	unclassified := countsExcept(plan.Blockers, known)

	planProductBlockerCodes := mergeCounts(sourceBlockers, runtimeBlockers, authorityBlockers, unclassified)
	planProductBlockers := sumCounts(planProductBlockerCodes)
	deploymentContextBlockers := sumCounts(deploymentBlockers)
	roadmap := targetmodel.ProgramRoadmapModel()
	roadmapFeatureBlockerCodes := targetmodel.FeatureFreezeBlockerCounts(roadmap)
	roadmapFeatureBlockers := sumCounts(roadmapFeatureBlockerCodes)
	productBlockerCodes := mergeCounts(planProductBlockerCodes, roadmapFeatureBlockerCodes)
	productBlockers := planProductBlockers + roadmapFeatureBlockers

	admissionPhaseStatus := StatusComplete
	if admissionStats.ReviewRequired > 0 {
		admissionPhaseStatus = StatusBlocked
	} else if admissionStats.Applicable > 0 {
		// Review has completed, but immutable acquisition remains a separate phase.
		admissionPhaseStatus = StatusComplete
	}

	sourcePhaseStatus := phaseStatus(sumCounts(sourceBlockers))
	runtimePhaseStatus := phaseStatus(sumCounts(runtimeBlockers))
	deploymentPhaseStatus := phaseStatus(deploymentContextBlockers)

	authorityPhaseStatus := StatusPending
	if sumCounts(authorityBlockers) > 0 {
		authorityPhaseStatus = StatusBlocked
	} else if planProductBlockers == 0 {
		authorityPhaseStatus = StatusComplete
	}

	phases := []Phase{
		{
			ID:           "upstream-admission",
			Status:       admissionPhaseStatus,
			BlockerCount: admissionStats.ReviewRequired,
			Metrics: map[string]int{
				"applicable":          admissionStats.Applicable,
				"readyForAcquisition": admissionStats.Ready,
				"reviewRequired":      admissionStats.ReviewRequired,
				"runtimeBlocked":      admissionStats.RuntimeBlocked,
			},
		},
		{
			ID:           "immutable-source-acquisition",
			Status:       sourcePhaseStatus,
			BlockerCount: sumCounts(sourceBlockers),
			BlockerCodes: sourceBlockers,
			Metrics: map[string]int{
				"enabledComponents": len(plan.Steps),
				"exactVersion":      exactVersion,
				"sourceResolved":    sourceResolved,
				"sourceLocked":      sourceLocked,
			},
		},
		{
			ID:           "runtime-certification",
			Status:       runtimePhaseStatus,
			BlockerCount: sumCounts(runtimeBlockers),
			BlockerCodes: runtimeBlockers,
			Metrics: map[string]int{
				"enabledComponents": len(plan.Steps),
				"runtimeCertified":  runtimeCertified,
				"evidenceBound":     evidenceBound,
			},
		},
		{
			ID:           "control-plane-certification-authority",
			Status:       authorityPhaseStatus,
			BlockerCount: sumCounts(authorityBlockers),
			BlockerCodes: authorityBlockers,
		},
		{
			ID:           "deployment-context-immutability",
			Status:       deploymentPhaseStatus,
			BlockerCount: deploymentContextBlockers,
			BlockerCodes: deploymentBlockers,
		},
		{
			ID:           "mandatory-roadmap-feature-freeze",
			Status:       phaseStatus(roadmapFeatureBlockers),
			BlockerCount: roadmapFeatureBlockers,
			BlockerCodes: roadmapFeatureBlockerCodes,
		},
		{
			ID:           "exact-sha-physical-runtime",
			Status:       StatusNotEvaluated,
			BlockerCount: 0,
		},
	}

	return Report{
		APIVersion:                    "platform.4so.io/v1alpha1",
		Kind:                          "ReleaseReadiness",
		PlanID:                        plan.ID,
		Blueprint:                     plan.Blueprint,
		BlueprintVersion:              plan.BlueprintVersion,
		PlanStatus:                    plan.Status,
		DeploymentExecutable:          plan.Executable,
		ProductReleaseReady:           productBlockers == 0 && roadmap.GoalReady,
		PhysicalRuntimeStatus:         StatusNotEvaluated,
		TotalBlockers:                 len(plan.Blockers) + roadmapFeatureBlockers,
		ProductReleaseBlockers:        productBlockers,
		RoadmapFeatureBlockers:        roadmapFeatureBlockers,
		DeploymentContextBlockers:     deploymentContextBlockers,
		ProductBlockerCodes:           productBlockerCodes,
		RoadmapFeatureBlockerCodes:    roadmapFeatureBlockerCodes,
		DeploymentContextBlockerCodes: deploymentBlockers,
		UnclassifiedProductBlockers:   sumCounts(unclassified),
		EnabledComponents:             len(plan.Steps),
		UpstreamAdmission:             admissionStats,
		ProgramRoadmap:                roadmap,
		Phases:                        phases,
	}, nil
}

func phaseStatus(blockers int) string {
	if blockers > 0 {
		return StatusBlocked
	}
	return StatusComplete
}

func countsFor(findings []domain.Finding, codes map[string]struct{}) map[string]int {
	out := map[string]int{}
	for _, finding := range findings {
		if _, ok := codes[finding.Code]; ok {
			out[finding.Code]++
		}
	}
	return compactCounts(out)
}

func countsExcept(findings []domain.Finding, known map[string]struct{}) map[string]int {
	out := map[string]int{}
	for _, finding := range findings {
		if _, ok := known[finding.Code]; !ok {
			out[finding.Code]++
		}
	}
	return compactCounts(out)
}

func compactCounts(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]int, len(keys))
	for _, key := range keys {
		out[key] = in[key]
	}
	return out
}

func mergeCounts(countSets ...map[string]int) map[string]int {
	out := map[string]int{}
	for _, counts := range countSets {
		for code, count := range counts {
			out[code] += count
		}
	}
	return compactCounts(out)
}

func sumCounts(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func mergeCodeSets(sets ...map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for _, set := range sets {
		for code := range set {
			out[code] = struct{}{}
		}
	}
	return out
}

func isExactVersion(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
