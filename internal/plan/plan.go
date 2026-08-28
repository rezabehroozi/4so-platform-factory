package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/gitops"
	"regexp"
	"sort"
	"strings"
	"time"
)

var exactRelease = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func Build(b domain.Blueprint, cs map[string]catalog.Component) (domain.DeploymentPlan, error) {
	return build(b, cs, false)
}

// BuildWithCertificationAuthority may produce an execution-ready plan only when
// the caller has already revalidated a durable control-plane Catalog release
// whose runtime certification evidence is authoritative. Source/catalog
// metadata alone must never be allowed to manufacture execution readiness.
func BuildWithCertificationAuthority(b domain.Blueprint, cs map[string]catalog.Component) (domain.DeploymentPlan, error) {
	return build(b, cs, true)
}

func build(b domain.Blueprint, cs map[string]catalog.Component, certificationAuthorityVerified bool) (domain.DeploymentPlan, error) {
	enabled := map[string]bool{}
	for _, s := range b.Spec.Components {
		if s.Enabled {
			enabled[s.Name] = true
		}
	}
	steps := make([]domain.PlanStep, 0, len(enabled))
	blockers := make([]domain.Finding, 0)
	catalogReadinessBlockers := 0
	riskSummary := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	approvals := map[string]bool{}
	for _, r := range b.Spec.Governance.ApprovalRequiredFor {
		approvals[r] = true
	}

	if strings.Contains(b.Spec.Delivery.Repository, "example.invalid") {
		blockers = append(blockers, finding("GIT_ENDPOINT_NOT_CONFIGURED", "spec.delivery.repository", "replace the example Git endpoint before execution"))
	}
	if strings.Contains(b.Spec.Delivery.OCIRegistry, "example.invalid") {
		blockers = append(blockers, finding("OCI_ENDPOINT_NOT_CONFIGURED", "spec.delivery.ociRegistry", "replace the example OCI endpoint before execution"))
	}
	if b.Spec.Delivery.RevisionType != "commit" || !gitops.IsFullCommitSHA(b.Spec.Delivery.Revision) {
		blockers = append(blockers, finding("GIT_REVISION_NOT_IMMUTABLE", "spec.delivery.revision", "resolve the selected branch or tag to an immutable full Git commit object ID before execution"))
	}

	names := make([]string, 0, len(enabled))
	for name := range enabled {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c, ok := cs[name]
		if !ok {
			return domain.DeploymentPlan{}, fmt.Errorf("unknown component %s", name)
		}
		deps := make([]string, 0)
		for _, d := range c.Spec.Dependencies {
			if enabled[d] {
				deps = append(deps, d)
			}
		}
		sort.Strings(deps)
		provides := append([]string(nil), c.Spec.Provides...)
		sort.Strings(provides)
		riskSummary[c.Spec.Risk]++
		steps = append(steps, domain.PlanStep{
			ID: fmt.Sprintf("wave-%03d-%s", c.Spec.Wave, name), Component: name,
			ReleaseConstraint: c.Spec.Release, CertificationStatus: c.Spec.Certification.Status,
			SourceResolved: c.Spec.Source.Resolved, SourceLockDigest: c.Spec.Source.SourceLockDigest,
			CertificationEvidence: c.Spec.Certification.EvidenceDigest,
			Wave:                  c.Spec.Wave, Risk: c.Spec.Risk, Dependencies: deps, Provides: provides,
			Readiness: append([]string(nil), c.Spec.Readiness...), Rollback: c.Spec.Rollback.Strategy,
			ApprovalRequired: approvals[c.Spec.Risk],
		})
		path := "catalog.components." + name
		if !exactRelease.MatchString(c.Spec.Release) {
			blockers = append(blockers, finding("COMPONENT_VERSION_NOT_PINNED", path+".release", "resolve and verify an exact component version before execution"))
			catalogReadinessBlockers++
		}
		if !c.Spec.Source.Resolved {
			blockers = append(blockers, finding("COMPONENT_SOURCE_UNRESOLVED", path+".source", "resolve the source and verify artifact integrity, provenance, licenses and image inventory"))
			catalogReadinessBlockers++
		}
		if c.Spec.Source.SourceLockDigest == "" {
			blockers = append(blockers, finding("SOURCE_LOCK_MISSING", path+".source.sourceLockDigest", "an immutable source lock digest is required"))
			catalogReadinessBlockers++
		}
		certificationStatus := strings.ToLower(strings.TrimSpace(c.Spec.Certification.Status))
		if certificationStatus != "target-runtime-certified" && certificationStatus != "upgrade-certified" {
			blockers = append(blockers, finding("COMPONENT_NOT_RUNTIME_CERTIFIED", path+".certification.status", "component is not target-runtime or upgrade certified"))
			catalogReadinessBlockers++
		}
		if c.Spec.Certification.EvidenceDigest == "" {
			blockers = append(blockers, finding("CERTIFICATION_EVIDENCE_MISSING", path+".certification.evidenceDigest", "runtime certification evidence digest is required"))
			catalogReadinessBlockers++
		}
	}

	if catalogReadinessBlockers == 0 && !certificationAuthorityVerified {
		blockers = append(blockers, finding("CERTIFICATION_AUTHORITY_UNVERIFIED", "catalog.certificationAuthority", "execution readiness requires a RUNTIME/PRODUCTION Catalog release whose certification evidence was revalidated by the control-plane authority"))
	}

	sort.Slice(steps, func(i, j int) bool {
		if steps[i].Wave == steps[j].Wave {
			return steps[i].Component < steps[j].Component
		}
		return steps[i].Wave < steps[j].Wave
	})
	sort.Slice(blockers, func(i, j int) bool {
		if blockers[i].Path == blockers[j].Path {
			return blockers[i].Code < blockers[j].Code
		}
		return blockers[i].Path < blockers[j].Path
	})

	blueprintRaw, err := json.Marshal(b)
	if err != nil {
		return domain.DeploymentPlan{}, fmt.Errorf("marshal blueprint: %w", err)
	}
	blueprintSum := sha256.Sum256(blueprintRaw)
	blueprintDigest := "sha256:" + hex.EncodeToString(blueprintSum[:])
	catalogDigest := catalog.Digest(cs)
	identityRaw, _ := json.Marshal(struct {
		BlueprintDigest string
		CatalogDigest   string
		Steps           []domain.PlanStep
	}{blueprintDigest, catalogDigest, steps})
	identitySum := sha256.Sum256(identityRaw)
	executable := len(blockers) == 0
	status := "planning-only"
	if executable {
		status = "execution-ready"
	}
	return domain.DeploymentPlan{
		ID: "plan-" + hex.EncodeToString(identitySum[:8]), Blueprint: b.Metadata.Name,
		BlueprintVersion: b.Metadata.Version, BlueprintDigest: blueprintDigest, CatalogDigest: catalogDigest,
		CreatedAt: time.Now().UTC(), Status: status, Executable: executable,
		Blockers: blockers, RiskSummary: riskSummary, Steps: steps, EvidenceRequired: true,
	}, nil
}

func finding(code, path, message string) domain.Finding {
	return domain.Finding{Code: code, Severity: "blocker", Path: path, Message: message}
}
