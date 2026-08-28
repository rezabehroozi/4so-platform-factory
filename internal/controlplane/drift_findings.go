package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

func DriftFindingFingerprint(clusterID, category, code, resource string) string {
	raw := strings.ToLower(strings.TrimSpace(clusterID)) + "\x00" + strings.ToUpper(strings.TrimSpace(category)) + "\x00" + strings.ToUpper(strings.TrimSpace(code)) + "\x00" + strings.TrimSpace(resource)
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func severityRank(v DriftSeverity) int {
	switch v {
	case DriftSeverityCritical:
		return 5
	case DriftSeverityHigh:
		return 4
	case DriftSeverityMedium:
		return 3
	case DriftSeverityLow:
		return 2
	default:
		return 1
	}
}

func MergeDriftFindingHistory(clusterID string, prior []DriftScan, findings []DriftFinding, now time.Time) []DriftFinding {
	now = now.UTC()
	history := map[string]DriftFinding{}
	for _, scan := range prior {
		for _, target := range scan.Targets {
			if target.ClusterID != clusterID {
				continue
			}
			for _, finding := range target.Findings {
				if finding.Fingerprint == "" {
					continue
				}
				old, ok := history[finding.Fingerprint]
				if !ok || finding.LastSeenAt.After(old.LastSeenAt) {
					history[finding.Fingerprint] = finding
				}
			}
		}
	}
	dedup := map[string]DriftFinding{}
	for _, finding := range findings {
		finding.Category = strings.ToUpper(strings.TrimSpace(finding.Category))
		finding.Code = strings.ToUpper(strings.TrimSpace(finding.Code))
		finding.Owner = strings.TrimSpace(finding.Owner)
		finding.Resource = strings.TrimSpace(finding.Resource)
		finding.Summary = strings.TrimSpace(finding.Summary)
		finding.Remediation.Action = strings.ToUpper(strings.TrimSpace(finding.Remediation.Action))
		finding.Remediation.Mode = strings.ToUpper(strings.TrimSpace(finding.Remediation.Mode))
		if finding.Fingerprint == "" {
			finding.Fingerprint = DriftFindingFingerprint(clusterID, finding.Category, finding.Code, finding.Resource)
		}
		if old, ok := history[finding.Fingerprint]; ok {
			finding.FirstSeenAt = old.FirstSeenAt
			finding.Occurrences = old.Occurrences + 1
		} else {
			finding.FirstSeenAt = now
			finding.Occurrences = 1
		}
		finding.LastSeenAt = now
		if old, ok := dedup[finding.Fingerprint]; ok {
			if severityRank(finding.Severity) > severityRank(old.Severity) {
				old.Severity = finding.Severity
			}
			if finding.Summary != "" {
				old.Summary = finding.Summary
			}
			if finding.Remediation.Action != "" {
				old.Remediation = finding.Remediation
			}
			dedup[finding.Fingerprint] = old
		} else {
			dedup[finding.Fingerprint] = finding
		}
	}
	out := make([]DriftFinding, 0, len(dedup))
	for _, finding := range dedup {
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func RuntimeDriftFindings(target DriftScanTarget, result DriftTaskResult, prior []DriftScan, now time.Time) (*DriftComparison, []DriftFinding) {
	findings := append([]DriftFinding(nil), target.Findings...)
	comparison := &DriftComparison{ProductGeneratedDigest: target.DesiredDigest, LiveObservedDigest: strings.TrimSpace(result.ObservedDigest), Classification: string(GitDriftInSync)}
	if comparison.LiveObservedDigest == "" {
		comparison.Classification = string(GitDriftObservedUnknown)
	} else if comparison.LiveObservedDigest != comparison.ProductGeneratedDigest {
		comparison.Classification = string(GitDriftLiveDrift)
		findings = append(findings, DriftFinding{Category: "BASELINE", Code: "LIVE_DIGEST_MISMATCH", Severity: DriftSeverityHigh, Owner: "platform-operator", Resource: target.ClusterID, Summary: "live observed digest differs from the platform-generated desired digest", Remediation: DriftRemediation{Action: "REAPPLY_BASELINE", Mode: "OPERATION", Eligible: true}})
	}
	for _, change := range result.Changes {
		action := strings.ToUpper(strings.TrimSpace(change.Action))
		if action == "" || action == "NOOP" {
			continue
		}
		resource := strings.TrimSpace(change.Resource)
		category := "BASELINE"
		severity := DriftSeverityMedium
		remediation := DriftRemediation{Action: "REAPPLY_BASELINE", Mode: "OPERATION", Eligible: true}
		upperResource := strings.ToUpper(resource)
		if strings.Contains(upperResource, "NETWORKPOLICY/") || strings.Contains(upperResource, "RESOURCEQUOTA/") || strings.Contains(upperResource, "LIMITRANGE/") {
			category = "POLICY"
			severity = DriftSeverityHigh
		}
		findings = append(findings, DriftFinding{Category: category, Code: "RESOURCE_" + action, Severity: severity, Owner: "platform-operator", Resource: resource, Summary: fmt.Sprintf("%s change detected for %s", action, resource), Remediation: remediation})
	}
	if target.Git != nil {
		comparison.ProductGeneratedDigest = target.Git.BaseDigest
		comparison.GitDesiredDigest = target.Git.CurrentDigest
		comparison.LiveObservedDigest = target.Git.ObservedDigest
		comparison.Classification = string(target.Git.Classification)
		var finding *DriftFinding
		switch target.Git.Classification {
		case GitDriftThreeWayConflict:
			finding = &DriftFinding{Category: "GIT", Code: "THREE_WAY_CONFLICT", Severity: DriftSeverityCritical, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "product-generated, Git desired and live observed state conflict", Remediation: DriftRemediation{Action: "RESOLVE_THREE_WAY", Mode: "GUIDANCE", Eligible: false, Reason: "automatic overwrite is intentionally disabled"}}
		case GitDriftUntrustedChange:
			finding = &DriftFinding{Category: "GIT", Code: "UNTRUSTED_GIT_CHANGE", Severity: DriftSeverityCritical, Owner: "security-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "Git desired state changed without a trusted platform signature", Remediation: DriftRemediation{Action: "REVIEW_UNTRUSTED_GIT", Mode: "GUIDANCE", Eligible: false, Reason: "untrusted Git state cannot be adopted automatically"}}
		case GitDriftLiveDrift:
			finding = &DriftFinding{Category: "GIT", Code: "LIVE_DRIFT", Severity: DriftSeverityHigh, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "live observed state differs from the trusted Git desired state", Remediation: DriftRemediation{Action: "REAPPLY_BASELINE", Mode: "OPERATION", Eligible: true}}
		case GitDriftExternalApplied:
			finding = &DriftFinding{Category: "GIT", Code: "TRUSTED_EXTERNAL_APPLIED", Severity: DriftSeverityLow, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "trusted external Git change is already applied live and can be adopted", Remediation: DriftRemediation{Action: "ADOPT_TRUSTED_GIT", Mode: "DIRECT_ACTION", Eligible: target.Git.Adoptable}}
		case GitDriftExternalChange:
			finding = &DriftFinding{Category: "GIT", Code: "TRUSTED_EXTERNAL_CHANGE", Severity: DriftSeverityMedium, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "trusted external Git change differs from the managed base", Remediation: DriftRemediation{Action: "REVIEW_EXTERNAL_GIT", Mode: "GUIDANCE", Eligible: false}}
		case GitDriftObservedUnknown:
			finding = &DriftFinding{Category: "GIT", Code: "LIVE_OBSERVED_UNKNOWN", Severity: DriftSeverityMedium, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "live digest is unavailable for three-way comparison", Remediation: DriftRemediation{Action: "RERUN_DRIFT_SCAN", Mode: "GUIDANCE", Eligible: false}}
		case GitDriftCommitOnlyChange:
			finding = &DriftFinding{Category: "GIT", Code: "COMMIT_ONLY_CHANGE", Severity: DriftSeverityLow, Owner: "platform-operator", Resource: target.Git.Organization + "/" + target.Git.Repository, Summary: "Git commit changed without a desired-state digest change", Remediation: DriftRemediation{Action: "REVIEW_GIT_COMMIT", Mode: "GUIDANCE", Eligible: false}}
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return comparison, MergeDriftFindingHistory(target.ClusterID, prior, findings, now)
}
