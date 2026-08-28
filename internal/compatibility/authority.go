package compatibility

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/targetmodel"
)

const AuthorityMethod = "PLATFORM_COMPATIBILITY_MATRIX_V1"

type Target struct {
	KubernetesVersion string `json:"kubernetesVersion"`
	Architecture      string `json:"architecture"`
	Distribution      string `json:"distribution"`
	Provider          string `json:"provider"`
}

type Constraint struct {
	Name                 string   `json:"name"`
	KubernetesMinVersion string   `json:"kubernetesMinVersion"`
	KubernetesMaxVersion string   `json:"kubernetesMaxVersion"`
	Architectures        []string `json:"architectures"`
	Distributions        []string `json:"distributions"`
	Providers            []string `json:"providers"`
}

type Check struct {
	Constraint string   `json:"constraint"`
	Dimension  string   `json:"dimension"`
	Status     string   `json:"status"`
	Target     string   `json:"target"`
	Allowed    []string `json:"allowed,omitempty"`
	Authority  string   `json:"authority"`
	Message    string   `json:"message"`
}

type Decision struct {
	Method   string   `json:"method"`
	Status   string   `json:"status"`
	Target   Target   `json:"target"`
	Checks   []Check  `json:"checks"`
	Blockers []string `json:"blockers,omitempty"`
	Digest   string   `json:"digest"`
}

func NormalizeTarget(t Target) Target {
	t.KubernetesVersion = normalizeKubernetesVersion(t.KubernetesVersion)
	t.Architecture = strings.ToLower(strings.TrimSpace(t.Architecture))
	t.Distribution = targetmodel.CanonicalDistribution(t.Distribution)
	t.Provider = strings.ToLower(strings.TrimSpace(t.Provider))
	return t
}

func Evaluate(target Target, constraints []Constraint) Decision {
	target = NormalizeTarget(target)
	normalized := append([]Constraint(nil), constraints...)
	for i := range normalized {
		normalized[i] = normalizeConstraint(normalized[i])
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Name < normalized[j].Name })
	out := Decision{Method: AuthorityMethod, Status: "PASS", Target: target}
	for _, c := range normalized {
		out.Checks = append(out.Checks,
			versionCheck(target, c),
			membershipCheck(c.Name, "architecture", target.Architecture, c.Architectures),
			membershipCheck(c.Name, "distribution", target.Distribution, c.Distributions),
			membershipCheck(c.Name, "provider", target.Provider, c.Providers),
		)
	}
	sort.Slice(out.Checks, func(i, j int) bool {
		if out.Checks[i].Constraint != out.Checks[j].Constraint {
			return out.Checks[i].Constraint < out.Checks[j].Constraint
		}
		return out.Checks[i].Dimension < out.Checks[j].Dimension
	})
	for _, check := range out.Checks {
		if check.Status != "PASS" {
			out.Status = "FAIL"
			out.Blockers = append(out.Blockers, check.Constraint+":"+check.Dimension+":"+check.Message)
		}
	}
	sort.Strings(out.Blockers)
	out.Digest = Digest(out)
	return out
}

func Validate(decision Decision, constraints []Constraint) error {
	if decision.Method != AuthorityMethod || (decision.Status != "PASS" && decision.Status != "FAIL") || !strings.HasPrefix(decision.Digest, "sha256:") {
		return fmt.Errorf("compatibility decision authority is incomplete")
	}
	if decision.Digest != Digest(decision) {
		return fmt.Errorf("compatibility decision digest mismatch")
	}
	expected := Evaluate(decision.Target, constraints)
	gotRaw, _ := json.Marshal(decision)
	expectedRaw, _ := json.Marshal(expected)
	if string(gotRaw) != string(expectedRaw) {
		return fmt.Errorf("compatibility decision does not match authoritative constraints")
	}
	return nil
}

func Digest(v Decision) string {
	clone := v
	clone.Digest = ""
	raw, _ := json.Marshal(clone)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func CoversConstraint(outer, inner Constraint) error {
	outer = normalizeConstraint(outer)
	inner = normalizeConstraint(inner)
	outerMin, e1 := minor(outer.KubernetesMinVersion)
	outerMax, e2 := minor(outer.KubernetesMaxVersion)
	innerMin, e3 := minor(inner.KubernetesMinVersion)
	innerMax, e4 := minor(inner.KubernetesMaxVersion)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || outerMin > innerMin || outerMax < innerMax {
		return fmt.Errorf("Kubernetes range is not covered")
	}
	if !containsAll(outer.Architectures, inner.Architectures) {
		return fmt.Errorf("architecture set is not covered")
	}
	if !containsAll(outer.Distributions, inner.Distributions) {
		return fmt.Errorf("distribution set is not covered")
	}
	if len(inner.Providers) > 0 && !containsAll(outer.Providers, inner.Providers) {
		return fmt.Errorf("provider set is not covered")
	}
	return nil
}

func normalizeConstraint(c Constraint) Constraint {
	c.Name = strings.TrimSpace(c.Name)
	c.KubernetesMinVersion = normalizeKubernetesVersion(c.KubernetesMinVersion)
	c.KubernetesMaxVersion = normalizeKubernetesVersion(c.KubernetesMaxVersion)
	c.Architectures = normalizedSet(c.Architectures)
	c.Distributions = targetmodel.CanonicalDistributionSet(c.Distributions)
	c.Providers = normalizedSet(c.Providers)
	return c
}

func normalizedSet(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func containsAll(outer, inner []string) bool {
	if contains(outer, "*") {
		return true
	}
	set := map[string]bool{}
	for _, v := range outer {
		set[v] = true
	}
	for _, v := range inner {
		if !set[v] {
			return false
		}
	}
	return true
}

func membershipCheck(name, dimension, target string, allowed []string) Check {
	check := Check{Constraint: name, Dimension: dimension, Target: target, Allowed: append([]string(nil), allowed...), Authority: AuthorityMethod}
	if target == "" {
		check.Status = "FAIL"
		check.Message = "target value is required"
		return check
	}
	if contains(allowed, "*") || contains(allowed, target) {
		check.Status = "PASS"
		check.Message = "target is admitted"
	} else {
		check.Status = "FAIL"
		check.Message = "target is outside admitted compatibility set"
	}
	return check
}

func versionCheck(target Target, c Constraint) Check {
	allowed := []string{c.KubernetesMinVersion + ".." + c.KubernetesMaxVersion}
	check := Check{Constraint: c.Name, Dimension: "kubernetes", Target: target.KubernetesVersion, Allowed: allowed, Authority: AuthorityMethod}
	v, ev := minor(target.KubernetesVersion)
	min, emin := minor(c.KubernetesMinVersion)
	max, emax := minor(c.KubernetesMaxVersion)
	if ev != nil || emin != nil || emax != nil || v < min || v > max {
		check.Status = "FAIL"
		check.Message = "Kubernetes minor is outside admitted range"
	} else {
		check.Status = "PASS"
		check.Message = "Kubernetes minor is admitted"
	}
	return check
}

func normalizeKubernetesVersion(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return "1." + parts[1]
	}
	return v
}

func minor(v string) (int, error) {
	v = normalizeKubernetesVersion(v)
	parts := strings.Split(v, ".")
	if len(parts) != 2 || parts[0] != "1" {
		return 0, fmt.Errorf("invalid Kubernetes version %q", v)
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid Kubernetes version %q", v)
	}
	return n, nil
}

func contains(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}
