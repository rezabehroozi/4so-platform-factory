package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const BaselineAuthority = "4SO_KUBERNETES_SECURITY_BASELINE_V1"

type Severity string

const (
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	Fingerprint string   `json:"fingerprint"`
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Kind        string   `json:"kind"`
	Namespace   string   `json:"namespace,omitempty"`
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Evidence    string   `json:"evidence"`
}

type Result struct {
	Authority string    `json:"authority"`
	Objects   int       `json:"objectsEvaluated"`
	Findings  []Finding `json:"findings"`
}

func EvaluateJSON(data []byte) (Result, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Result{}, fmt.Errorf("decode compliance input: %w", err)
	}
	objects, err := normalizeObjects(raw)
	if err != nil {
		return Result{}, err
	}
	return Evaluate(objects), nil
}

func Evaluate(objects []map[string]any) Result {
	out := Result{Authority: BaselineAuthority, Objects: len(objects), Findings: []Finding{}}
	for _, obj := range objects {
		kind := stringValue(obj["kind"])
		meta, _ := obj["metadata"].(map[string]any)
		name := stringValue(meta["name"])
		ns := stringValue(meta["namespace"])
		if kind == "ClusterRoleBinding" || kind == "RoleBinding" {
			roleRef, _ := obj["roleRef"].(map[string]any)
			if strings.EqualFold(stringValue(roleRef["kind"]), "ClusterRole") && stringValue(roleRef["name"]) == "cluster-admin" {
				out.Findings = append(out.Findings, finding("RBAC_CLUSTER_ADMIN_BINDING", SeverityCritical, kind, ns, name, "Binding grants cluster-admin", "roleRef.name=cluster-admin"))
			}
		}
		podSpec := extractPodSpec(kind, obj)
		if podSpec != nil {
			for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
				if boolValue(podSpec[field]) {
					out.Findings = append(out.Findings, finding("WORKLOAD_HOST_NAMESPACE", SeverityHigh, kind, ns, name, "Workload uses host namespace access", field+"=true"))
				}
			}
			for _, container := range containers(podSpec) {
				cname := stringValue(container["name"])
				sec, _ := container["securityContext"].(map[string]any)
				if boolValue(sec["privileged"]) {
					out.Findings = append(out.Findings, finding("WORKLOAD_PRIVILEGED_CONTAINER", SeverityCritical, kind, ns, name, "Container runs privileged", "container="+cname+" privileged=true"))
				}
				image := stringValue(container["image"])
				if image != "" && !usesDigestPin(image) {
					rule := "IMAGE_NOT_DIGEST_PINNED"
					summary := "Container image is not digest pinned"
					if usesLatestTag(image) {
						rule = "IMAGE_MUTABLE_LATEST_TAG"
						summary = "Container image uses a mutable or implicit latest tag"
					}
					out.Findings = append(out.Findings, finding(rule, SeverityMedium, kind, ns, name, summary, "container="+cname+" image="+image))
				}
			}
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Severity != out.Findings[j].Severity {
			return severityRank(out.Findings[i].Severity) > severityRank(out.Findings[j].Severity)
		}
		if out.Findings[i].RuleID != out.Findings[j].RuleID {
			return out.Findings[i].RuleID < out.Findings[j].RuleID
		}
		return out.Findings[i].Fingerprint < out.Findings[j].Fingerprint
	})
	return out
}

func normalizeObjects(raw any) ([]map[string]any, error) {
	switch v := raw.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for i, item := range v {
			obj, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("object %d is not a JSON object", i)
			}
			out = append(out, obj)
		}
		return out, nil
	case map[string]any:
		if strings.EqualFold(stringValue(v["kind"]), "List") {
			items, ok := v["items"].([]any)
			if !ok {
				return nil, fmt.Errorf("List.items must be an array")
			}
			return normalizeObjects(items)
		}
		return []map[string]any{v}, nil
	default:
		return nil, fmt.Errorf("compliance input must be a Kubernetes object, List, or array")
	}
}

func extractPodSpec(kind string, obj map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	switch kind {
	case "Pod":
		return spec
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		tmpl, _ := spec["template"].(map[string]any)
		ps, _ := tmpl["spec"].(map[string]any)
		return ps
	case "CronJob":
		jt, _ := spec["jobTemplate"].(map[string]any)
		js, _ := jt["spec"].(map[string]any)
		tmpl, _ := js["template"].(map[string]any)
		ps, _ := tmpl["spec"].(map[string]any)
		return ps
	default:
		return nil
	}
}

func containers(spec map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, key := range []string{"initContainers", "containers", "ephemeralContainers"} {
		list, _ := spec[key].([]any)
		for _, item := range list {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, obj)
			}
		}
	}
	return out
}

func FindingFingerprint(rule, kind, ns, name, evidence string) string {
	identity := strings.Join([]string{BaselineAuthority, strings.TrimSpace(rule), strings.TrimSpace(kind), strings.TrimSpace(ns), strings.TrimSpace(name), strings.TrimSpace(evidence)}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func ValidateFindingIdentity(v Finding) bool {
	if strings.TrimSpace(v.RuleID) == "" || strings.TrimSpace(v.Kind) == "" || strings.TrimSpace(v.Name) == "" || strings.TrimSpace(v.Summary) == "" || strings.TrimSpace(v.Evidence) == "" {
		return false
	}
	if len(v.Summary) > 512 || len(v.Evidence) > 1024 {
		return false
	}
	if severityRank(v.Severity) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v.Fingerprint), FindingFingerprint(v.RuleID, v.Kind, v.Namespace, v.Name, v.Evidence))
}

func finding(rule string, severity Severity, kind, ns, name, summary, evidence string) Finding {
	return Finding{Fingerprint: FindingFingerprint(rule, kind, ns, name, evidence), RuleID: rule, Severity: severity, Kind: kind, Namespace: ns, Name: name, Summary: summary, Evidence: evidence}
}

func usesDigestPin(image string) bool {
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || len(parts[1]) != 64 {
		return false
	}
	for _, r := range parts[1] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func severityRank(v Severity) int {
	switch v {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	default:
		return 0
	}
}

func usesLatestTag(image string) bool {
	if usesDigestPin(image) {
		return false
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	return colon <= slash || strings.EqualFold(image[colon+1:], "latest")
}
func stringValue(v any) string { s, _ := v.(string); return strings.TrimSpace(s) }
func boolValue(v any) bool     { b, _ := v.(bool); return b }
