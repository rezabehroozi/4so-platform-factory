package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	RuntimeClosureAPIVersion       = "platform.4so.io/v1alpha1"
	RuntimeClosureKind             = "RuntimeClosureReport"
	RuntimeClosureEvidenceSchema   = 1
	RuntimeClosureCanonicalization = "sorted-string-map-json-v1"
)

var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// RuntimeClosureInputs are the immutable values bound by a runtime-closure
// evidence digest. Every field is a string so the canonical form is stable
// across Go, browser and external verifier implementations.
type RuntimeClosureInputs struct {
	CampaignID             string `json:"campaignId"`
	ProjectID              string `json:"projectId"`
	ClusterID              string `json:"clusterId"`
	ClusterInventoryDigest string `json:"clusterInventoryDigest"`
	BaselineDeploymentID   string `json:"baselineDeploymentId"`
	BaselineDesiredDigest  string `json:"baselineDesiredDigest"`
	BaselineObservedDigest string `json:"baselineObservedDigest"`
	RuntimeVerificationID  string `json:"runtimeVerificationId"`
	RuntimeReportDigest    string `json:"runtimeReportDigest"`
	RuntimeDesiredDigest   string `json:"runtimeDesiredDigest"`
	RuntimeObservedDigest  string `json:"runtimeObservedDigest"`
}

func (v RuntimeClosureInputs) canonicalMap() map[string]string {
	return map[string]string{
		"campaignId":             strings.TrimSpace(v.CampaignID),
		"projectId":              strings.TrimSpace(v.ProjectID),
		"clusterId":              strings.TrimSpace(v.ClusterID),
		"clusterInventoryDigest": strings.TrimSpace(v.ClusterInventoryDigest),
		"baselineDeploymentId":   strings.TrimSpace(v.BaselineDeploymentID),
		"baselineDesiredDigest":  strings.TrimSpace(v.BaselineDesiredDigest),
		"baselineObservedDigest": strings.TrimSpace(v.BaselineObservedDigest),
		"runtimeVerificationId":  strings.TrimSpace(v.RuntimeVerificationID),
		"runtimeReportDigest":    strings.TrimSpace(v.RuntimeReportDigest),
		"runtimeDesiredDigest":   strings.TrimSpace(v.RuntimeDesiredDigest),
		"runtimeObservedDigest":  strings.TrimSpace(v.RuntimeObservedDigest),
	}
}

func (v RuntimeClosureInputs) Validate() error {
	ids := map[string]string{
		"campaignId":            v.CampaignID,
		"projectId":             v.ProjectID,
		"clusterId":             v.ClusterID,
		"baselineDeploymentId":  v.BaselineDeploymentID,
		"runtimeVerificationId": v.RuntimeVerificationID,
	}
	for name, value := range ids {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	digests := map[string]string{
		"clusterInventoryDigest": v.ClusterInventoryDigest,
		"baselineDesiredDigest":  v.BaselineDesiredDigest,
		"baselineObservedDigest": v.BaselineObservedDigest,
		"runtimeReportDigest":    v.RuntimeReportDigest,
		"runtimeDesiredDigest":   v.RuntimeDesiredDigest,
		"runtimeObservedDigest":  v.RuntimeObservedDigest,
	}
	for name, value := range digests {
		if !sha256Pattern.MatchString(strings.TrimSpace(value)) {
			return fmt.Errorf("%s must be a lowercase sha256 digest", name)
		}
	}
	if v.BaselineDesiredDigest != v.BaselineObservedDigest {
		return errors.New("baseline desired and observed digests differ")
	}
	if v.RuntimeDesiredDigest != v.RuntimeObservedDigest {
		return errors.New("runtime desired and observed digests differ")
	}
	if v.RuntimeDesiredDigest != v.BaselineDesiredDigest {
		return errors.New("runtime and baseline desired digests differ")
	}
	return nil
}

func (v RuntimeClosureInputs) CanonicalJSON() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(v.canonicalMap())
}

func (v RuntimeClosureInputs) Digest() (string, error) {
	raw, err := v.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type RuntimeClosureEvidence struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	Algorithm        string               `json:"algorithm"`
	Canonicalization string               `json:"canonicalization"`
	Inputs           RuntimeClosureInputs `json:"inputs"`
	Digest           string               `json:"digest"`
}

type RuntimeClosureVerification struct {
	Valid                 bool   `json:"valid"`
	CampaignID            string `json:"campaignId"`
	ProjectID             string `json:"projectId"`
	ClusterID             string `json:"clusterId"`
	BaselineDeploymentID  string `json:"baselineDeploymentId"`
	RuntimeVerificationID string `json:"runtimeVerificationId"`
	EvidenceDigest        string `json:"evidenceDigest"`
	Canonicalization      string `json:"canonicalization"`
}

type reportEnvelope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ID             string `json:"id"`
		EvidenceDigest string `json:"evidenceDigest"`
		State          string `json:"state"`
	} `json:"metadata"`
	Product struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"product"`
	Target struct {
		Cluster            json.RawMessage `json:"cluster"`
		BaselineDeployment json.RawMessage `json:"baselineDeployment"`
	} `json:"target"`
	RuntimeVerification json.RawMessage        `json:"runtimeVerification"`
	Result              map[string]any         `json:"result"`
	Claims              map[string]any         `json:"claims"`
	Evidence            RuntimeClosureEvidence `json:"evidence"`
}

func decodeStrict(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func objectString(raw json.RawMessage, key string) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("object is missing")
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	text, ok := value[key].(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("field %s is missing", key)
	}
	return text, nil
}

func boolClaim(claims map[string]any, key string, expected bool) error {
	value, ok := claims[key].(bool)
	if !ok || value != expected {
		return fmt.Errorf("claim %s must be %t", key, expected)
	}
	return nil
}

// VerifyRuntimeClosureReport independently recomputes the evidence digest and
// cross-checks it against every duplicated identity/digest carried by the
// report. It never treats a successful HTTP response as proof by itself.
func VerifyRuntimeClosureReport(raw []byte) (RuntimeClosureVerification, error) {
	var result RuntimeClosureVerification
	var report reportEnvelope
	if err := decodeStrict(raw, &report); err != nil {
		return result, fmt.Errorf("decode runtime closure report: %w", err)
	}
	if report.APIVersion != RuntimeClosureAPIVersion || report.Kind != RuntimeClosureKind {
		return result, errors.New("unsupported runtime closure report contract")
	}
	if report.Metadata.State != "SUCCEEDED" {
		return result, fmt.Errorf("runtime closure report state is %s, not SUCCEEDED", report.Metadata.State)
	}
	if strings.TrimSpace(report.Product.Name) != "4SO Platform Factory" || strings.TrimSpace(report.Product.Version) == "" {
		return result, errors.New("product identity or version is missing")
	}
	if report.Evidence.SchemaVersion != RuntimeClosureEvidenceSchema || report.Evidence.Algorithm != "sha256" || report.Evidence.Canonicalization != RuntimeClosureCanonicalization {
		return result, errors.New("unsupported runtime closure evidence schema")
	}
	if err := report.Evidence.Inputs.Validate(); err != nil {
		return result, fmt.Errorf("invalid runtime closure evidence inputs: %w", err)
	}
	computed, err := report.Evidence.Inputs.Digest()
	if err != nil {
		return result, err
	}
	if !sha256Pattern.MatchString(report.Evidence.Digest) || report.Evidence.Digest != computed {
		return result, errors.New("runtime closure evidence digest mismatch")
	}
	if report.Metadata.ID != report.Evidence.Inputs.CampaignID || report.Metadata.EvidenceDigest != computed {
		return result, errors.New("report metadata does not match evidence inputs")
	}
	if state, _ := report.Result["state"].(string); state != "SUCCEEDED" {
		return result, errors.New("report result is not SUCCEEDED")
	}
	for key, expected := range map[string]bool{"runtimeClosed": true, "runtimeCertified": false, "productionReady": false, "haCertified": false} {
		if err := boolClaim(report.Claims, key, expected); err != nil {
			return result, err
		}
	}
	checks := []struct {
		name string
		raw  json.RawMessage
		key  string
		want string
	}{
		{"cluster id", report.Target.Cluster, "id", report.Evidence.Inputs.ClusterID},
		{"cluster project", report.Target.Cluster, "projectId", report.Evidence.Inputs.ProjectID},
		{"cluster inventory digest", report.Target.Cluster, "inventoryDigest", report.Evidence.Inputs.ClusterInventoryDigest},
		{"baseline id", report.Target.BaselineDeployment, "id", report.Evidence.Inputs.BaselineDeploymentID},
		{"baseline project", report.Target.BaselineDeployment, "projectId", report.Evidence.Inputs.ProjectID},
		{"baseline cluster", report.Target.BaselineDeployment, "clusterId", report.Evidence.Inputs.ClusterID},
		{"baseline desired digest", report.Target.BaselineDeployment, "desiredDigest", report.Evidence.Inputs.BaselineDesiredDigest},
		{"baseline observed digest", report.Target.BaselineDeployment, "observedDigest", report.Evidence.Inputs.BaselineObservedDigest},
		{"verification id", report.RuntimeVerification, "id", report.Evidence.Inputs.RuntimeVerificationID},
		{"verification project", report.RuntimeVerification, "projectId", report.Evidence.Inputs.ProjectID},
		{"verification cluster", report.RuntimeVerification, "clusterId", report.Evidence.Inputs.ClusterID},
		{"verification report digest", report.RuntimeVerification, "reportDigest", report.Evidence.Inputs.RuntimeReportDigest},
		{"verification desired digest", report.RuntimeVerification, "desiredDigest", report.Evidence.Inputs.RuntimeDesiredDigest},
		{"verification observed digest", report.RuntimeVerification, "observedDigest", report.Evidence.Inputs.RuntimeObservedDigest},
	}
	for _, check := range checks {
		got, getErr := objectString(check.raw, check.key)
		if getErr != nil || got != check.want {
			return result, fmt.Errorf("%s does not match evidence inputs", check.name)
		}
	}
	result = RuntimeClosureVerification{
		Valid: true, CampaignID: report.Evidence.Inputs.CampaignID, ProjectID: report.Evidence.Inputs.ProjectID,
		ClusterID: report.Evidence.Inputs.ClusterID, BaselineDeploymentID: report.Evidence.Inputs.BaselineDeploymentID,
		RuntimeVerificationID: report.Evidence.Inputs.RuntimeVerificationID, EvidenceDigest: computed,
		Canonicalization: RuntimeClosureCanonicalization,
	}
	return result, nil
}
