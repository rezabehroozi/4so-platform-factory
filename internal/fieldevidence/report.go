package fieldevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/disasterrecovery"
	"platform.4so.io/factory/internal/lifecycle"
)

const (
	APIVersion             = "platform.4so.io/v1alpha1"
	Kind                   = "FieldExecutionEvidenceReport"
	EvidenceSchema         = 3
	ExactSHAEvidenceSchema = 2
	LegacyEvidenceSchema   = 1
	Canonicalization       = "sorted-string-map-json-v1"
	Algorithm              = "sha256"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Inputs struct {
	InstallerVersion        string `json:"installerVersion"`
	GeneratedAt             string `json:"generatedAt"`
	RunID                   string `json:"runId"`
	RunState                string `json:"runState"`
	ExecutionMode           string `json:"executionMode"`
	SpecDigest              string `json:"specDigest"`
	BundleDigest            string `json:"bundleDigest"`
	ReleaseArtifactDigest   string `json:"releaseArtifactDigest,omitempty"`
	InstallerBinaryDigest   string `json:"installerBinaryDigest,omitempty"`
	PreflightDigest         string `json:"preflightDigest"`
	BundleSnapshotDigest    string `json:"bundleSnapshotDigest"`
	PreflightSnapshotDigest string `json:"preflightSnapshotDigest"`
	InstallationRunDigest   string `json:"installationRunDigest"`
	GitOpsStatusDigest      string `json:"gitOpsStatusDigest"`
	HAStatusDigest          string `json:"haStatusDigest"`
	AirgapStatusDigest      string `json:"airgapStatusDigest"`
	LifecycleRunsDigest     string `json:"lifecycleRunsDigest"`
	DisasterRecoveryDigest  string `json:"disasterRecoveryDigest"`
}

func (v Inputs) canonicalMap() map[string]string {
	values := map[string]string{
		"installerVersion":        strings.TrimSpace(v.InstallerVersion),
		"generatedAt":             strings.TrimSpace(v.GeneratedAt),
		"runId":                   strings.TrimSpace(v.RunID),
		"runState":                strings.TrimSpace(v.RunState),
		"executionMode":           strings.TrimSpace(v.ExecutionMode),
		"specDigest":              strings.TrimSpace(v.SpecDigest),
		"bundleDigest":            strings.TrimSpace(v.BundleDigest),
		"preflightDigest":         strings.TrimSpace(v.PreflightDigest),
		"bundleSnapshotDigest":    strings.TrimSpace(v.BundleSnapshotDigest),
		"preflightSnapshotDigest": strings.TrimSpace(v.PreflightSnapshotDigest),
		"installationRunDigest":   strings.TrimSpace(v.InstallationRunDigest),
		"gitOpsStatusDigest":      strings.TrimSpace(v.GitOpsStatusDigest),
		"haStatusDigest":          strings.TrimSpace(v.HAStatusDigest),
		"airgapStatusDigest":      strings.TrimSpace(v.AirgapStatusDigest),
		"lifecycleRunsDigest":     strings.TrimSpace(v.LifecycleRunsDigest),
		"disasterRecoveryDigest":  strings.TrimSpace(v.DisasterRecoveryDigest),
	}
	if strings.TrimSpace(v.ReleaseArtifactDigest) != "" {
		values["releaseArtifactDigest"] = strings.TrimSpace(v.ReleaseArtifactDigest)
	}
	if strings.TrimSpace(v.InstallerBinaryDigest) != "" {
		values["installerBinaryDigest"] = strings.TrimSpace(v.InstallerBinaryDigest)
	}
	return values
}

func (v Inputs) Validate() error {
	for name, value := range map[string]string{
		"installerVersion": v.InstallerVersion, "generatedAt": v.GeneratedAt, "runId": v.RunID,
		"runState": v.RunState, "executionMode": v.ExecutionMode,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if v.ExecutionMode != "live" && v.ExecutionMode != "simulation" {
		return errors.New("executionMode must be live or simulation")
	}
	if _, err := time.Parse(time.RFC3339Nano, v.GeneratedAt); err != nil {
		return errors.New("generatedAt must be RFC3339")
	}
	for name, value := range map[string]string{
		"specDigest": v.SpecDigest, "bundleDigest": v.BundleDigest, "preflightDigest": v.PreflightDigest,
		"bundleSnapshotDigest": v.BundleSnapshotDigest, "preflightSnapshotDigest": v.PreflightSnapshotDigest,
		"installationRunDigest": v.InstallationRunDigest, "gitOpsStatusDigest": v.GitOpsStatusDigest,
		"haStatusDigest": v.HAStatusDigest, "airgapStatusDigest": v.AirgapStatusDigest,
		"lifecycleRunsDigest": v.LifecycleRunsDigest, "disasterRecoveryDigest": v.DisasterRecoveryDigest,
	} {
		if !digestPattern.MatchString(strings.TrimSpace(value)) {
			return fmt.Errorf("%s must be a lowercase sha256 digest", name)
		}
	}
	if strings.TrimSpace(v.ReleaseArtifactDigest) != "" && !digestPattern.MatchString(strings.TrimSpace(v.ReleaseArtifactDigest)) {
		return errors.New("releaseArtifactDigest must be a lowercase sha256 digest")
	}
	if strings.TrimSpace(v.InstallerBinaryDigest) != "" && !digestPattern.MatchString(strings.TrimSpace(v.InstallerBinaryDigest)) {
		return errors.New("installerBinaryDigest must be a lowercase sha256 digest")
	}
	return nil
}

func (v Inputs) Digest() (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(v.canonicalMap())
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

type Evidence struct {
	SchemaVersion    int    `json:"schemaVersion"`
	Algorithm        string `json:"algorithm"`
	Canonicalization string `json:"canonicalization"`
	Inputs           Inputs `json:"inputs"`
	Digest           string `json:"digest"`
}

type Metadata struct {
	ID             string    `json:"id"`
	State          string    `json:"state"`
	EvidenceDigest string    `json:"evidenceDigest"`
	GeneratedAt    time.Time `json:"generatedAt"`
}

type Product struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Snapshots struct {
	BundleAdmission      bootstrap.BundleAdmissionStatus `json:"bundleAdmission"`
	Preflight            bootstrap.PreflightReport       `json:"preflight"`
	InstallationRun      bootstrap.Run                   `json:"installationRun"`
	GitOpsStatus         bootstrap.GitOpsHandoverStatus  `json:"gitOpsStatus"`
	HAStatus             map[string]any                  `json:"haStatus"`
	AirgapStatus         map[string]any                  `json:"airgapStatus"`
	LifecycleRuns        []lifecycle.Run                 `json:"lifecycleRuns"`
	DisasterRecoveryRuns []disasterrecovery.Run          `json:"disasterRecoveryRuns"`
}

type Claims struct {
	FieldExecutionObserved bool `json:"fieldExecutionObserved"`
	LiveExecutionObserved  bool `json:"liveExecutionObserved"`
	InstallationSucceeded  bool `json:"installationSucceeded"`
	Simulation             bool `json:"simulation"`
	RuntimeCertified       bool `json:"runtimeCertified"`
	HACertified            bool `json:"haCertified"`
	ProductionReady        bool `json:"productionReady"`
}

type Report struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   Metadata  `json:"metadata"`
	Product    Product   `json:"product"`
	Snapshots  Snapshots `json:"snapshots"`
	Claims     Claims    `json:"claims"`
	Evidence   Evidence  `json:"evidence"`
}

type Verification struct {
	Valid                 bool   `json:"valid"`
	ProductVersion        string `json:"productVersion"`
	ReportID              string `json:"reportId"`
	RunID                 string `json:"runId"`
	RunState              string `json:"runState"`
	ExecutionMode         string `json:"executionMode"`
	SpecDigest            string `json:"specDigest"`
	BundleDigest          string `json:"bundleDigest"`
	ReleaseArtifactDigest string `json:"releaseArtifactDigest,omitempty"`
	InstallerBinaryDigest string `json:"installerBinaryDigest,omitempty"`
	PreflightDigest       string `json:"preflightDigest"`
	EvidenceDigest        string `json:"evidenceDigest"`
	InstallationSucceeded bool   `json:"installationSucceeded"`
	LiveExecutionObserved bool   `json:"liveExecutionObserved"`
}

func Build(version string, snapshots Snapshots, now time.Time) (Report, error) {
	var report Report
	if strings.TrimSpace(version) == "" {
		return report, errors.New("installer version is required")
	}
	if err := snapshots.Preflight.Verify(); err != nil {
		return report, fmt.Errorf("preflight snapshot: %w", err)
	}
	if !snapshots.BundleAdmission.Verified || snapshots.BundleAdmission.BundleDigest == "" {
		return report, errors.New("bundle admission snapshot is not verified")
	}
	if !digestPattern.MatchString(strings.TrimSpace(snapshots.BundleAdmission.SourceReleaseDigest)) {
		return report, errors.New("bundle admission is not bound to an exact source release artifact")
	}
	if strings.TrimSpace(snapshots.InstallationRun.ID) == "" {
		return report, errors.New("installation run is required")
	}
	if snapshots.InstallationRun.BundleDigest != snapshots.BundleAdmission.BundleDigest {
		return report, errors.New("installation run bundle digest does not match bundle admission")
	}
	if snapshots.InstallationRun.PreflightDigest != snapshots.Preflight.Digest {
		return report, errors.New("installation run preflight digest does not match preflight report")
	}
	if snapshots.InstallationRun.SpecDigest != snapshots.Preflight.RequestDigest {
		return report, errors.New("installation run spec digest does not match preflight request digest")
	}
	if snapshots.InstallationRun.Version != version || snapshots.Preflight.Version != version || snapshots.BundleAdmission.Version != version {
		return report, errors.New("installer, bundle, preflight and run versions do not match")
	}
	generated := now.UTC()
	mode := "live"
	if snapshots.InstallationRun.Simulation {
		mode = "simulation"
	}
	installerBinaryDigest, err := CurrentExecutableDigest()
	if err != nil {
		return report, fmt.Errorf("digest running installer executable: %w", err)
	}
	inputs := Inputs{
		InstallerVersion: version, GeneratedAt: generated.Format(time.RFC3339Nano), RunID: snapshots.InstallationRun.ID,
		RunState: string(snapshots.InstallationRun.State), ExecutionMode: mode, SpecDigest: snapshots.InstallationRun.SpecDigest,
		BundleDigest: snapshots.InstallationRun.BundleDigest, ReleaseArtifactDigest: snapshots.BundleAdmission.SourceReleaseDigest, InstallerBinaryDigest: installerBinaryDigest, PreflightDigest: snapshots.InstallationRun.PreflightDigest,
	}
	if inputs.BundleSnapshotDigest, err = digestJSON(snapshots.BundleAdmission); err != nil {
		return report, err
	}
	if inputs.PreflightSnapshotDigest, err = digestJSON(snapshots.Preflight); err != nil {
		return report, err
	}
	if inputs.InstallationRunDigest, err = digestJSON(snapshots.InstallationRun); err != nil {
		return report, err
	}
	if inputs.GitOpsStatusDigest, err = digestJSON(snapshots.GitOpsStatus); err != nil {
		return report, err
	}
	if inputs.HAStatusDigest, err = digestJSON(snapshots.HAStatus); err != nil {
		return report, err
	}
	if inputs.AirgapStatusDigest, err = digestJSON(snapshots.AirgapStatus); err != nil {
		return report, err
	}
	if inputs.LifecycleRunsDigest, err = digestJSON(nonNilLifecycle(snapshots.LifecycleRuns)); err != nil {
		return report, err
	}
	if inputs.DisasterRecoveryDigest, err = digestJSON(nonNilDR(snapshots.DisasterRecoveryRuns)); err != nil {
		return report, err
	}
	digest, err := inputs.Digest()
	if err != nil {
		return report, err
	}
	report = Report{
		APIVersion: APIVersion, Kind: Kind,
		Metadata: Metadata{ID: "field-" + strings.TrimPrefix(digest, "sha256:")[:20], State: inputs.RunState, EvidenceDigest: digest, GeneratedAt: generated},
		Product:  Product{Name: "4SO Platform Factory", Version: version}, Snapshots: snapshots,
		Claims: Claims{FieldExecutionObserved: true, LiveExecutionObserved: !snapshots.InstallationRun.Simulation,
			InstallationSucceeded: snapshots.InstallationRun.State == bootstrap.RunSucceeded, Simulation: snapshots.InstallationRun.Simulation,
			RuntimeCertified: false, HACertified: false, ProductionReady: false},
		Evidence: Evidence{SchemaVersion: EvidenceSchema, Algorithm: Algorithm, Canonicalization: Canonicalization, Inputs: inputs, Digest: digest},
	}
	return report, nil
}

func Verify(raw []byte) (Verification, error) {
	var result Verification
	var report Report
	if err := decodeStrict(raw, &report); err != nil {
		return result, fmt.Errorf("decode field evidence report: %w", err)
	}
	if report.APIVersion != APIVersion || report.Kind != Kind {
		return result, errors.New("unsupported field evidence report contract")
	}
	if report.Product.Name != "4SO Platform Factory" || strings.TrimSpace(report.Product.Version) == "" {
		return result, errors.New("field evidence product identity is invalid")
	}
	if (report.Evidence.SchemaVersion != EvidenceSchema && report.Evidence.SchemaVersion != ExactSHAEvidenceSchema && report.Evidence.SchemaVersion != LegacyEvidenceSchema) || report.Evidence.Algorithm != Algorithm || report.Evidence.Canonicalization != Canonicalization {
		return result, errors.New("unsupported field evidence schema")
	}
	switch report.Evidence.SchemaVersion {
	case EvidenceSchema:
		if !digestPattern.MatchString(strings.TrimSpace(report.Evidence.Inputs.ReleaseArtifactDigest)) || report.Evidence.Inputs.ReleaseArtifactDigest != report.Snapshots.BundleAdmission.SourceReleaseDigest {
			return result, errors.New("field evidence is not bound to the exact source release artifact")
		}
		if !digestPattern.MatchString(strings.TrimSpace(report.Evidence.Inputs.InstallerBinaryDigest)) {
			return result, errors.New("field evidence is not bound to the running installer binary")
		}
	case ExactSHAEvidenceSchema:
		if !digestPattern.MatchString(strings.TrimSpace(report.Evidence.Inputs.ReleaseArtifactDigest)) || report.Evidence.Inputs.ReleaseArtifactDigest != report.Snapshots.BundleAdmission.SourceReleaseDigest {
			return result, errors.New("schema v2 field evidence is not bound to the exact source release artifact")
		}
		if strings.TrimSpace(report.Evidence.Inputs.InstallerBinaryDigest) != "" {
			return result, errors.New("schema v2 field evidence must not contain installerBinaryDigest")
		}
	case LegacyEvidenceSchema:
		if strings.TrimSpace(report.Evidence.Inputs.ReleaseArtifactDigest) != "" || strings.TrimSpace(report.Evidence.Inputs.InstallerBinaryDigest) != "" || strings.TrimSpace(report.Snapshots.BundleAdmission.SourceReleaseDigest) != "" {
			return result, errors.New("legacy field evidence must not contain exact-release runtime binding")
		}
	}
	if err := report.Snapshots.Preflight.Verify(); err != nil {
		return result, fmt.Errorf("preflight snapshot: %w", err)
	}
	if !report.Snapshots.BundleAdmission.Verified {
		return result, errors.New("bundle admission snapshot is not verified")
	}
	computedInputs := report.Evidence.Inputs
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"installer version", computedInputs.InstallerVersion, report.Product.Version},
		{"generatedAt", computedInputs.GeneratedAt, report.Metadata.GeneratedAt.UTC().Format(time.RFC3339Nano)},
		{"run id", computedInputs.RunID, report.Snapshots.InstallationRun.ID},
		{"run state", computedInputs.RunState, string(report.Snapshots.InstallationRun.State)},
		{"spec digest", computedInputs.SpecDigest, report.Snapshots.InstallationRun.SpecDigest},
		{"bundle digest", computedInputs.BundleDigest, report.Snapshots.InstallationRun.BundleDigest},
		{"release artifact digest", computedInputs.ReleaseArtifactDigest, report.Snapshots.BundleAdmission.SourceReleaseDigest},
		{"preflight digest", computedInputs.PreflightDigest, report.Snapshots.InstallationRun.PreflightDigest},
	}
	mode := "live"
	if report.Snapshots.InstallationRun.Simulation {
		mode = "simulation"
	}
	checks = append(checks, struct{ name, got, want string }{"execution mode", computedInputs.ExecutionMode, mode})
	for _, check := range checks {
		if check.got != check.want {
			return result, fmt.Errorf("%s does not match snapshot", check.name)
		}
	}
	if report.Snapshots.InstallationRun.BundleDigest != report.Snapshots.BundleAdmission.BundleDigest || report.Snapshots.InstallationRun.PreflightDigest != report.Snapshots.Preflight.Digest || report.Snapshots.InstallationRun.SpecDigest != report.Snapshots.Preflight.RequestDigest {
		return result, errors.New("installation run is not bound to bundle and preflight snapshots")
	}
	if report.Snapshots.InstallationRun.Version != report.Product.Version || report.Snapshots.Preflight.Version != report.Product.Version || report.Snapshots.BundleAdmission.Version != report.Product.Version {
		return result, errors.New("field evidence snapshot versions do not match product version")
	}
	digestChecks := []struct {
		name  string
		value any
		want  string
	}{
		{"bundle admission", report.Snapshots.BundleAdmission, computedInputs.BundleSnapshotDigest},
		{"preflight", report.Snapshots.Preflight, computedInputs.PreflightSnapshotDigest},
		{"installation run", report.Snapshots.InstallationRun, computedInputs.InstallationRunDigest},
		{"GitOps status", report.Snapshots.GitOpsStatus, computedInputs.GitOpsStatusDigest},
		{"HA status", report.Snapshots.HAStatus, computedInputs.HAStatusDigest},
		{"air-gap status", report.Snapshots.AirgapStatus, computedInputs.AirgapStatusDigest},
		{"lifecycle runs", nonNilLifecycle(report.Snapshots.LifecycleRuns), computedInputs.LifecycleRunsDigest},
		{"disaster recovery runs", nonNilDR(report.Snapshots.DisasterRecoveryRuns), computedInputs.DisasterRecoveryDigest},
	}
	for _, check := range digestChecks {
		got, err := digestJSON(check.value)
		if err != nil {
			return result, err
		}
		if got != check.want {
			return result, fmt.Errorf("%s snapshot digest mismatch", check.name)
		}
	}
	digest, err := computedInputs.Digest()
	if err != nil {
		return result, err
	}
	if report.Evidence.Digest != digest || report.Metadata.EvidenceDigest != digest || report.Metadata.ID != "field-"+strings.TrimPrefix(digest, "sha256:")[:20] {
		return result, errors.New("field evidence digest or metadata mismatch")
	}
	if report.Metadata.State != computedInputs.RunState {
		return result, errors.New("metadata state does not match installation run")
	}
	expectedSucceeded := report.Snapshots.InstallationRun.State == bootstrap.RunSucceeded
	expectedLive := !report.Snapshots.InstallationRun.Simulation
	if !report.Claims.FieldExecutionObserved || report.Claims.LiveExecutionObserved != expectedLive || report.Claims.InstallationSucceeded != expectedSucceeded || report.Claims.Simulation != report.Snapshots.InstallationRun.Simulation {
		return result, errors.New("field execution claims do not match snapshots")
	}
	if report.Claims.RuntimeCertified || report.Claims.HACertified || report.Claims.ProductionReady {
		return result, errors.New("field evidence report must not claim certification or production readiness")
	}
	return Verification{Valid: true, ProductVersion: report.Product.Version, ReportID: report.Metadata.ID, RunID: computedInputs.RunID, RunState: computedInputs.RunState,
		ExecutionMode: computedInputs.ExecutionMode, SpecDigest: computedInputs.SpecDigest, BundleDigest: computedInputs.BundleDigest, ReleaseArtifactDigest: computedInputs.ReleaseArtifactDigest, InstallerBinaryDigest: computedInputs.InstallerBinaryDigest,
		PreflightDigest: computedInputs.PreflightDigest, EvidenceDigest: digest, InstallationSucceeded: expectedSucceeded, LiveExecutionObserved: expectedLive}, nil
}

func CurrentExecutableDigest() (string, error) {
	path := "/proc/self/exe"
	file, err := os.Open(path)
	if err != nil {
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
		file, err = os.Open(path)
		if err != nil {
			return "", err
		}
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func digestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}
func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func nonNilLifecycle(value []lifecycle.Run) []lifecycle.Run {
	if value == nil {
		return []lifecycle.Run{}
	}
	return value
}
func nonNilDR(value []disasterrecovery.Run) []disasterrecovery.Run {
	if value == nil {
		return []disasterrecovery.Run{}
	}
	return value
}
func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
