package daprruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ExecutorImageEvidenceAuthority = "DAPR_EXECUTOR_IMAGE_EVIDENCE_V1"
	ExecutorContextAuthority       = "DAPR_EXECUTOR_CONTEXT_AUTHORITY_V1"
)

type ExecutorImageEvidence struct {
	Authority                     string `json:"authority"`
	ExecutorContextAuthority      string `json:"executorContextAuthority"`
	ExecutorContextDigest         string `json:"executorContextDigest"`
	AcquisitionReceiptDigest      string `json:"acquisitionReceiptDigest"`
	SourceReleaseDigest           string `json:"sourceReleaseDigest"`
	BuildAuthority                string `json:"buildAuthority"`
	BuildctlVersion               string `json:"buildctlVersion"`
	RegistryAuthority             string `json:"registryAuthority"`
	RegistryScheme                string `json:"registryScheme"`
	RegistryIdentity              string `json:"registryIdentity"`
	ImageReference                string `json:"imageReference"`
	ImageDigest                   string `json:"imageDigest"`
	RegistryReadback              bool   `json:"registryReadback"`
	CredentialsEmbedded           bool   `json:"credentialsEmbedded"`
	RuntimeMutationPerformed      bool   `json:"runtimeMutationPerformed"`
	PhysicalCertificationInferred bool   `json:"physicalCertificationInferred"`
}

type ExecutorAuthority struct {
	Authority           string `json:"authority"`
	EvidenceDigest      string `json:"evidenceDigest"`
	SourceReleaseDigest string `json:"sourceReleaseDigest"`
	ImageReference      string `json:"imageReference"`
	ImageDigest       string `json:"imageDigest"`
	RegistryAuthority string `json:"registryAuthority"`
	RegistryScheme    string `json:"registryScheme"`
	RegistryIdentity  string `json:"registryIdentity"`
}

func normalizeExecutorEvidence(value ExecutorImageEvidence) ExecutorImageEvidence {
	value.Authority = strings.TrimSpace(value.Authority)
	value.ExecutorContextAuthority = strings.TrimSpace(value.ExecutorContextAuthority)
	value.ExecutorContextDigest = strings.ToLower(strings.TrimSpace(value.ExecutorContextDigest))
	value.AcquisitionReceiptDigest = strings.ToLower(strings.TrimSpace(value.AcquisitionReceiptDigest))
	value.SourceReleaseDigest = strings.ToLower(strings.TrimSpace(value.SourceReleaseDigest))
	value.BuildAuthority = strings.ToLower(strings.TrimSpace(value.BuildAuthority))
	value.BuildctlVersion = strings.TrimSpace(value.BuildctlVersion)
	value.RegistryAuthority = strings.ToLower(strings.TrimSpace(value.RegistryAuthority))
	value.RegistryScheme = strings.ToLower(strings.TrimSpace(value.RegistryScheme))
	value.RegistryIdentity = strings.ToLower(strings.TrimSpace(value.RegistryIdentity))
	value.ImageReference = strings.TrimSpace(value.ImageReference)
	value.ImageDigest = strings.ToLower(strings.TrimSpace(value.ImageDigest))
	return value
}

func ValidateExecutorImageEvidence(value ExecutorImageEvidence, expectedRegistry string) error {
	value = normalizeExecutorEvidence(value)
	if value.Authority != ExecutorImageEvidenceAuthority || value.ExecutorContextAuthority != ExecutorContextAuthority {
		return fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_AUTHORITY_INVALID")
	}
	for _, digest := range []string{value.ExecutorContextDigest, value.AcquisitionReceiptDigest, value.SourceReleaseDigest, value.ImageDigest} {
		if !lifecycleDigest(digest) {
			return fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_DIGEST_INVALID")
		}
	}
	if value.BuildAuthority != "buildkit" || value.BuildctlVersion == "" || len(value.BuildctlVersion) > 256 {
		return fmt.Errorf("DAPR_EXECUTOR_BUILD_AUTHORITY_INVALID")
	}
	if value.RegistryAuthority != "zot" {
		return fmt.Errorf("DAPR_EXECUTOR_REGISTRY_AUTHORITY_INVALID")
	}
	scheme, host, err := expectedRegistryIdentity(value.RegistryScheme + "://" + value.RegistryIdentity)
	if err != nil || scheme != value.RegistryScheme || host != value.RegistryIdentity {
		return fmt.Errorf("DAPR_EXECUTOR_REGISTRY_IDENTITY_INVALID")
	}
	if strings.TrimSpace(expectedRegistry) != "" {
		expectedScheme, expectedHost, expectedErr := expectedRegistryIdentity(expectedRegistry)
		if expectedErr != nil {
			return expectedErr
		}
		if expectedScheme != value.RegistryScheme || expectedHost != value.RegistryIdentity {
			return fmt.Errorf("DAPR_EXECUTOR_REGISTRY_MISMATCH")
		}
	}
	expectedRef := value.RegistryIdentity + "/4so/dapr-runtime@" + value.ImageDigest
	if !digestPinnedImage(value.ImageReference) || value.ImageReference != expectedRef {
		return fmt.Errorf("DAPR_EXECUTOR_IMAGE_REFERENCE_INVALID")
	}
	if !value.RegistryReadback || value.CredentialsEmbedded || value.RuntimeMutationPerformed || value.PhysicalCertificationInferred {
		return fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_BOUNDARY_INVALID")
	}
	return nil
}

func ValidateExecutorAuthority(value ExecutorAuthority) error {
	value.Authority = strings.TrimSpace(value.Authority)
	value.EvidenceDigest = strings.ToLower(strings.TrimSpace(value.EvidenceDigest))
	value.SourceReleaseDigest = strings.ToLower(strings.TrimSpace(value.SourceReleaseDigest))
	value.ImageReference = strings.TrimSpace(value.ImageReference)
	value.ImageDigest = strings.ToLower(strings.TrimSpace(value.ImageDigest))
	value.RegistryAuthority = strings.ToLower(strings.TrimSpace(value.RegistryAuthority))
	value.RegistryScheme = strings.ToLower(strings.TrimSpace(value.RegistryScheme))
	value.RegistryIdentity = strings.ToLower(strings.TrimSpace(value.RegistryIdentity))
	if value.Authority != ExecutorImageEvidenceAuthority || !lifecycleDigest(value.EvidenceDigest) ||
		!lifecycleDigest(value.SourceReleaseDigest) || !lifecycleDigest(value.ImageDigest) || value.RegistryAuthority != "zot" {
		return fmt.Errorf("DAPR_EXECUTOR_AUTHORITY_INVALID")
	}
	scheme, host, err := expectedRegistryIdentity(value.RegistryScheme + "://" + value.RegistryIdentity)
	if err != nil || scheme != value.RegistryScheme || host != value.RegistryIdentity {
		return fmt.Errorf("DAPR_EXECUTOR_AUTHORITY_REGISTRY_INVALID")
	}
	if value.ImageReference != value.RegistryIdentity+"/4so/dapr-runtime@"+value.ImageDigest || !digestPinnedImage(value.ImageReference) {
		return fmt.Errorf("DAPR_EXECUTOR_AUTHORITY_IMAGE_INVALID")
	}
	return nil
}

func ValidateExecutorAuthorityForRegistry(value ExecutorAuthority, expectedRegistry string) error {
	if err := ValidateExecutorAuthority(value); err != nil {
		return err
	}
	expectedScheme, expectedHost, err := expectedRegistryIdentity(expectedRegistry)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(value.RegistryScheme), expectedScheme) ||
		!strings.EqualFold(strings.TrimSpace(value.RegistryIdentity), expectedHost) {
		return fmt.Errorf("DAPR_EXECUTOR_AUTHORITY_REGISTRY_MISMATCH")
	}
	return nil
}

func ValidateExecutorAuthorityForRelease(value ExecutorAuthority, expectedSourceReleaseDigest string) error {
	if err := ValidateExecutorAuthority(value); err != nil {
		return err
	}
	expectedSourceReleaseDigest = strings.ToLower(strings.TrimSpace(expectedSourceReleaseDigest))
	if !lifecycleDigest(expectedSourceReleaseDigest) {
		return fmt.Errorf("DAPR_EXECUTOR_SOURCE_RELEASE_AUTHORITY_REQUIRED")
	}
	if !strings.EqualFold(strings.TrimSpace(value.SourceReleaseDigest), expectedSourceReleaseDigest) {
		return fmt.Errorf("DAPR_EXECUTOR_SOURCE_RELEASE_MISMATCH")
	}
	return nil
}

func ExecutorAuthorityFromEvidence(value ExecutorImageEvidence, evidenceDigest string) (ExecutorAuthority, error) {
	value = normalizeExecutorEvidence(value)
	evidenceDigest = strings.ToLower(strings.TrimSpace(evidenceDigest))
	if err := ValidateExecutorImageEvidence(value, ""); err != nil {
		return ExecutorAuthority{}, err
	}
	if !lifecycleDigest(evidenceDigest) {
		return ExecutorAuthority{}, fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_FILE_DIGEST_INVALID")
	}
	out := ExecutorAuthority{
		Authority: ExecutorImageEvidenceAuthority,
		EvidenceDigest: evidenceDigest,
		SourceReleaseDigest: value.SourceReleaseDigest,
		ImageReference: value.ImageReference,
		ImageDigest: value.ImageDigest,
		RegistryAuthority: value.RegistryAuthority,
		RegistryScheme: value.RegistryScheme,
		RegistryIdentity: value.RegistryIdentity,
	}
	if err := ValidateExecutorAuthority(out); err != nil {
		return ExecutorAuthority{}, err
	}
	return out, nil
}

func ExecutorAuthorityFromRuntimeLock(lock RuntimeLock) (ExecutorAuthority, error) {
	lock = normalize(lock)
	if err := ValidateRuntimeLock(lock); err != nil {
		return ExecutorAuthority{}, err
	}
	out := ExecutorAuthority{
		Authority: ExecutorImageEvidenceAuthority,
		EvidenceDigest: lock.ExecutorEvidenceDigest,
		SourceReleaseDigest: lock.ExecutorSourceReleaseDigest,
		ImageReference: lock.ExecutorImageReference,
		ImageDigest: lock.ExecutorImageDigest,
		RegistryAuthority: lock.RegistryAuthority,
		RegistryScheme: lock.RegistryScheme,
		RegistryIdentity: lock.MirrorRegistry,
	}
	if err := ValidateExecutorAuthority(out); err != nil {
		return ExecutorAuthority{}, err
	}
	return out, nil
}

func ExecutorAuthoritiesEqual(a, b ExecutorAuthority) bool {
	return strings.TrimSpace(a.Authority) == strings.TrimSpace(b.Authority) &&
		strings.EqualFold(strings.TrimSpace(a.EvidenceDigest), strings.TrimSpace(b.EvidenceDigest)) &&
		strings.EqualFold(strings.TrimSpace(a.SourceReleaseDigest), strings.TrimSpace(b.SourceReleaseDigest)) &&
		strings.TrimSpace(a.ImageReference) == strings.TrimSpace(b.ImageReference) &&
		strings.EqualFold(strings.TrimSpace(a.ImageDigest), strings.TrimSpace(b.ImageDigest)) &&
		strings.EqualFold(strings.TrimSpace(a.RegistryAuthority), strings.TrimSpace(b.RegistryAuthority)) &&
		strings.EqualFold(strings.TrimSpace(a.RegistryScheme), strings.TrimSpace(b.RegistryScheme)) &&
		strings.EqualFold(strings.TrimSpace(a.RegistryIdentity), strings.TrimSpace(b.RegistryIdentity))
}

func LoadExecutorImageEvidence(path string) (ExecutorImageEvidence, ExecutorAuthority, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_FILE_REQUIRED")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_FILE_INVALID")
	}
	file, err := os.Open(clean)
	if err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	if !opened.Mode().IsRegular() || opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_FILE_CHANGED")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	if len(raw) == 0 || len(raw) > 1<<20 || int64(len(raw)) != opened.Size() {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_FILE_CHANGED")
	}
	var value ExecutorImageEvidence
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("decode Dapr executor evidence: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", fmt.Errorf("DAPR_EXECUTOR_EVIDENCE_TRAILING_DATA")
	}
	value = normalizeExecutorEvidence(value)
	if err = ValidateExecutorImageEvidence(value, ""); err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	authority, err := ExecutorAuthorityFromEvidence(value, digest)
	if err != nil {
		return ExecutorImageEvidence{}, ExecutorAuthority{}, "", err
	}
	return value, authority, digest, nil
}
