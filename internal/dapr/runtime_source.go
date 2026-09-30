package daprruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/targetmodel"
)

const RuntimeLockAuthority = targetmodel.DaprRuntimeSupplyChainAuthority

type RuntimeLock = targetmodel.DaprRuntimeSupplyChainLock

func normalize(lock targetmodel.DaprRuntimeSupplyChainLock) targetmodel.DaprRuntimeSupplyChainLock {
	lock.Authority = strings.TrimSpace(lock.Authority)
	lock.SourcePlanAuthority = strings.TrimSpace(lock.SourcePlanAuthority)
	lock.Version = strings.TrimSpace(lock.Version)
	lock.UpstreamRepository = strings.TrimRight(strings.TrimSpace(lock.UpstreamRepository), "/")
	lock.UpstreamRef = strings.TrimSpace(lock.UpstreamRef)
	lock.UpstreamCommit = strings.ToLower(strings.TrimSpace(lock.UpstreamCommit))
	lock.SourceArchiveDigest = strings.ToLower(strings.TrimSpace(lock.SourceArchiveDigest))
	lock.HelmChartDigest = strings.ToLower(strings.TrimSpace(lock.HelmChartDigest))
	lock.HelmPackageDigest = strings.ToLower(strings.TrimSpace(lock.HelmPackageDigest))
	lock.HelmRenderDigest = strings.ToLower(strings.TrimSpace(lock.HelmRenderDigest))
	lock.HelmMirrorReference = strings.TrimSpace(lock.HelmMirrorReference)
	lock.HelmMirrorManifestDigest = strings.ToLower(strings.TrimSpace(lock.HelmMirrorManifestDigest))
	lock.AcquisitionReceiptDigest = strings.ToLower(strings.TrimSpace(lock.AcquisitionReceiptDigest))
	lock.MirrorEvidenceDigest = strings.ToLower(strings.TrimSpace(lock.MirrorEvidenceDigest))
	lock.ExecutorEvidenceDigest = strings.ToLower(strings.TrimSpace(lock.ExecutorEvidenceDigest))
	lock.ExecutorImageReference = strings.TrimSpace(lock.ExecutorImageReference)
	lock.ExecutorImageDigest = strings.ToLower(strings.TrimSpace(lock.ExecutorImageDigest))
	lock.RegistryAuthority = strings.ToLower(strings.TrimSpace(lock.RegistryAuthority))
	lock.RegistryScheme = strings.ToLower(strings.TrimSpace(lock.RegistryScheme))
	lock.MirrorRegistry = strings.ToLower(strings.TrimSpace(lock.MirrorRegistry))
	for i := range lock.ImageLocks {
		image := &lock.ImageLocks[i]
		image.Role = strings.ToLower(strings.TrimSpace(image.Role))
		image.SourceRepository = strings.TrimRight(strings.TrimSpace(image.SourceRepository), "/")
		image.SourceDigest = strings.ToLower(strings.TrimSpace(image.SourceDigest))
		image.MirrorReference = strings.TrimSpace(image.MirrorReference)
		image.MirrorDigest = strings.ToLower(strings.TrimSpace(image.MirrorDigest))
	}
	sort.Slice(lock.ImageLocks, func(i, j int) bool {
		if lock.ImageLocks[i].Role != lock.ImageLocks[j].Role {
			return lock.ImageLocks[i].Role < lock.ImageLocks[j].Role
		}
		return lock.ImageLocks[i].SourceRepository < lock.ImageLocks[j].SourceRepository
	})
	return lock
}

func ValidateRuntimeLock(lock targetmodel.DaprRuntimeSupplyChainLock) error {
	lock = normalize(lock)
	if issues := targetmodel.ValidateDaprRuntimeSupplyChainLock(lock); len(issues) != 0 {
		return fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_LOCK_INVALID %s", strings.Join(issues, ","))
	}
	return nil
}

func expectedRegistryIdentity(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("DAPR_EXPECTED_REGISTRY_REQUIRED")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + strings.TrimRight(value, "/")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("DAPR_EXPECTED_REGISTRY_INVALID")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("DAPR_EXPECTED_REGISTRY_INVALID")
	}
	if path := strings.Trim(parsed.Path, "/"); path != "" {
		return "", "", fmt.Errorf("DAPR_EXPECTED_REGISTRY_INVALID")
	}
	return scheme, strings.ToLower(parsed.Host), nil
}

func ValidateRuntimeLockForRegistry(lock targetmodel.DaprRuntimeSupplyChainLock, expectedRegistry string) error {
	lock = normalize(lock)
	if err := ValidateRuntimeLock(lock); err != nil {
		return err
	}
	scheme, host, err := expectedRegistryIdentity(expectedRegistry)
	if err != nil {
		return err
	}
	if lock.RegistryScheme != scheme || lock.MirrorRegistry != host {
		return fmt.Errorf("DAPR_RUNTIME_MIRROR_REGISTRY_MISMATCH")
	}
	for _, image := range lock.ImageLocks {
		if !strings.HasPrefix(image.MirrorReference, host+"/dapr/") {
			return fmt.Errorf("DAPR_RUNTIME_MIRROR_REGISTRY_MISMATCH")
		}
	}
	return nil
}

func RuntimeLockDigest(lock targetmodel.DaprRuntimeSupplyChainLock) (string, error) {
	lock = normalize(lock)
	if err := ValidateRuntimeLock(lock); err != nil {
		return "", err
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return "", fmt.Errorf("marshal Dapr runtime lock: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func LoadRuntimeLock(path string) (targetmodel.DaprRuntimeSupplyChainLock, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_FILE_REQUIRED")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_FILE_INVALID")
	}
	file, err := os.Open(clean)
	if err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", err
	}
	if !opened.Mode().IsRegular() || opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_FILE_CHANGED")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", err
	}
	if len(raw) == 0 || len(raw) > 1<<20 || int64(len(raw)) != opened.Size() {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_FILE_CHANGED")
	}
	var lock targetmodel.DaprRuntimeSupplyChainLock
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&lock); err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("decode Dapr runtime supply-chain lock: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("DAPR_RUNTIME_SUPPLY_CHAIN_TRAILING_DATA")
		}
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", fmt.Errorf("decode Dapr runtime supply-chain trailing data: %w", err)
	}
	lock = normalize(lock)
	digest, err := RuntimeLockDigest(lock)
	if err != nil {
		return targetmodel.DaprRuntimeSupplyChainLock{}, "", err
	}
	return lock, digest, nil
}
