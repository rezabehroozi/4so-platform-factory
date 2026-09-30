package daprruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/targetmodel"
)

func testDigest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func validRuntimeLock() RuntimeLock {
	plan := targetmodel.DaprRuntimeSourcePlanModel()
	chars := []string{"a", "b", "c", "d"}
	images := make([]targetmodel.DaprRuntimeImageLock, 0, len(plan.RequiredImages))
	for i, image := range plan.RequiredImages {
		digest := testDigest(chars[i])
		images = append(images, targetmodel.DaprRuntimeImageLock{
			Role: image.Role, SourceRepository: image.Repository, SourceDigest: digest,
			MirrorReference: "zot.internal.example/dapr/" + image.Role + "@" + digest,
			MirrorDigest: digest,
		})
	}
	return RuntimeLock{
		Authority: targetmodel.DaprRuntimeSupplyChainAuthority, SourcePlanAuthority: plan.Authority,
		Version: plan.Version, UpstreamRepository: plan.UpstreamRepository, UpstreamRef: plan.UpstreamRef,
		UpstreamCommit: plan.UpstreamCommit, SourceArchiveDigest: testDigest("e"), HelmChartDigest: testDigest("f"),
		HelmPackageDigest: testDigest("0"), HelmRenderDigest: testDigest("1"),
		HelmMirrorReference: "zot.internal.example/dapr-charts/dapr@" + testDigest("4"), HelmMirrorManifestDigest: testDigest("4"),
		AcquisitionReceiptDigest: testDigest("2"), MirrorEvidenceDigest: testDigest("3"),
		ExecutorEvidenceDigest: testDigest("5"), ExecutorSourceReleaseDigest: testDigest("7"), ExecutorImageDigest: testDigest("6"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + testDigest("6"),
		RegistryAuthority: "zot", RegistryScheme: "https", MirrorRegistry: "zot.internal.example",
		ImageLocks: images, ZotMirrorVerified: true, OfflineReplayReady: true, Admitted: true,
	}
}

func TestRuntimeLockDigestIsCanonicalAcrossImageOrdering(t *testing.T) {
	first := validRuntimeLock()
	second := validRuntimeLock()
	for i, j := 0, len(second.ImageLocks)-1; i < j; i, j = i+1, j-1 {
		second.ImageLocks[i], second.ImageLocks[j] = second.ImageLocks[j], second.ImageLocks[i]
	}
	a, err := RuntimeLockDigest(first)
	if err != nil { t.Fatal(err) }
	b, err := RuntimeLockDigest(second)
	if err != nil { t.Fatal(err) }
	if a != b {
		t.Fatalf("Dapr runtime lock digest depends on image ordering: %s != %s", a, b)
	}
}

func TestRuntimeLockRequiresExecutorSourceReleaseDigest(t *testing.T) {
	lock := validRuntimeLock()
	lock.ExecutorSourceReleaseDigest = ""
	if err := ValidateRuntimeLock(lock); err == nil ||
		!strings.Contains(err.Error(), "source-digest-invalid") {
		t.Fatalf("Dapr runtime lock without executor source release binding was admitted: %v", err)
	}
}

func TestRuntimeLockRequiresConfiguredProductZotRegistry(t *testing.T) {
	lock := validRuntimeLock()
	if err := ValidateRuntimeLockForRegistry(lock, "https://zot.internal.example"); err != nil {
		t.Fatalf("matching product zot registry rejected: %v", err)
	}
	if err := ValidateRuntimeLockForRegistry(lock, "http://zot.internal.example"); err == nil || !strings.Contains(err.Error(), "MIRROR_REGISTRY_MISMATCH") {
		t.Fatalf("Dapr registry transport mismatch accepted: %v", err)
	}
	if err := ValidateRuntimeLockForRegistry(lock, "http://platform-zot:5000"); err == nil || !strings.Contains(err.Error(), "MIRROR_REGISTRY_MISMATCH") {
		t.Fatalf("foreign Dapr mirror registry accepted: %v", err)
	}
	lock.RegistryScheme = "http"
	lock.MirrorRegistry = "platform-zot:5000"
	for i := range lock.ImageLocks {
		lock.ImageLocks[i].MirrorReference = "platform-zot:5000/dapr/" + lock.ImageLocks[i].Role + "@" + lock.ImageLocks[i].MirrorDigest
	}
	lock.HelmMirrorReference = "platform-zot:5000/dapr-charts/dapr@" + lock.HelmMirrorManifestDigest
	lock.ExecutorImageReference = "platform-zot:5000/4so/dapr-runtime@" + lock.ExecutorImageDigest
	if err := ValidateRuntimeLockForRegistry(lock, "http://platform-zot:5000"); err != nil {
		t.Fatalf("matching plain-HTTP product zot registry rejected: %v", err)
	}
}

func TestLoadRuntimeLockRejectsUnknownOrSymlinkedAuthority(t *testing.T) {
	withTemp := func(raw []byte, check func(string)) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "lock.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil { t.Fatal(err) }
		check(path)
	}
	lock := validRuntimeLock()
	raw, _ := json.Marshal(lock)
	withTemp(raw, func(path string) {
		got, digest, err := LoadRuntimeLock(path)
		if err != nil { t.Fatal(err) }
		if !got.Admitted || !strings.HasPrefix(digest, "sha256:") { t.Fatalf("loaded lock drift: %#v %s", got, digest) }
	})
	var expanded map[string]any
	if err := json.Unmarshal(raw, &expanded); err != nil { t.Fatal(err) }
	expanded["untrustedClaim"] = true
	bad, _ := json.Marshal(expanded)
	withTemp(bad, func(path string) {
		if _, _, err := LoadRuntimeLock(path); err == nil {
			t.Fatal("unknown Dapr runtime lock field was accepted")
		}
	})
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, raw, 0o600); err != nil { t.Fatal(err) }
	link := filepath.Join(dir, "lock.json")
	if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
	if _, _, err := LoadRuntimeLock(link); err == nil || !strings.Contains(err.Error(), "FILE_INVALID") {
		t.Fatalf("symlinked Dapr runtime lock was accepted: %v", err)
	}
}
