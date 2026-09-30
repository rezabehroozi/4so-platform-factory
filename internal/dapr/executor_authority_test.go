package daprruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executorAuthorityTestEvidence() ExecutorImageEvidence {
	return ExecutorImageEvidence{
		Authority: ExecutorImageEvidenceAuthority,
		ExecutorContextAuthority: ExecutorContextAuthority,
		ExecutorContextDigest: lifecycleTestDigest("1"),
		AcquisitionReceiptDigest: lifecycleTestDigest("2"),
		SourceReleaseDigest: lifecycleTestDigest("3"),
		BuildAuthority: "buildkit",
		BuildctlVersion: "buildctl github.com/moby/buildkit v0.test",
		RegistryAuthority: "zot",
		RegistryScheme: "https",
		RegistryIdentity: "zot.internal.example",
		ImageReference: "zot.internal.example/4so/dapr-runtime@" + lifecycleTestDigest("4"),
		ImageDigest: lifecycleTestDigest("4"),
		RegistryReadback: true,
		CredentialsEmbedded: false,
		RuntimeMutationPerformed: false,
		PhysicalCertificationInferred: false,
	}
}

func TestExecutorAuthorityAcceptsStandaloneEvidenceAndMatchesRuntimeLock(t *testing.T) {
	evidence := executorAuthorityTestEvidence()
	if err := ValidateExecutorImageEvidence(evidence, "https://zot.internal.example"); err != nil {
		t.Fatalf("valid standalone Dapr executor evidence rejected: %v", err)
	}
	lock := daprLifecycleTestLock(t)
	fromLock, err := ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if fromLock.ImageReference != lock.ExecutorImageReference || fromLock.EvidenceDigest != lock.ExecutorEvidenceDigest ||
		fromLock.SourceReleaseDigest != lock.ExecutorSourceReleaseDigest {
		t.Fatalf("runtime lock executor authority drift: %#v", fromLock)
	}
	authority, err := ExecutorAuthorityFromEvidence(evidence, lifecycleTestDigest("9"))
	if err != nil { t.Fatal(err) }
	if err = ValidateExecutorAuthorityForRelease(authority, evidence.SourceReleaseDigest); err != nil {
		t.Fatalf("matching exact release rejected: %v", err)
	}
	if err = ValidateExecutorAuthorityForRelease(authority, lifecycleTestDigest("8")); err == nil ||
		!strings.Contains(err.Error(), "SOURCE_RELEASE_MISMATCH") {
		t.Fatalf("foreign exact release accepted for Dapr executor: %v", err)
	}
}

func TestExecutorAuthorityRejectsRegistryAndImageSubstitution(t *testing.T) {
	evidence := executorAuthorityTestEvidence()
	if err := ValidateExecutorImageEvidence(evidence, "https://foreign.example"); err == nil {
		t.Fatal("foreign registry accepted as Dapr executor authority")
	}
	evidence = executorAuthorityTestEvidence()
	evidence.ImageReference = "zot.internal.example/4so/dapr-runtime@" + lifecycleTestDigest("9")
	if err := ValidateExecutorImageEvidence(evidence, "https://zot.internal.example"); err == nil {
		t.Fatal("executor image substitution accepted without matching evidence digest")
	}
}

func TestLoadExecutorImageEvidenceIsStrictAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	evidence := executorAuthorityTestEvidence()
	raw := []byte(`{
  "authority":"DAPR_EXECUTOR_IMAGE_EVIDENCE_V1",
  "executorContextAuthority":"DAPR_EXECUTOR_CONTEXT_AUTHORITY_V1",
  "executorContextDigest":"` + evidence.ExecutorContextDigest + `",
  "acquisitionReceiptDigest":"` + evidence.AcquisitionReceiptDigest + `",
  "sourceReleaseDigest":"` + evidence.SourceReleaseDigest + `",
  "buildAuthority":"buildkit",
  "buildctlVersion":"buildctl test",
  "registryAuthority":"zot",
  "registryScheme":"https",
  "registryIdentity":"zot.internal.example",
  "imageReference":"` + evidence.ImageReference + `",
  "imageDigest":"` + evidence.ImageDigest + `",
  "registryReadback":true,
  "credentialsEmbedded":false,
  "runtimeMutationPerformed":false,
  "physicalCertificationInferred":false
}`)
	path := filepath.Join(dir, "executor.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil { t.Fatal(err) }
	_, authority, digest, err := LoadExecutorImageEvidence(path)
	if err != nil { t.Fatalf("strict executor evidence load failed: %v", err) }
	if authority.EvidenceDigest != digest || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("executor evidence digest binding drift: authority=%#v digest=%s", authority, digest)
	}
	trailing := filepath.Join(dir, "trailing.json")
	if err = os.WriteFile(trailing, append(raw, []byte("{}")...), 0o600); err != nil { t.Fatal(err) }
	if _, _, _, err = LoadExecutorImageEvidence(trailing); err == nil {
		t.Fatal("executor evidence trailing JSON accepted")
	}
	link := filepath.Join(dir, "executor-link.json")
	if err = os.Symlink(path, link); err != nil { t.Fatal(err) }
	if _, _, _, err = LoadExecutorImageEvidence(link); err == nil {
		t.Fatal("symlink executor evidence accepted")
	}
}
