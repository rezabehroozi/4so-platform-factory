package gitops

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestBuildRevisionIsDeterministicAndSigned(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := RevisionInput{ProductVersion: "0.0.10", SpecDigest: "sha256:spec", BundleDigest: "sha256:bundle", PublicEndpoint: "https://platform.example.test"}
	first, err := Build(input, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(input, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.Signature != second.Signature || first.ID != second.ID {
		t.Fatal("revision generation is not deterministic")
	}
	if len(first.Files) != 6 {
		t.Fatalf("files=%d", len(first.Files))
	}
	paths := OrderedPaths(first.Files)
	if paths[len(paths)-1] != "clusters/appliance/kustomization.yaml" {
		t.Fatalf("last path=%s", paths[len(paths)-1])
	}
}

func TestValidateCanonicalManagedFilesRejectsIncompleteOrTamperedBundle(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := Build(RevisionInput{ProductVersion: "0.0.118", SpecDigest: "sha256:spec", BundleDigest: "sha256:bundle", PublicEndpoint: "https://platform.example.test", GitEndpoint: "https://git.example.test", Registry: "https://registry.example.test", Identity: "https://auth.example.test"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	input := RevisionInput{ProductVersion: "0.0.118", SpecDigest: "sha256:spec", BundleDigest: "sha256:bundle", PublicEndpoint: "https://platform.example.test", GitEndpoint: "https://git.example.test", Registry: "https://registry.example.test", Identity: "https://auth.example.test"}
	if err := ValidateCanonicalManagedFiles(revision.Files, input, revision.ID, revision.Digest, revision.Signature, revision.PublicKeyFingerprint); err != nil {
		t.Fatalf("canonical bundle rejected: %v", err)
	}
	clone := func() map[string][]byte {
		out := make(map[string][]byte, len(revision.Files))
		for name, raw := range revision.Files {
			out[name] = append([]byte(nil), raw...)
		}
		return out
	}
	missing := clone()
	delete(missing, "clusters/appliance/platform-gitops-revision.yaml")
	if err := ValidateCanonicalManagedFiles(missing, input, revision.ID, revision.Digest, revision.Signature, revision.PublicKeyFingerprint); err == nil {
		t.Fatal("missing canonical managed file was accepted")
	}
	tampered := clone()
	tampered["clusters/appliance/platform-managed-state.yaml"] = append(tampered["clusters/appliance/platform-managed-state.yaml"], []byte("# tampered\n")...)
	if err := ValidateCanonicalManagedFiles(tampered, input, revision.ID, revision.Digest, revision.Signature, revision.PublicKeyFingerprint); err == nil {
		t.Fatal("tampered rendered managed file was accepted")
	}
	extra := clone()
	extra["clusters/appliance/unmanaged.yaml"] = []byte("kind: ConfigMap\n")
	if err := ValidateCanonicalManagedFiles(extra, input, revision.ID, revision.Digest, revision.Signature, revision.PublicKeyFingerprint); err == nil {
		t.Fatal("non-canonical extra managed-revision path was accepted")
	}
}
