package gitops

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

var managedRevisionPaths = []string{
	".platform/revision.json",
	".platform/revision.sig",
	".platform/public-key.pem",
	"clusters/appliance/platform-managed-state.yaml",
	"clusters/appliance/platform-gitops-revision.yaml",
	"clusters/appliance/kustomization.yaml",
}

type RevisionInput struct {
	ProductVersion string `json:"productVersion"`
	SpecDigest     string `json:"specDigest"`
	BundleDigest   string `json:"bundleDigest"`
	PublicEndpoint string `json:"publicEndpoint"`
	GitEndpoint    string `json:"gitEndpoint"`
	Registry       string `json:"registryEndpoint"`
	Identity       string `json:"identityEndpoint"`
}

type Revision struct {
	ID                   string            `json:"id"`
	Digest               string            `json:"digest"`
	Signature            string            `json:"signature"`
	PublicKeyFingerprint string            `json:"publicKeyFingerprint"`
	Files                map[string][]byte `json:"-"`
}

// ManagedRevisionPaths returns the exact file set owned by a Platform Factory
// signed desired-state revision. Callers must not add or omit paths when
// publishing a managed revision.
func ManagedRevisionPaths() []string {
	return append([]string(nil), managedRevisionPaths...)
}

func renderManagedManifests(input RevisionInput, id, digest, signature, fingerprint string) (string, string, string) {
	stateManifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-managed-state
  namespace: platform-system
  labels:
    platform.4so.io/ownership: gitops
    platform.4so.io/revision: %s
data:
  productVersion: %q
  specDigest: %q
  bundleDigest: %q
  publicEndpoint: %q
  gitEndpoint: %q
  registryEndpoint: %q
  identityEndpoint: %q
`, id, input.ProductVersion, input.SpecDigest, input.BundleDigest, input.PublicEndpoint, input.GitEndpoint, input.Registry, input.Identity)
	revisionManifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-gitops-revision
  namespace: platform-system
  labels:
    platform.4so.io/ownership: gitops
    platform.4so.io/revision: %s
data:
  revisionID: %q
  revisionDigest: %q
  signature: %q
  publicKeyFingerprint: %q
`, id, id, digest, signature, fingerprint)
	kustomization := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - platform-managed-state.yaml
  - platform-gitops-revision.yaml
`
	return stateManifest, revisionManifest, kustomization
}

// ValidateCanonicalManagedFiles proves that the caller supplied exactly the
// product-owned six-file revision bundle and that the rendered GitOps manifests
// are the deterministic representation of the signed revision descriptor.
// Cryptographic signature/public-key verification remains the responsibility
// of the caller that parsed the descriptor.
func ValidateCanonicalManagedFiles(files map[string][]byte, input RevisionInput, id, digest, signature, fingerprint string) error {
	if len(files) != len(managedRevisionPaths) {
		return fmt.Errorf("managed revision must contain exactly %d canonical files", len(managedRevisionPaths))
	}
	allowed := make(map[string]bool, len(managedRevisionPaths))
	for _, filePath := range managedRevisionPaths {
		allowed[filePath] = true
		if _, ok := files[filePath]; !ok {
			return fmt.Errorf("managed revision canonical file %q is missing", filePath)
		}
	}
	for filePath := range files {
		if !allowed[filePath] {
			return fmt.Errorf("managed revision contains non-canonical path %q", filePath)
		}
	}
	if strings.TrimSpace(string(files[".platform/revision.sig"])) != strings.TrimSpace(signature) {
		return fmt.Errorf("managed revision signature file does not match signed descriptor")
	}
	stateManifest, revisionManifest, kustomization := renderManagedManifests(input, id, digest, signature, fingerprint)
	expected := map[string][]byte{
		"clusters/appliance/platform-managed-state.yaml":   []byte(stateManifest),
		"clusters/appliance/platform-gitops-revision.yaml": []byte(revisionManifest),
		"clusters/appliance/kustomization.yaml":            []byte(kustomization),
	}
	for filePath, want := range expected {
		if !bytes.Equal(files[filePath], want) {
			return fmt.Errorf("managed revision file %q is not the canonical rendering of the signed descriptor", filePath)
		}
	}
	return nil
}

func Build(input RevisionInput, privateKey ed25519.PrivateKey) (Revision, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Revision{}, fmt.Errorf("invalid Ed25519 private key")
	}
	input.ProductVersion = strings.TrimSpace(input.ProductVersion)
	input.SpecDigest = strings.TrimSpace(input.SpecDigest)
	input.BundleDigest = strings.TrimSpace(input.BundleDigest)
	if input.ProductVersion == "" || input.SpecDigest == "" || input.BundleDigest == "" {
		return Revision{}, fmt.Errorf("productVersion, specDigest and bundleDigest are required")
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return Revision{}, err
	}
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	signature := ed25519.Sign(privateKey, sum[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicSum := sha256.Sum256(publicKey)
	fingerprint := "sha256:" + hex.EncodeToString(publicSum[:])
	id := "revision-" + hex.EncodeToString(sum[:8])

	payload := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1",
		"kind":       "PlatformRevision",
		"metadata": map[string]any{
			"id": id,
		},
		"spec": input,
		"integrity": map[string]string{
			"digest":               digest,
			"signature":            base64.StdEncoding.EncodeToString(signature),
			"publicKeyFingerprint": fingerprint,
		},
	}
	payloadRaw, _ := json.MarshalIndent(payload, "", "  ")
	payloadRaw = append(payloadRaw, '\n')

	signatureText := base64.StdEncoding.EncodeToString(signature)
	stateManifest, revisionManifest, kustomization := renderManagedManifests(input, id, digest, signatureText, fingerprint)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})

	files := map[string][]byte{
		".platform/revision.json":                          payloadRaw,
		".platform/revision.sig":                           []byte(signatureText + "\n"),
		".platform/public-key.pem":                         publicPEM,
		"clusters/appliance/platform-managed-state.yaml":   []byte(stateManifest),
		"clusters/appliance/platform-gitops-revision.yaml": []byte(revisionManifest),
		"clusters/appliance/kustomization.yaml":            []byte(kustomization),
	}
	return Revision{ID: id, Digest: digest, Signature: signatureText, PublicKeyFingerprint: fingerprint, Files: files}, nil
}

func OrderedPaths(files map[string][]byte) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for index, path := range paths {
		if path == "clusters/appliance/kustomization.yaml" {
			paths = append(append(paths[:index], paths[index+1:]...), path)
			break
		}
	}
	return paths
}
