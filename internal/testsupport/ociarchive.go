package testsupport

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"platform.4so.io/factory/internal/ociarchive"
)

type testPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type testDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *testPlatform     `json:"platform,omitempty"`
}

func WriteWorkloadOCIArchive(path string, repositories []string) ([]string, error) {
	blobs := map[string][]byte{}
	refs := make([]string, 0, len(repositories))
	descriptors := make([]testDescriptor, 0, len(repositories))
	for _, repo := range repositories {
		config, _ := json.Marshal(map[string]string{"repository": repo})
		configSum := sha256.Sum256(config)
		configHex := hex.EncodeToString(configSum[:])
		configDigest := "sha256:" + configHex
		blobs[configHex] = config
		manifest := struct {
			SchemaVersion int              `json:"schemaVersion"`
			MediaType     string           `json:"mediaType"`
			Config        testDescriptor   `json:"config"`
			Layers        []testDescriptor `json:"layers"`
		}{2, "application/vnd.oci.image.manifest.v1+json", testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(len(config))}, []testDescriptor{}}
		raw, _ := json.Marshal(manifest)
		sum := sha256.Sum256(raw)
		hexSum := hex.EncodeToString(sum[:])
		digest := "sha256:" + hexSum
		blobs[hexSum] = raw
		ref := repo + "@" + digest
		refs = append(refs, ref)
		descriptors = append(descriptors, testDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: digest, Size: int64(len(raw)), Annotations: map[string]string{"io.containerd.image.name": ref, "org.opencontainers.image.ref.name": ref}, Platform: &testPlatform{Architecture: "amd64", OS: "linux"}})
	}
	sort.Strings(refs)
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Digest < descriptors[j].Digest })
	layout, _ := json.Marshal(map[string]any{"imageLayoutVersion": "1.0.0"})
	index, _ := json.Marshal(struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		Manifests     []testDescriptor  `json:"manifests"`
		Annotations   map[string]string `json:"annotations"`
	}{2, "application/vnd.oci.image.index.v1+json", descriptors, map[string]string{"org.opencontainers.image.created.by": "4so-test-fixture"}})
	inventory, _ := json.Marshal(ociarchive.Inventory{Authority: ociarchive.InventoryAuthority, SchemaVersion: ociarchive.InventorySchemaVersion, ImportAddressabilityAuthority: ociarchive.ImportAddressabilityAuthority, Images: refs})
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(f)
	files := map[string][]byte{"oci-layout": layout, "index.json": index, "4so-image-inventory.json": inventory}
	for digest, raw := range blobs {
		files["blobs/sha256/"+digest] = raw
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := files[name]
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Format: tar.FormatUSTAR}
		if err = tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err = tw.Write(raw); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	if err = tw.Close(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if _, err = ociarchive.Inspect(path); err != nil {
		return nil, fmt.Errorf("generated OCI archive invalid: %w", err)
	}
	return refs, nil
}

func WorkloadRepositories(prefix string, includeOCM bool) []string {
	names := []string{"postgres", "platform-api", "forgejo", "zot", "keycloak", "maintenance", "platform-agent", "platform-probe", "argocd", "cnpg", "storage"}
	if includeOCM {
		names = append(names, "ocm")
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, prefix+n)
	}
	return out
}

func RefsByRepository(refs []string) map[string]string {
	out := map[string]string{}
	for _, ref := range refs {
		for i := 0; i < len(ref); i++ {
			if ref[i] == '@' {
				out[ref[:i]] = ref
				break
			}
		}
	}
	return out
}
