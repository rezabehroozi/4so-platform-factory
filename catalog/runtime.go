package catalog

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	renderNamespace   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	renderKubeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?$`)
	taggedGitCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	taggedGitCommitShort = regexp.MustCompile(`^[0-9a-f]{7}$`)
)

type SourceEvidence struct {
	Component             string `json:"component"`
	Version               string `json:"version"`
	SourceType            string `json:"sourceType"`
	BundleKey             string `json:"bundleKey"`
	ArtifactDigest        string `json:"artifactDigest"`
	RenderManifestDigest  string `json:"renderManifestDigest,omitempty"`
	SourceLockDigest      string `json:"sourceLockDigest"`
	ImageInventoryDigest  string `json:"imageInventoryDigest"`
	LicenseManifestDigest string `json:"licenseManifestDigest"`
	SBOMDigest            string `json:"sbomDigest"`
	ProvenanceDigest      string `json:"provenanceDigest"`
	Verification          string `json:"verification"`
}

type externalRenderValueEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type externalRenderGenerationEvidence struct {
	Tool                 string                        `json:"tool"`
	ToolVersion          string                        `json:"toolVersion"`
	ReleaseName          string                        `json:"releaseName"`
	Namespace            string                        `json:"namespace"`
	IncludeCRDs          bool                          `json:"includeCRDs"`
	KubernetesVersions   []string                      `json:"kubernetesVersions"`
	KubernetesRenderDigests map[string]string           `json:"kubernetesRenderDigests,omitempty"`
	Values               []externalRenderValueEvidence `json:"values"`
	ImageResolver        string                        `json:"imageResolver"`
	ImageResolverVersion string                        `json:"imageResolverVersion"`
}

func componentRenderKubeVersion(v string) string {
	v = strings.TrimSpace(v)
	if !renderKubeVersion.MatchString(v) {
		return ""
	}
	if strings.Count(v, ".") == 1 {
		return v + ".0"
	}
	return v
}

func verifyExternalHelmGeneration(c Component, g *externalRenderGenerationEvidence) error {
	if g == nil || strings.TrimSpace(g.Tool) != "helm-template" || strings.TrimSpace(g.ToolVersion) == "" || strings.TrimSpace(g.ImageResolver) != "crane-digest" || strings.TrimSpace(g.ImageResolverVersion) == "" {
		return fmt.Errorf("helm-chart source lock is missing exact render/image-resolution generation evidence")
	}
	if strings.TrimSpace(g.ReleaseName) != "platform-factory" {
		return fmt.Errorf("helm-chart source lock render release name mismatch")
	}
	if strings.TrimSpace(g.Namespace) != strings.TrimSpace(c.Spec.Namespace) {
		return fmt.Errorf("helm-chart source lock render namespace mismatch")
	}
	if !g.IncludeCRDs {
		return fmt.Errorf("helm-chart source lock render must include CRDs")
	}
	want := []string{componentRenderKubeVersion(c.Spec.Compatibility.Kubernetes.MinVersion), componentRenderKubeVersion(c.Spec.Compatibility.Kubernetes.MaxVersion)}
	if want[0] == "" || want[1] == "" || len(g.KubernetesVersions) != 2 || g.KubernetesVersions[0] != want[0] || g.KubernetesVersions[1] != want[1] {
		return fmt.Errorf("helm-chart source lock Kubernetes render window mismatch")
	}
	if len(g.KubernetesRenderDigests) > 0 {
		if len(g.KubernetesRenderDigests) != 2 {
			return fmt.Errorf("helm-chart source lock render digest matrix coverage mismatch")
		}
		for _, version := range want {
			if !exactDigest(strings.TrimSpace(g.KubernetesRenderDigests[version])) {
				return fmt.Errorf("helm-chart source lock render digest matrix missing %s", version)
			}
		}
	}
	seen := map[string]bool{}
	for _, value := range g.Values {
		p := strings.TrimSpace(value.Path)
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || seen[p] || !exactDigest(strings.TrimSpace(value.SHA256)) {
			return fmt.Errorf("helm-chart source lock contains invalid values provenance")
		}
		seen[p] = true
	}
	return nil
}

type taggedSourceSetIndex struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Component  string `json:"component"`
	Version    string `json:"version"`
	Upstream   struct {
		Project            string `json:"project"`
		ReleaseURL         string `json:"releaseUrl"`
		Revision           string `json:"revision"`
		ReleaseCommit      string `json:"releaseCommit"`
		ReleaseCommitShort string `json:"releaseCommitShort"`
		Channel            string `json:"channel"`
	} `json:"upstream"`
	Files []struct {
		Path   string `json:"path"`
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Assembly struct {
		NetworkFetchRequired bool   `json:"networkFetchRequired"`
		Method               string `json:"method"`
		Note                 string `json:"note"`
	} `json:"assembly"`
}

func verifyTaggedSourceSetArtifact(c Component) error {
	name, err := bundlePath(c, "artifact.bin")
	if err != nil {
		return err
	}
	raw, err := catalogFiles.ReadFile(name)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("open tagged source-set artifact: %w", err)
	}
	entries := map[string][]byte{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.FileInfo().Mode()&0o120000 != 0 || strings.Contains(f.Name, "\\") || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "../") || path.Clean(f.Name) != f.Name || strings.Contains(f.Name, "/") {
			return fmt.Errorf("unsafe tagged source-set entry %q", f.Name)
		}
		if _, ok := entries[f.Name]; ok {
			return fmt.Errorf("duplicate tagged source-set entry %q", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 32<<20))
		_ = rc.Close()
		if err != nil {
			return err
		}
		entries[f.Name] = b
	}
	idxRaw, ok := entries["source-index.json"]
	if !ok {
		return fmt.Errorf("tagged source-set missing source-index.json")
	}
	var idx taggedSourceSetIndex
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		return fmt.Errorf("decode tagged source index: %w", err)
	}
	if !taggedGitCommitShort.MatchString(idx.Upstream.ReleaseCommitShort) || (idx.Upstream.ReleaseCommit != "" && (!taggedGitCommit.MatchString(idx.Upstream.ReleaseCommit) || !strings.HasPrefix(idx.Upstream.ReleaseCommit, idx.Upstream.ReleaseCommitShort))) {
		return fmt.Errorf("tagged source-set release commit identity mismatch")
	}
	if idx.APIVersion != "platform.4so.io/v1alpha1" || idx.Kind != "UpstreamSourceSet" || idx.Component != c.Metadata.Name || idx.Version != c.Spec.Release || strings.TrimSpace(idx.Upstream.ReleaseURL) == "" || idx.Upstream.Revision != "v"+c.Spec.Release || idx.Assembly.NetworkFetchRequired || idx.Assembly.Method != "deterministic-zip-from-official-tag-files" || len(idx.Files) == 0 {
		return fmt.Errorf("tagged source-set identity/offline contract mismatch")
	}
	seen := map[string]bool{}
	for _, f := range idx.Files {
		if f.Path == "source-index.json" || strings.TrimSpace(f.Path) == "" || strings.TrimSpace(f.URL) == "" || !exactDigest(f.SHA256) {
			return fmt.Errorf("invalid tagged source index entry %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("duplicate tagged source index path %q", f.Path)
		}
		seen[f.Path] = true
		b, ok := entries[f.Path]
		if !ok {
			return fmt.Errorf("tagged source-set missing indexed file %q", f.Path)
		}
		sum := sha256.Sum256(b)
		got := "sha256:" + hex.EncodeToString(sum[:])
		if got != f.SHA256 {
			return fmt.Errorf("tagged source-set digest mismatch for %s", f.Path)
		}
	}
	if len(entries) != len(idx.Files)+1 {
		return fmt.Errorf("tagged source-set contains unindexed payload files")
	}
	return nil
}

type imageInventoryDocument struct {
	SchemaVersion int    `json:"schemaVersion,omitempty"`
	Component     string `json:"component,omitempty"`
	Version       string `json:"version,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Images        []struct {
		Reference string `json:"reference"`
	} `json:"images"`
}

func collectImageReferences(v any, out map[string]bool) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			collectImageReferences(item, out)
		}
	case map[string]any:
		for key, value := range x {
			if key == "image" {
				if ref, ok := value.(string); ok && strings.TrimSpace(ref) != "" {
					out[strings.TrimSpace(ref)] = true
				}
			}
			collectImageReferences(value, out)
		}
	}
}

func ImageReferences(c Component) ([]string, error) {
	if !c.Spec.Source.Resolved {
		return nil, fmt.Errorf("component %s source is unresolved", c.Metadata.Name)
	}
	name, err := bundlePath(c, "image-inventory.json")
	if err != nil {
		return nil, err
	}
	raw, err := catalogFiles.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var doc imageInventoryDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode image inventory: %w", err)
	}
	seen := map[string]bool{}
	refs := make([]string, 0, len(doc.Images))
	for _, image := range doc.Images {
		ref := strings.TrimSpace(image.Reference)
		if ref == "" || !strings.Contains(ref, "@sha256:") {
			return nil, fmt.Errorf("image inventory reference must be digest-pinned: %q", ref)
		}
		parts := strings.Split(ref, "@")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || !exactDigest(parts[1]) {
			return nil, fmt.Errorf("image inventory reference is invalid: %q", ref)
		}
		if seen[ref] {
			return nil, fmt.Errorf("duplicate image inventory reference %q", ref)
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}

func ReleaseImageReferences(components map[string]Component) ([]string, error) {
	seen := map[string]bool{}
	for _, c := range components {
		if !c.Spec.Source.Resolved {
			continue
		}
		refs, err := ImageReferences(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Metadata.Name, err)
		}
		for _, ref := range refs {
			seen[ref] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out, nil
}

func verifyManifestImageInventory(c Component, manifestFile string) error {
	manifestName, err := bundlePath(c, manifestFile)
	if err != nil {
		return err
	}
	raw, err := catalogFiles.ReadFile(manifestName)
	if err != nil {
		return err
	}
	if strings.Contains(string(raw), "example.invalid") {
		return fmt.Errorf("embedded manifest contains reserved example.invalid endpoint")
	}
	var resources []any
	if err = json.Unmarshal(raw, &resources); err != nil {
		return fmt.Errorf("decode render manifest: %w", err)
	}
	if len(resources) == 0 {
		return fmt.Errorf("render manifest has no resources")
	}
	manifestImages := map[string]bool{}
	collectImageReferences(resources, manifestImages)
	inventory, err := ImageReferences(c)
	if err != nil {
		return err
	}
	inventorySet := map[string]bool{}
	for _, ref := range inventory {
		inventorySet[ref] = true
	}
	for ref := range manifestImages {
		if !inventorySet[ref] {
			return fmt.Errorf("render manifest image %s is missing from image inventory", ref)
		}
	}
	for ref := range inventorySet {
		if !manifestImages[ref] {
			return fmt.Errorf("image inventory reference %s is not used by render manifest", ref)
		}
	}
	return nil
}

type RenderedComponent struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	RenderedDigest string           `json:"renderedDigest"`
	Resources      []map[string]any `json:"resources"`
	SourceEvidence SourceEvidence   `json:"sourceEvidence"`
}

func bundlePath(c Component, file string) (string, error) {
	key := strings.TrimSpace(c.Spec.Source.BundleKey)
	if key == "" {
		return "", fmt.Errorf("bundleKey is required for embedded-native source")
	}
	clean := path.Clean(key)
	if clean != key || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean == "." {
		return "", fmt.Errorf("bundleKey is not a safe relative path")
	}
	return "runtime/" + clean + "/" + file, nil
}

func embeddedDigest(c Component, file string) (string, error) {
	name, err := bundlePath(c, file)
	if err != nil {
		return "", err
	}
	raw, err := catalogFiles.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func requireDigestMatch(c Component, file, wanted string) error {
	if !exactDigest(wanted) {
		return fmt.Errorf("%s contract digest is not exact sha256", file)
	}
	got, err := embeddedDigest(c, file)
	if err != nil {
		return err
	}
	if got != wanted {
		return fmt.Errorf("%s digest mismatch: contract=%s embedded=%s", file, wanted, got)
	}
	return nil
}

func verifyResolvedComponent(c Component) error {
	if !c.Spec.Source.Resolved {
		return nil
	}
	if !exactReleaseLabel(c.Spec.Release) {
		return fmt.Errorf("resolved component release must be exact")
	}
	if c.Spec.Source.Type != "embedded-native" {
		// Resolved external sources must be mirrored into the release bundle with
		// immutable source material. A resolved=true flag plus arbitrary digests is
		// never sufficient to cross RENDER/RUNTIME admission.
		if strings.TrimSpace(c.Spec.Source.BundleKey) == "" {
			return fmt.Errorf("resolved external source requires an embedded air-gap bundleKey")
		}
		if !strings.EqualFold(strings.TrimSpace(c.Spec.Source.SignatureVerification), "sha256-pinned-offline") {
			return fmt.Errorf("resolved external source requires sha256-pinned-offline artifact verification")
		}
		checks := []struct{ file, digest string }{
			{"artifact.bin", c.Spec.Source.ArtifactDigest},
			{"render-manifest.json", c.Spec.Source.RenderManifestDigest},
			{"source-lock.json", c.Spec.Source.SourceLockDigest},
			{"image-inventory.json", c.Spec.Source.ImageInventoryDigest},
			{"licenses.json", c.Spec.Source.LicenseManifestDigest},
			{"sbom.spdx.json", c.Spec.Source.SBOM},
			{"provenance.json", c.Spec.Source.Provenance},
		}
		for _, check := range checks {
			if err := requireDigestMatch(c, check.file, check.digest); err != nil {
				return err
			}
		}
		if c.Spec.Source.Type == "external-tagged-source-set" {
			if err := verifyTaggedSourceSetArtifact(c); err != nil {
				return err
			}
		}
		lockName, _ := bundlePath(c, "source-lock.json")
		lockRaw, err := catalogFiles.ReadFile(lockName)
		if err != nil {
			return err
		}
		var lock struct {
			Component              string                            `json:"component"`
			Version                string                            `json:"version"`
			SourceType             string                            `json:"sourceType"`
			UpstreamURL            string                            `json:"upstreamUrl"`
			UpstreamRevision       string                            `json:"upstreamRevision"`
			UpstreamArtifact       string                            `json:"upstreamArtifact"`
			UpstreamArtifactDigest string                            `json:"upstreamArtifactDigest"`
			Renderer               string                            `json:"renderer"`
			UpstreamVerification   string                            `json:"upstreamVerification"`
			NetworkFetchRequired   bool                              `json:"networkFetchRequired"`
			Generation             *externalRenderGenerationEvidence `json:"generation,omitempty"`
		}
		if err := json.Unmarshal(lockRaw, &lock); err != nil {
			return fmt.Errorf("decode external source lock: %w", err)
		}
		if lock.Component != c.Metadata.Name || lock.Version != c.Spec.Release || lock.SourceType != c.Spec.Source.Type || strings.TrimSpace(lock.UpstreamURL) == "" || strings.TrimSpace(lock.UpstreamRevision) == "" || strings.TrimSpace(lock.UpstreamArtifact) == "" || lock.UpstreamArtifactDigest != c.Spec.Source.ArtifactDigest || lock.Renderer != "json-resource-list-v1" || lock.UpstreamVerification != "sha256-pinned-offline" || lock.NetworkFetchRequired {
			return fmt.Errorf("external source lock identity, renderer, upstream evidence or offline contract mismatch")
		}
		if c.Spec.Source.Type == "helm-chart" {
			if err := verifyExternalHelmGeneration(c, lock.Generation); err != nil {
				return err
			}
		} else if lock.Generation != nil {
			return fmt.Errorf("non-Helm external source lock must not contain Helm generation evidence")
		}
		if err := verifyManifestImageInventory(c, "render-manifest.json"); err != nil {
			return err
		}
		return nil
	}
	if c.Spec.Delivery.Type != "native-manifest" {
		return fmt.Errorf("embedded-native source requires native-manifest delivery")
	}
	if !strings.EqualFold(strings.TrimSpace(c.Spec.Source.SignatureVerification), "sha256-pinned-offline") {
		return fmt.Errorf("embedded-native verification must be sha256-pinned-offline")
	}
	checks := []struct{ file, digest string }{
		{"manifest.json", c.Spec.Source.ArtifactDigest},
		{"source-lock.json", c.Spec.Source.SourceLockDigest},
		{"image-inventory.json", c.Spec.Source.ImageInventoryDigest},
		{"licenses.json", c.Spec.Source.LicenseManifestDigest},
		{"sbom.spdx.json", c.Spec.Source.SBOM},
		{"provenance.json", c.Spec.Source.Provenance},
	}
	for _, check := range checks {
		if err := requireDigestMatch(c, check.file, check.digest); err != nil {
			return err
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.Spec.Certification.Status), "render-certified") {
		if err := requireDigestMatch(c, "render-evidence.json", c.Spec.Certification.EvidenceDigest); err != nil {
			return err
		}
	}
	lockName, _ := bundlePath(c, "source-lock.json")
	lockRaw, err := catalogFiles.ReadFile(lockName)
	if err != nil {
		return err
	}
	var lock struct {
		Component            string `json:"component"`
		Version              string `json:"version"`
		SourceType           string `json:"sourceType"`
		Renderer             string `json:"renderer"`
		NetworkFetchRequired bool   `json:"networkFetchRequired"`
	}
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		return fmt.Errorf("decode source lock: %w", err)
	}
	if lock.Component != c.Metadata.Name || lock.Version != c.Spec.Release || lock.SourceType != "embedded-native" || lock.Renderer != "json-template-v1" || lock.NetworkFetchRequired {
		return fmt.Errorf("source lock identity or renderer contract mismatch")
	}
	manifestFile := "manifest.json"
	if c.Spec.Source.Type != "embedded-native" {
		manifestFile = "render-manifest.json"
	}
	manifestName, _ := bundlePath(c, manifestFile)
	manifestRaw, err := catalogFiles.ReadFile(manifestName)
	if err != nil {
		return err
	}
	if strings.Contains(string(manifestRaw), "example.invalid") {
		return fmt.Errorf("embedded manifest contains reserved example.invalid endpoint")
	}
	var resources []map[string]any
	if err := json.Unmarshal(manifestRaw, &resources); err != nil {
		return fmt.Errorf("decode embedded manifest: %w", err)
	}
	if len(resources) == 0 {
		return fmt.Errorf("embedded manifest has no resources")
	}
	if err := verifyManifestImageInventory(c, manifestFile); err != nil {
		return err
	}
	return nil
}

func sourceEvidence(c Component) SourceEvidence {
	return SourceEvidence{
		Component: c.Metadata.Name, Version: c.Spec.Release, SourceType: c.Spec.Source.Type,
		BundleKey: c.Spec.Source.BundleKey, ArtifactDigest: c.Spec.Source.ArtifactDigest, RenderManifestDigest: c.Spec.Source.RenderManifestDigest,
		SourceLockDigest: c.Spec.Source.SourceLockDigest, ImageInventoryDigest: c.Spec.Source.ImageInventoryDigest,
		LicenseManifestDigest: c.Spec.Source.LicenseManifestDigest, SBOMDigest: c.Spec.Source.SBOM,
		ProvenanceDigest: c.Spec.Source.Provenance, Verification: c.Spec.Source.SignatureVerification,
	}
}

func renderValue(v any, vars map[string]string) any {
	switch x := v.(type) {
	case string:
		out := x
		for key, value := range vars {
			out = strings.ReplaceAll(out, "${"+key+"}", value)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = renderValue(x[i], vars)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			out[k] = renderValue(value, vars)
		}
		return out
	default:
		return v
	}
}

func unresolvedToken(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, "${")
	case []any:
		for _, value := range x {
			if unresolvedToken(value) {
				return true
			}
		}
	case map[string]any:
		for _, value := range x {
			if unresolvedToken(value) {
				return true
			}
		}
	}
	return false
}

func resourceIdentity(resource map[string]any) string {
	apiVersion, _ := resource["apiVersion"].(string)
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	return apiVersion + "|" + kind + "|" + namespace + "|" + name
}

func RenderComponent(c Component, namespace, catalogReleaseID string) (RenderedComponent, error) {
	if err := verifyResolvedComponent(c); err != nil {
		return RenderedComponent{}, err
	}
	if c.Spec.Source.Type == "embedded-native" && c.Spec.Delivery.Type != "native-manifest" {
		return RenderedComponent{}, fmt.Errorf("component %s embedded source requires native-manifest delivery", c.Metadata.Name)
	}
	if c.Spec.Source.Type != "embedded-native" && c.Spec.Source.RenderManifestDigest == "" {
		return RenderedComponent{}, fmt.Errorf("component %s external source is missing render manifest evidence", c.Metadata.Name)
	}
	namespace = strings.TrimSpace(namespace)
	if !renderNamespace.MatchString(namespace) || len(namespace) > 63 {
		return RenderedComponent{}, fmt.Errorf("namespace must be a DNS label no longer than 63 characters")
	}
	catalogReleaseID = strings.TrimSpace(catalogReleaseID)
	if catalogReleaseID == "" {
		return RenderedComponent{}, fmt.Errorf("catalogReleaseId is required")
	}
	manifestFile := "manifest.json"
	if c.Spec.Source.Type != "embedded-native" {
		manifestFile = "render-manifest.json"
	}
	manifestName, _ := bundlePath(c, manifestFile)
	raw, err := catalogFiles.ReadFile(manifestName)
	if err != nil {
		return RenderedComponent{}, err
	}
	var generic []any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return RenderedComponent{}, err
	}
	renderedAny := renderValue(generic, map[string]string{"namespace": namespace, "catalogReleaseId": catalogReleaseID})
	if unresolvedToken(renderedAny) {
		return RenderedComponent{}, fmt.Errorf("render left unresolved template tokens")
	}
	renderedSlice, ok := renderedAny.([]any)
	if !ok {
		return RenderedComponent{}, fmt.Errorf("rendered manifest is not a resource list")
	}
	resources := make([]map[string]any, 0, len(renderedSlice))
	seen := map[string]bool{}
	for _, item := range renderedSlice {
		resource, ok := item.(map[string]any)
		if !ok {
			return RenderedComponent{}, fmt.Errorf("rendered resource is not an object")
		}
		identity := resourceIdentity(resource)
		if strings.HasPrefix(identity, "|||") || strings.HasSuffix(identity, "|") {
			return RenderedComponent{}, fmt.Errorf("rendered resource missing apiVersion/kind/name")
		}
		if seen[identity] {
			return RenderedComponent{}, fmt.Errorf("duplicate rendered resource %s", identity)
		}
		seen[identity] = true
		resources = append(resources, resource)
	}
	// Preserve manifest order for application while hashing canonical JSON of that order.
	canonical, err := json.Marshal(resources)
	if err != nil {
		return RenderedComponent{}, err
	}
	sum := sha256.Sum256(canonical)
	return RenderedComponent{
		Name: c.Metadata.Name, Version: c.Spec.Release,
		RenderedDigest: "sha256:" + hex.EncodeToString(sum[:]), Resources: resources,
		SourceEvidence: sourceEvidence(c),
	}, nil
}

func ResolvedRenderable(components map[string]Component) []Component {
	out := []Component{}
	for _, c := range components {
		if c.Spec.Source.Resolved && verifyResolvedComponent(c) == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.Name < out[j].Metadata.Name })
	return out
}
