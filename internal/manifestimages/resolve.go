package manifestimages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const ResolutionAuthority = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1"

const maxManifestBytes = 16 * 1024 * 1024

var (
	directImagePattern   = regexp.MustCompile(`(?m)^([ \t]*image:[ \t]*["']?)([^"'\s#]+)`)
	imageArgEqualPattern = regexp.MustCompile(`(?m)^([ \t]*-[ \t]*["']?--[A-Za-z0-9-]*image=)([^"'\s#]+)`)
	imageArgPairPattern  = regexp.MustCompile(`(?m)^([ \t]*-[ \t]*["']?--[A-Za-z0-9-]*image["']?[ \t]*\r?\n[ \t]*-[ \t]*["']?)([^"'\s#]+)`)
	exactDigestPattern   = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-f]{64}$`)
)

type Resolution struct {
	Source string `json:"source"`
	Exact  string `json:"exact"`
}

type Result struct {
	Authority              string       `json:"authority"`
	SchemaVersion          int          `json:"schemaVersion"`
	SourceManifestSHA256   string       `json:"sourceManifestSha256"`
	SourceManifestBytes    int          `json:"sourceManifestBytes"`
	ResolvedManifestSHA256 string       `json:"resolvedManifestSha256"`
	ResolvedManifestBytes  int          `json:"resolvedManifestBytes"`
	Images                 []Resolution `json:"images"`
}

type span struct {
	start int
	end   int
	ref   string
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalRepository(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") {
		return "", fmt.Errorf("image reference %q is not canonical", ref)
	}
	if at := strings.LastIndex(ref, "@sha256:"); at >= 0 {
		if !exactDigestPattern.MatchString(ref) {
			return "", fmt.Errorf("image reference %q has an invalid digest", ref)
		}
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if slash <= 0 || slash == len(ref)-1 {
		return "", fmt.Errorf("image reference %q must include an explicit registry and repository", ref)
	}
	host := ref[:strings.Index(ref, "/")]
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") && host != "localhost" {
		return "", fmt.Errorf("image reference %q must use an explicit registry host", ref)
	}
	name := ref[slash+1:]
	if colon := strings.LastIndex(name, ":"); colon >= 0 {
		ref = ref[:slash+1] + name[:colon]
	}
	if strings.HasSuffix(ref, "/") || strings.Contains(ref, "@") {
		return "", fmt.Errorf("image reference %q has an invalid repository", ref)
	}
	return ref, nil
}

func collectPatternSpans(raw []byte, pattern *regexp.Regexp, spans *[]span) {
	for _, match := range pattern.FindAllSubmatchIndex(raw, -1) {
		if len(match) < 6 || match[4] < 0 || match[5] <= match[4] {
			continue
		}
		*spans = append(*spans, span{start: match[4], end: match[5], ref: string(raw[match[4]:match[5]])})
	}
}

func scan(raw []byte) ([]span, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return nil, fmt.Errorf("manifest must be 1-%d bytes", maxManifestBytes)
	}
	if strings.IndexByte(string(raw), 0) >= 0 {
		return nil, fmt.Errorf("manifest contains NUL bytes")
	}
	spans := []span{}
	collectPatternSpans(raw, directImagePattern, &spans)
	collectPatternSpans(raw, imageArgEqualPattern, &spans)
	collectPatternSpans(raw, imageArgPairPattern, &spans)
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	clean := make([]span, 0, len(spans))
	for _, current := range spans {
		if _, err := canonicalRepository(current.ref); err != nil {
			return nil, fmt.Errorf("manifest image %q: %w", current.ref, err)
		}
		if len(clean) > 0 {
			previous := clean[len(clean)-1]
			if current.start < previous.end {
				if current.start == previous.start && current.end == previous.end && current.ref == previous.ref {
					continue
				}
				return nil, fmt.Errorf("manifest image token spans overlap")
			}
		}
		clean = append(clean, current)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("manifest contains no runtime image references")
	}
	return clean, nil
}

func Extract(raw []byte) ([]string, error) {
	spans, err := scan(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	refs := []string{}
	for _, s := range spans {
		if !seen[s.ref] {
			seen[s.ref] = true
			refs = append(refs, s.ref)
		}
	}
	sort.Strings(refs)
	return refs, nil
}

func Resolve(raw []byte, mappings map[string]string) ([]byte, Result, error) {
	var empty Result
	spans, err := scan(raw)
	if err != nil {
		return nil, empty, err
	}
	expected := map[string]bool{}
	resolved := map[string]string{}
	for _, s := range spans {
		expected[s.ref] = true
		if _, exists := resolved[s.ref]; exists {
			continue
		}
		exact := s.ref
		if !exactDigestPattern.MatchString(s.ref) {
			exact = strings.TrimSpace(mappings[s.ref])
			if exact == "" {
				return nil, empty, fmt.Errorf("manifest image %q is not digest-pinned and has no exact resolution", s.ref)
			}
		} else if mapped := strings.TrimSpace(mappings[s.ref]); mapped != "" && mapped != s.ref {
			return nil, empty, fmt.Errorf("already digest-pinned manifest image %q cannot be remapped", s.ref)
		}
		if !exactDigestPattern.MatchString(exact) {
			return nil, empty, fmt.Errorf("manifest image %q resolution %q must be registry/repository@sha256:digest", s.ref, exact)
		}
		sourceRepo, err := canonicalRepository(s.ref)
		if err != nil {
			return nil, empty, err
		}
		exactRepo, err := canonicalRepository(exact)
		if err != nil {
			return nil, empty, err
		}
		if sourceRepo != exactRepo {
			return nil, empty, fmt.Errorf("manifest image %q resolution changes repository to %q", s.ref, exact)
		}
		resolved[s.ref] = exact
	}
	for source := range mappings {
		if !expected[source] {
			return nil, empty, fmt.Errorf("resolution supplied for image %q that is not present in the manifest", source)
		}
	}

	var out strings.Builder
	out.Grow(len(raw) + len(spans)*72)
	cursor := 0
	for _, s := range spans {
		out.Write(raw[cursor:s.start])
		out.WriteString(resolved[s.ref])
		cursor = s.end
	}
	out.Write(raw[cursor:])
	resolvedRaw := []byte(out.String())
	afterRefs, err := Extract(resolvedRaw)
	if err != nil {
		return nil, empty, fmt.Errorf("resolved manifest validation failed: %w", err)
	}
	for _, ref := range afterRefs {
		if !exactDigestPattern.MatchString(ref) {
			return nil, empty, fmt.Errorf("resolved manifest still contains mutable runtime image %q", ref)
		}
	}
	rows := make([]Resolution, 0, len(resolved))
	for source, exact := range resolved {
		rows = append(rows, Resolution{Source: source, Exact: exact})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Source < rows[j].Source })
	result := Result{
		Authority: ResolutionAuthority, SchemaVersion: 1,
		SourceManifestSHA256: digest(raw), SourceManifestBytes: len(raw),
		ResolvedManifestSHA256: digest(resolvedRaw), ResolvedManifestBytes: len(resolvedRaw),
		Images: rows,
	}
	return resolvedRaw, result, nil
}

func WriteResolved(raw []byte, mappings map[string]string, outManifest, outLock string) (Result, error) {
	var empty Result
	resolved, result, err := Resolve(raw, mappings)
	if err != nil {
		return empty, err
	}
	lockRaw, err := json.Marshal(result)
	if err != nil {
		return empty, err
	}
	lockRaw = append(lockRaw, '\n')
	if err := writeAtomicNew(outManifest, resolved, 0o644); err != nil {
		return empty, err
	}
	if err := writeAtomicNew(outLock, lockRaw, 0o644); err != nil {
		_ = os.Remove(outManifest)
		return empty, err
	}
	return result, nil
}

func writeAtomicNew(path string, raw []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) == "" || filepath.Clean(path) == "." {
		return fmt.Errorf("output path is required")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".manifest-images-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
