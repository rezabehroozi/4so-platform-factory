package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"platform.4so.io/factory/internal/openchoreo"
)

var imageLine = regexp.MustCompile(`^(\s*(?:-\s*)?image:\s*)(["']?)([^"'\s#]+)(["']?)(\s*(?:#.*)?)$`)

func imageRepository(ref string) string {
	ref = strings.TrimSpace(ref)
	if at := strings.IndexByte(ref, '@'); at >= 0 {
		ref = ref[:at]
	}
	lastSlash := strings.LastIndexByte(ref, '/')
	if colon := strings.LastIndexByte(ref, ':'); colon > lastSlash {
		ref = ref[:colon]
	}
	return ref
}

func runtimeMirrorMap(source openchoreo.RuntimeSource) (map[string]string, error) {
	if err := openchoreo.ValidateRuntimeExecutionSource(source); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, row := range source.Images {
		repository := imageRepository(row.SourceReference)
		if repository == "" || strings.TrimSpace(row.MirrorReference) == "" {
			return nil, errors.New("OpenChoreo image mirror entry is incomplete")
		}
		if existing, ok := out[repository]; ok && existing != row.MirrorReference {
			return nil, fmt.Errorf("OpenChoreo source image repository maps to multiple exact mirrors: %s", repository)
		}
		out[repository] = row.MirrorReference
	}
	if len(out) == 0 {
		return nil, errors.New("OpenChoreo image mirror map is empty")
	}
	return out, nil
}

func postRender(in io.Reader, out io.Writer, source openchoreo.RuntimeSource) error {
	mappings, err := runtimeMirrorMap(source)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(io.LimitReader(in, maxRenderBytes+1))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var total int64
	for scanner.Scan() {
		line := scanner.Text()
		total += int64(len(line)) + 1
		if total > maxRenderBytes {
			return errors.New("OpenChoreo rendered manifest exceeds bounded input")
		}
		match := imageLine.FindStringSubmatch(line)
		if match != nil {
			if match[2] != match[4] {
				return errors.New("OpenChoreo rendered image quoting is malformed")
			}
			repository := imageRepository(match[3])
			mirror, ok := mappings[repository]
			if !ok {
				return fmt.Errorf("OpenChoreo rendered image has no exact zot mirror: %s", repository)
			}
			line = match[1] + match[2] + mirror + match[4] + match[5]
		}
		if _, err := io.WriteString(out, line+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func sha256File(path string, maxBytes int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return "", fmt.Errorf("runtime artifact is not a bounded regular file: %s", path)
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, maxBytes+1)); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyRuntimeArtifacts(source openchoreo.RuntimeSource) error {
	paths := map[string][3]string{
		"control-plane": {"/runtime/openchoreo-control-plane.tgz", "/runtime/control-plane-values.yaml", "/runtime/control-plane-render.json"},
		"data-plane":    {"/runtime/openchoreo-data-plane.tgz", "/runtime/data-plane-values.yaml", "/runtime/data-plane-render.json"},
	}
	if len(source.Planes) != len(paths) {
		return errors.New("OpenChoreo runtime plane inventory is incomplete")
	}
	for _, plane := range source.Planes {
		files, ok := paths[plane.Name]
		if !ok {
			return fmt.Errorf("OpenChoreo runtime plane is unsupported: %s", plane.Name)
		}
		checks := []struct {
			path, want string
			limit      int64
		}{
			{files[0], plane.ChartSHA256, 256 << 20},
			{files[1], plane.ValuesSHA256, 4 << 20},
			{files[2], plane.RenderManifestSHA256, 64 << 20},
		}
		for _, check := range checks {
			got, err := sha256File(check.path, check.limit)
			if err != nil || got != check.want {
				return fmt.Errorf("OpenChoreo runtime artifact digest mismatch for %s", check.path)
			}
		}
	}
	return nil
}
