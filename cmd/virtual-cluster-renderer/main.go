package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/buildinfo"
)

const (
	authority = "VIRTUAL_CLUSTER_IMAGE_POST_RENDER_AUTHORITY_V1"
	maxInputBytes = 32 * 1024 * 1024
)

var imageLine = regexp.MustCompile(`^(\s*image:\s*)(["']?)([^"'\s#]+)(["']?)(\s*(?:#.*)?)$`)

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

func validateMirrorRef(ref string) error {
	ref = strings.TrimSpace(ref)
	at := strings.LastIndex(ref, "@sha256:")
	if at <= 0 || len(ref[at+len("@sha256:"):]) != 64 {
		return errors.New("mirror reference must be exact sha256")
	}
	for _, c := range ref[at+len("@sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("mirror reference digest must be lowercase hex")
		}
	}
	if strings.ContainsAny(ref, " \t\r\n") {
		return errors.New("mirror reference contains whitespace")
	}
	return nil
}

func loadMap(raw string) (map[string]string, error) {
	var mappings map[string]string
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&mappings); err != nil {
		return nil, fmt.Errorf("decode image mirror map: %w", err)
	}
	if len(mappings) == 0 {
		return nil, errors.New("image mirror map is empty")
	}
	for source, mirror := range mappings {
		if strings.TrimSpace(source) != source || source == "" || imageRepository(source) != source || strings.ContainsAny(source, " \t\r\n@") {
			return nil, fmt.Errorf("invalid source image repository %q", source)
		}
		if err := validateMirrorRef(mirror); err != nil {
			return nil, fmt.Errorf("invalid mirror for %s: %w", source, err)
		}
	}
	return mappings, nil
}

func rewrite(in io.Reader, out io.Writer, mappings map[string]string) error {
	limited := io.LimitReader(in, maxInputBytes+1)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	used := map[string]int{}
	var total int64
	for scanner.Scan() {
		line := scanner.Text()
		total += int64(len(line)) + 1
		if total > maxInputBytes {
			return errors.New("rendered manifest exceeds bounded input")
		}
		match := imageLine.FindStringSubmatch(line)
		if match != nil {
			ref := match[3]
			repository := imageRepository(ref)
			mirror, ok := mappings[repository]
			if !ok {
				return fmt.Errorf("rendered image repository has no exact mirror authority: %s", repository)
			}
			if match[2] != match[4] {
				return fmt.Errorf("rendered image quoting is malformed for %s", repository)
			}
			line = match[1] + match[2] + mirror + match[4] + match[5]
			used[repository]++
		}
		if _, err := io.WriteString(out, line+"\n"); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	var missing []string
	for source := range mappings {
		if used[source] == 0 {
			missing = append(missing, source)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("mirror authority contains image repositories absent from render: %s", strings.Join(missing, ","))
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(buildinfo.Version)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: virtual-cluster-renderer [version|--version]")
		os.Exit(2)
	}
	raw := strings.TrimSpace(os.Getenv("FOURSO_VIRTUAL_CLUSTER_IMAGE_MAP_JSON"))
	mappings, err := loadMap(raw)
	if err == nil {
		err = rewrite(os.Stdin, os.Stdout, mappings)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s_BLOCKED %v\n", authority, err)
		os.Exit(2)
	}
}
