package imagebundle

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type RegistryClient struct {
	BaseURL string
	HTTP    *http.Client
}

type MirrorResult struct {
	SourceReference   string `json:"sourceReference"`
	MirrorReference   string `json:"mirrorReference"`
	Repository        string `json:"repository"`
	Digest            string `json:"digest"`
	UploadedBlobs     int    `json:"uploadedBlobs"`
	UploadedManifests int    `json:"uploadedManifests"`
	Verified          bool   `json:"verified"`
}

func parseRegistryBase(base string) (*url.URL, error) {
	base = strings.TrimSpace(base)
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("registry URL must be http(s)://host")
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, fmt.Errorf("registry URL must contain only scheme and host without credentials, path, query or fragment")
	}
	u.Path = ""
	return u, nil
}

func validateRegistryTarget(base *url.URL, target *url.URL) error {
	if base == nil || target == nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return fmt.Errorf("registry target must be an absolute http(s) URL")
	}
	if target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return fmt.Errorf("registry target must not contain credentials, fragment or opaque URL data")
	}
	if base.Scheme == "https" && target.Scheme != "https" {
		return fmt.Errorf("refusing registry transport downgrade from HTTPS to %s", target.Scheme)
	}
	return nil
}

func NewRegistryClient(base string) (*RegistryClient, error) {
	u, err := parseRegistryBase(base)
	if err != nil {
		return nil, err
	}
	return &RegistryClient{BaseURL: strings.TrimRight(u.String(), "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}
func (c *RegistryClient) httpClient() *http.Client {
	baseClient := c.HTTP
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *baseClient
	previousRedirect := clone.CheckRedirect
	registryBase, baseErr := parseRegistryBase(c.BaseURL)
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if baseErr != nil {
			return baseErr
		}
		if err := validateRegistryTarget(registryBase, req.URL); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 registry redirects")
		}
		return nil
	}
	return &clone
}
func (c *RegistryClient) registryHost() (string, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}
func (c *RegistryClient) MirrorReference(source string) (string, error) {
	repo, err := MirrorRepository(source)
	if err != nil {
		return "", err
	}
	_, _, dg, _ := ParseDigestReference(source)
	host, err := c.registryHost()
	if err != nil {
		return "", err
	}
	return host + "/" + repo + "@" + dg, nil
}
func resolveLocation(base, loc string) (string, error) {
	b, err := url.Parse(strings.TrimSpace(base))
	if err != nil || b.Scheme == "" || b.Host == "" || (b.Scheme != "http" && b.Scheme != "https") {
		return "", fmt.Errorf("invalid registry upload base URL")
	}
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || strings.TrimSpace(loc) == "" {
		return "", fmt.Errorf("invalid registry upload location")
	}
	resolved := b.ResolveReference(u)
	if err := validateRegistryTarget(b, resolved); err != nil {
		return "", err
	}
	return resolved.String(), nil
}

func appendDigestQueryOpaque(rawURL, digest string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	var existing []string
	for _, field := range strings.Split(u.RawQuery, "&") {
		if field == "" {
			continue
		}
		parts := strings.SplitN(field, "=", 2)
		key, err := url.QueryUnescape(parts[0])
		if err != nil {
			return "", fmt.Errorf("invalid registry upload query key: %w", err)
		}
		if key != "digest" {
			continue
		}
		value := ""
		if len(parts) == 2 {
			value, err = url.QueryUnescape(parts[1])
			if err != nil {
				return "", fmt.Errorf("invalid registry upload digest query: %w", err)
			}
		}
		existing = append(existing, value)
	}
	if len(existing) > 0 {
		if len(existing) != 1 || existing[0] != digest {
			return "", fmt.Errorf("registry upload location contains conflicting digest query")
		}
		return u.String(), nil
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += "digest=" + url.QueryEscape(digest)
	return u.String(), nil
}
func (c *RegistryClient) do(ctx context.Context, method, endpoint, contentType string, body []byte, expected ...int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method == http.MethodHead || strings.Contains(endpoint, "/manifests/") {
		req.Header.Set("Accept", strings.Join([]string{MediaTypeOCIManifest, MediaTypeOCIIndex, MediaTypeDockerManifest, MediaTypeDockerList}, ", "))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	ok := false
	for _, x := range expected {
		if resp.StatusCode == x {
			ok = true
			break
		}
	}
	if !ok {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return nil, fmt.Errorf("registry %s %s returned HTTP %d: %s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp, nil
}
func (c *RegistryClient) blobExists(ctx context.Context, repo, digest string) bool {
	ep := c.BaseURL + "/v2/" + repo + "/blobs/" + digest
	resp, err := c.do(ctx, http.MethodHead, ep, "", nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
func (c *RegistryClient) pushBlob(ctx context.Context, repo string, obj Object) error {
	if c.blobExists(ctx, repo, obj.Digest) {
		return nil
	}
	start := c.BaseURL + "/v2/" + repo + "/blobs/uploads/"
	resp, err := c.do(ctx, http.MethodPost, start, "", nil, http.StatusAccepted)
	if err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if loc == "" {
		return fmt.Errorf("registry upload location missing")
	}
	locationBase := start
	if resp.Request != nil && resp.Request.URL != nil {
		locationBase = resp.Request.URL.String()
	}
	upload, err := resolveLocation(locationBase, loc)
	if err != nil {
		return err
	}
	upload, err = appendDigestQueryOpaque(upload, obj.Digest)
	if err != nil {
		return err
	}
	resp, err = c.do(ctx, http.MethodPut, upload, "application/octet-stream", obj.Raw, http.StatusCreated, http.StatusNoContent)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func (c *RegistryClient) pushManifest(ctx context.Context, repo string, obj Object) error {
	ep := c.BaseURL + "/v2/" + repo + "/manifests/" + obj.Digest
	ct := obj.MediaType
	if ct == "" {
		ct = MediaTypeOCIManifest
	}
	resp, err := c.do(ctx, http.MethodPut, ep, ct, obj.Raw, http.StatusCreated, http.StatusAccepted, http.StatusNoContent)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func (c *RegistryClient) Verify(ctx context.Context, sourceReference string) (MirrorResult, error) {
	repo, err := MirrorRepository(sourceReference)
	if err != nil {
		return MirrorResult{}, err
	}
	_, _, dg, _ := ParseDigestReference(sourceReference)
	ep := c.BaseURL + "/v2/" + repo + "/manifests/" + dg
	resp, err := c.do(ctx, http.MethodHead, ep, "", nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return MirrorResult{}, err
	}
	defer resp.Body.Close()
	mirror, _ := c.MirrorReference(sourceReference)
	result := MirrorResult{SourceReference: sourceReference, MirrorReference: mirror, Repository: repo, Digest: dg, Verified: false}
	if resp.StatusCode == http.StatusNotFound {
		return result, nil
	}
	header := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if header != "" && header != dg {
		return result, fmt.Errorf("registry digest mismatch: requested %s got %s", dg, header)
	}
	result.Verified = true
	return result, nil
}
func (c *RegistryClient) Push(ctx context.Context, v Verified) (MirrorResult, error) {
	repo := v.Manifest.MirrorRepository
	blobs := []Object{}
	manifests := []Object{}
	for _, o := range v.Objects {
		if o.Manifest {
			manifests = append(manifests, o)
		} else {
			blobs = append(blobs, o)
		}
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Digest < blobs[j].Digest })
	for _, o := range blobs {
		if err := c.pushBlob(ctx, repo, o); err != nil {
			return MirrorResult{}, err
		}
	}
	// Child manifests must exist before an image index that references them. The verifier walks root first,
	// so reverse the manifest order and always push the root digest last.
	for i, j := 0, len(manifests)-1; i < j; i, j = i+1, j-1 {
		manifests[i], manifests[j] = manifests[j], manifests[i]
	}
	for _, o := range manifests {
		if err := c.pushManifest(ctx, repo, o); err != nil {
			return MirrorResult{}, err
		}
	}
	result, err := c.Verify(ctx, v.Manifest.SourceReference)
	if err != nil {
		return MirrorResult{}, err
	}
	result.UploadedBlobs = len(blobs)
	result.UploadedManifests = len(manifests)
	if !result.Verified {
		return result, fmt.Errorf("registry did not expose mirrored root manifest after push")
	}
	return result, nil
}
