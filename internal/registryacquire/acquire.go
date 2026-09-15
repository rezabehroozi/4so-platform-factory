package registryacquire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Authority = "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2"

const (
	mediaOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	maxManifestBytes    = 8 << 20
	maxTokenBytes       = 1 << 20
	maxConfigBytes      = 16 << 20
	maxLayerBytes       = int64(8) << 30
	maxImageBytes       = int64(32) << 30
)

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9.-]+(?::[0-9]+)?$`)
	tagRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

type Spec struct {
	Role                  string `json:"role"`
	SourceRepository      string `json:"sourceRepository"`
	RegistryEndpoint      string `json:"registryEndpoint"`
	RegistryRepo          string `json:"registryRepository"`
	SelectedVersion       string `json:"selectedVersion"`
	Tag                   string `json:"tag"`
	SelectionChannel      string `json:"selectionChannel"`
	SelectionEvidenceURL  string `json:"selectionEvidenceURL"`
	ReleaseArtifactDigest string `json:"releaseArtifactDigest"`
	PlanDigest            string `json:"planDigest"`
	OS                    string `json:"os"`
	Architecture          string `json:"architecture"`
}

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type Result struct {
	Authority             string       `json:"authority"`
	SchemaVersion         int          `json:"schemaVersion"`
	Role                  string       `json:"role"`
	ReleaseArtifactDigest string       `json:"releaseArtifactDigest"`
	PlanDigest            string       `json:"planDigest"`
	SourceRepository      string       `json:"sourceRepository"`
	SelectedVersion       string       `json:"selectedVersion"`
	SourceTag             string       `json:"sourceTag"`
	SelectionChannel      string       `json:"selectionChannel"`
	SelectionEvidenceURL  string       `json:"selectionEvidenceURL"`
	RegistryEndpoint      string       `json:"registryEndpoint"`
	RegistryRepository    string       `json:"registryRepository"`
	PlatformOS            string       `json:"platformOs"`
	PlatformArch          string       `json:"platformArchitecture"`
	TagRootDigest         string       `json:"tagRootDigest"`
	TagRootMediaType      string       `json:"tagRootMediaType"`
	TagRootBytes          int64        `json:"tagRootBytes"`
	ManifestDigest        string       `json:"manifestDigest"`
	ManifestMediaType     string       `json:"manifestMediaType"`
	ExactReference        string       `json:"exactReference"`
	Config                Descriptor   `json:"config"`
	Layers                []Descriptor `json:"layers"`
	ReachableBytes        int64        `json:"reachableBytes"`
}

type Client struct {
	HTTP *http.Client
}

func blockedAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		v := addr.As4()
		return v[0] == 0 || v[0] == 10 || v[0] == 127 || (v[0] == 169 && v[1] == 254) || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) || (v[0] == 192 && v[1] == 168)
	}
	return false
}

func NewPublicClient() *Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid registry target %q: %w", address, err)
		}
		values, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(values) == 0 {
			return nil, fmt.Errorf("resolve registry target %q: %w", host, err)
		}
		for _, value := range values {
			if blockedAddress(value) {
				return nil, fmt.Errorf("registry target resolves to unsafe address %s", value.Unmap())
			}
		}
		var last error
		for _, value := range values {
			addr := value.Unmap()
			if network == "tcp4" && !addr.Is4() {
				continue
			}
			if network == "tcp6" && addr.Is4() {
				continue
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			last = dialErr
		}
		if last == nil {
			last = errors.New("no address compatible with requested network")
		}
		return nil, last
	}
	return &Client{HTTP: &http.Client{Transport: transport, CheckRedirect: checkPublicRedirect}}
}

func checkPublicRedirect(req *http.Request, via []*http.Request) error {
	// via contains the already-issued requests. Allow at most five redirect hops.
	if len(via) > 5 {
		return errors.New("registry redirect limit exceeded")
	}
	if req == nil || req.URL == nil || req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil || req.URL.Opaque != "" {
		return errors.New("registry redirect target must be an absolute credential-free HTTPS URL")
	}
	if len(via) > 0 {
		previous := via[len(via)-1]
		if previous == nil || previous.URL == nil {
			return errors.New("registry redirect history is invalid")
		}
		if !strings.EqualFold(previous.URL.Scheme, req.URL.Scheme) || !strings.EqualFold(previous.URL.Host, req.URL.Host) {
			req.Header.Del("Authorization")
		}
	}
	return nil
}

func NewTestClient(httpClient *http.Client) *Client { return &Client{HTTP: httpClient} }

func canonicalSpec(spec Spec) error {
	spec.Role = strings.TrimSpace(spec.Role)
	if spec.Role == "" {
		return errors.New("external image role is required")
	}
	if spec.OS != "linux" || spec.Architecture != "amd64" {
		return errors.New("external image acquisition currently requires linux/amd64")
	}
	if !tagRE.MatchString(spec.Tag) || strings.EqualFold(spec.Tag, "latest") {
		return fmt.Errorf("external image tag %q is not an immutable version-selection input", spec.Tag)
	}
	if strings.TrimSpace(spec.SelectedVersion) == "" || strings.TrimSpace(spec.SelectedVersion) != spec.SelectedVersion {
		return errors.New("external image selected version is required and canonical")
	}
	if strings.TrimSpace(spec.SelectionChannel) == "" || strings.TrimSpace(spec.SelectionChannel) != spec.SelectionChannel {
		return errors.New("external image selection channel is required and canonical")
	}
	evidence, err := url.Parse(spec.SelectionEvidenceURL)
	if err != nil || evidence.Scheme != "https" || evidence.Host == "" || evidence.User != nil || evidence.Fragment != "" {
		return errors.New("external image selection evidence URL must be credential-free HTTPS")
	}
	if strings.TrimSpace(spec.SourceRepository) != spec.SourceRepository || strings.TrimSpace(spec.RegistryEndpoint) != spec.RegistryEndpoint || strings.TrimSpace(spec.RegistryRepo) != spec.RegistryRepo {
		return errors.New("external image source fields must be canonical")
	}
	if !hostRE.MatchString(spec.RegistryEndpoint) || strings.Contains(spec.RegistryEndpoint, "..") {
		return fmt.Errorf("registry endpoint %q is invalid", spec.RegistryEndpoint)
	}
	if spec.RegistryRepo == "" || strings.HasPrefix(spec.RegistryRepo, "/") || strings.HasSuffix(spec.RegistryRepo, "/") || strings.Contains(spec.RegistryRepo, "..") || strings.ContainsAny(spec.RegistryRepo, " @?#\\") {
		return fmt.Errorf("registry repository %q is invalid", spec.RegistryRepo)
	}
	slash := strings.Index(spec.SourceRepository, "/")
	if slash <= 0 || slash == len(spec.SourceRepository)-1 || strings.ContainsAny(spec.SourceRepository, " @?#\\") {
		return fmt.Errorf("source repository %q is invalid", spec.SourceRepository)
	}
	if strings.Contains(spec.SourceRepository, ":") {
		return fmt.Errorf("source repository %q must not contain a tag", spec.SourceRepository)
	}
	return nil
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requestURL(host, repo, kind, ref string) string {
	return "https://" + host + "/v2/" + repo + "/" + kind + "/" + ref
}

func readLimited(resp *http.Response, limit int64) ([]byte, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("registry response exceeds %d bytes", limit)
	}
	return raw, nil
}

func parseBearerChallenge(raw, repo string) (*url.URL, url.Values, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return nil, nil, errors.New("registry authentication challenge must use Bearer")
	}
	rest := strings.TrimSpace(raw[len("Bearer "):])
	params := map[string]string{}
	for len(rest) > 0 {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return nil, nil, errors.New("malformed registry Bearer challenge")
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimSpace(rest[eq+1:])
		if !strings.HasPrefix(rest, `"`) {
			return nil, nil, errors.New("registry Bearer challenge values must be quoted")
		}
		rest = rest[1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return nil, nil, errors.New("unterminated registry Bearer challenge value")
		}
		value := rest[:end]
		if strings.Contains(value, `\`) {
			return nil, nil, errors.New("escaped registry Bearer challenge values are unsupported")
		}
		if _, exists := params[key]; exists {
			return nil, nil, fmt.Errorf("duplicate registry Bearer challenge parameter %q", key)
		}
		params[key] = value
		rest = strings.TrimSpace(rest[end+1:])
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, ",") {
			return nil, nil, errors.New("malformed registry Bearer challenge separator")
		}
		rest = strings.TrimSpace(rest[1:])
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil || realm.Fragment != "" || realm.Opaque != "" {
		return nil, nil, errors.New("registry Bearer realm must be an absolute credential-free HTTPS URL")
	}
	values := realm.Query()
	realm.RawQuery = ""
	service := strings.TrimSpace(params["service"])
	if service != "" {
		values.Set("service", service)
	}
	wantScope := "repository:" + repo + ":pull"
	if scope := strings.TrimSpace(params["scope"]); scope != "" && scope != wantScope {
		return nil, nil, fmt.Errorf("registry Bearer scope %q does not match %q", scope, wantScope)
	}
	values.Set("scope", wantScope)
	return realm, values, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeJSON(raw []byte, target any, disallowUnknown bool) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if disallowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (c *Client) token(ctx context.Context, challenge, repo string) (string, error) {
	realm, values, err := parseBearerChallenge(challenge, repo)
	if err != nil {
		return "", err
	}
	realm.RawQuery = values.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := readLimited(resp, maxTokenBytes)
		return "", fmt.Errorf("registry token endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	raw, err := readLimited(resp, maxTokenBytes)
	if err != nil {
		return "", err
	}
	var doc struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}
	if err := decodeJSON(raw, &doc, false); err != nil {
		return "", fmt.Errorf("decode registry token response: %w", err)
	}
	token := strings.TrimSpace(doc.Token)
	if token == "" {
		token = strings.TrimSpace(doc.AccessToken)
	}
	if token == "" || len(token) > 64<<10 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("registry token response does not contain a canonical bearer token")
	}
	return token, nil
}

func (c *Client) do(ctx context.Context, method, endpoint, repo, bearer string, accept []string) (*http.Response, string, error) {
	makeReq := func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if len(accept) > 0 {
			req.Header.Set("Accept", strings.Join(accept, ", "))
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return req, nil
	}
	req, err := makeReq(bearer)
	if err != nil {
		return nil, bearer, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, bearer, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, bearer, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	_ = resp.Body.Close()
	token, err := c.token(ctx, challenge, repo)
	if err != nil {
		return nil, bearer, err
	}
	req, _ = makeReq(token)
	resp, err = c.HTTP.Do(req)
	return resp, token, err
}

type manifestDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	URLs         []string          `json:"urls,omitempty"`
	Data         string            `json:"data,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Platform     *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}
type indexDocument struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Manifests     []manifestDescriptor `json:"manifests"`
	Annotations   map[string]string    `json:"annotations,omitempty"`
	ArtifactType  string               `json:"artifactType,omitempty"`
	Subject       *manifestDescriptor  `json:"subject,omitempty"`
}
type manifestDocument struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Config        manifestDescriptor   `json:"config"`
	Layers        []manifestDescriptor `json:"layers"`
	Annotations   map[string]string    `json:"annotations,omitempty"`
	ArtifactType  string               `json:"artifactType,omitempty"`
	Subject       *manifestDescriptor  `json:"subject,omitempty"`
}

func validateDescriptor(d manifestDescriptor, max int64) error {
	if !digestRE.MatchString(d.Digest) || d.Size <= 0 || d.Size > max {
		return fmt.Errorf("invalid OCI descriptor digest/size %q/%d", d.Digest, d.Size)
	}
	if len(d.URLs) != 0 || d.Data != "" || d.ArtifactType != "" {
		return fmt.Errorf("OCI descriptor %s uses unsupported alternate/embedded artifact fields", d.Digest)
	}
	return nil
}

func mediaType(resp *http.Response, raw []byte) string {
	ct := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if ct != "" {
		return ct
	}
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.MediaType
}

func (c *Client) fetchManifest(ctx context.Context, spec Spec, ref, bearer string) ([]byte, string, string, string, error) {
	accepts := []string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerManifest}
	ep := requestURL(spec.RegistryEndpoint, spec.RegistryRepo, "manifests", ref)
	resp, token, err := c.do(ctx, http.MethodGet, ep, spec.RegistryRepo, bearer, accepts)
	if err != nil {
		return nil, "", "", token, err
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := readLimited(resp, 1<<20)
		return nil, "", "", token, fmt.Errorf("registry manifest GET returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	raw, err := readLimited(resp, maxManifestBytes)
	if err != nil {
		return nil, "", "", token, err
	}
	digest := digestBytes(raw)
	if header := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest")); header != "" && header != digest {
		return nil, "", "", token, fmt.Errorf("registry manifest digest header %s does not match body %s", header, digest)
	}
	mt := mediaType(resp, raw)
	var declared struct {
		MediaType string `json:"mediaType"`
	}
	if err := decodeJSON(raw, &declared, false); err != nil {
		return nil, "", "", token, fmt.Errorf("decode registry manifest envelope: %w", err)
	}
	if declared.MediaType != "" && mt != declared.MediaType {
		return nil, "", "", token, fmt.Errorf("registry response media type %q does not match document %q", mt, declared.MediaType)
	}
	return raw, digest, mt, token, nil
}

func choosePlatform(raw []byte, osName, arch string) (manifestDescriptor, error) {
	var doc indexDocument
	if err := decodeJSON(raw, &doc, true); err != nil || doc.SchemaVersion != 2 || len(doc.Manifests) == 0 || len(doc.Manifests) > 256 {
		return manifestDescriptor{}, errors.New("registry image index is invalid")
	}
	if doc.MediaType != "" && doc.MediaType != mediaOCIIndex && doc.MediaType != mediaDockerList {
		return manifestDescriptor{}, fmt.Errorf("registry image index document media type %q is invalid", doc.MediaType)
	}
	if doc.ArtifactType != "" || doc.Subject != nil {
		return manifestDescriptor{}, errors.New("registry workload image index cannot be an artifact/referrer")
	}
	matches := []manifestDescriptor{}
	for _, d := range doc.Manifests {
		if err := validateDescriptor(d, maxManifestBytes); err != nil {
			return manifestDescriptor{}, err
		}
		if d.Platform != nil && d.Platform.OS == osName && d.Platform.Architecture == arch && d.Platform.Variant == "" {
			matches = append(matches, d)
		}
	}
	if len(matches) != 1 {
		return manifestDescriptor{}, fmt.Errorf("registry image index must contain exactly one %s/%s descriptor, got %d", osName, arch, len(matches))
	}
	return matches[0], nil
}

func parseManifest(raw []byte, mt string) (manifestDocument, error) {
	if mt != mediaOCIManifest && mt != mediaDockerManifest {
		return manifestDocument{}, fmt.Errorf("unsupported final image manifest media type %q", mt)
	}
	var doc manifestDocument
	if err := decodeJSON(raw, &doc, true); err != nil || doc.SchemaVersion != 2 {
		return manifestDocument{}, errors.New("registry image manifest is invalid")
	}
	if doc.MediaType != "" && doc.MediaType != mt {
		return manifestDocument{}, fmt.Errorf("registry image manifest document media type %q does not match response %q", doc.MediaType, mt)
	}
	if doc.ArtifactType != "" || doc.Subject != nil {
		return manifestDocument{}, errors.New("registry workload image manifest cannot be an artifact/referrer")
	}
	if err := validateDescriptor(doc.Config, maxConfigBytes); err != nil {
		return manifestDocument{}, err
	}
	if len(doc.Layers) == 0 || len(doc.Layers) > 512 {
		return manifestDocument{}, errors.New("registry image manifest has invalid layer count")
	}
	var total int64 = doc.Config.Size
	for _, layer := range doc.Layers {
		if err := validateDescriptor(layer, maxLayerBytes); err != nil {
			return manifestDocument{}, err
		}
		if total > maxImageBytes-layer.Size {
			return manifestDocument{}, errors.New("registry image reachable bytes exceed limit")
		}
		total += layer.Size
	}
	return doc, nil
}

func ensureNewDir(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("output OCI layout path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", fmt.Errorf("refusing to overwrite existing OCI layout %s", abs)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(parent, ".registry-acquire-*")
	if err != nil {
		return "", err
	}
	return tmp, nil
}

func writeBlobRaw(root, digest string, raw []byte) error {
	if digestBytes(raw) != digest {
		return fmt.Errorf("blob %s digest mismatch", digest)
	}
	path := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func (c *Client) downloadBlob(ctx context.Context, spec Spec, d manifestDescriptor, bearer, root string) (string, int64, error) {
	ep := requestURL(spec.RegistryEndpoint, spec.RegistryRepo, "blobs", d.Digest)
	resp, token, err := c.do(ctx, http.MethodGet, ep, spec.RegistryRepo, bearer, nil)
	if err != nil {
		return bearer, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return token, 0, fmt.Errorf("registry blob GET %s returned HTTP %d", d.Digest, resp.StatusCode)
	}
	path := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(d.Digest, "sha256:"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		_ = resp.Body.Close()
		return token, 0, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = resp.Body.Close()
		return token, 0, err
	}
	hash := sha256.New()
	limited := io.LimitReader(resp.Body, d.Size+1)
	n, copyErr := io.Copy(io.MultiWriter(f, hash), limited)
	closeBodyErr := resp.Body.Close()
	syncErr := f.Sync()
	closeFileErr := f.Close()
	if copyErr != nil {
		return token, n, copyErr
	}
	if closeBodyErr != nil {
		return token, n, closeBodyErr
	}
	if syncErr != nil {
		return token, n, syncErr
	}
	if closeFileErr != nil {
		return token, n, closeFileErr
	}
	if n != d.Size {
		return token, n, fmt.Errorf("registry blob %s size %d does not match descriptor %d", d.Digest, n, d.Size)
	}
	got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if got != d.Digest {
		return token, n, fmt.Errorf("registry blob %s body digest is %s", d.Digest, got)
	}
	return token, n, nil
}

func writeJSONAtomicNew(path string, doc any) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".registry-lock-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(name, 0o644); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func (c *Client) Acquire(ctx context.Context, spec Spec, outLayout, outLock string) (Result, error) {
	var empty Result
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if c == nil || c.HTTP == nil {
		return empty, errors.New("registry HTTP client is required")
	}
	if err := canonicalSpec(spec); err != nil {
		return empty, err
	}
	if !digestRE.MatchString(spec.ReleaseArtifactDigest) || !digestRE.MatchString(spec.PlanDigest) {
		return empty, errors.New("external image acquisition requires exact release and plan digests")
	}
	tmp, err := ensureNewDir(outLayout)
	if err != nil {
		return empty, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(tmp)
		}
	}()
	raw, rootDigest, rootMT, bearer, err := c.fetchManifest(ctx, spec, spec.Tag, "")
	if err != nil {
		return empty, err
	}
	if err := writeBlobRaw(tmp, rootDigest, raw); err != nil {
		return empty, err
	}
	finalRaw, finalDigest, finalMT := raw, rootDigest, rootMT
	if rootMT == mediaOCIIndex || rootMT == mediaDockerList {
		child, err := choosePlatform(raw, spec.OS, spec.Architecture)
		if err != nil {
			return empty, err
		}
		finalRaw, finalDigest, finalMT, bearer, err = c.fetchManifest(ctx, spec, child.Digest, bearer)
		if err != nil {
			return empty, err
		}
		if finalDigest != child.Digest || int64(len(finalRaw)) != child.Size {
			return empty, fmt.Errorf("platform manifest does not match index descriptor")
		}
		if child.MediaType != "" && finalMT != child.MediaType {
			return empty, fmt.Errorf("platform manifest media type %q does not match index descriptor %q", finalMT, child.MediaType)
		}
	}
	manifest, err := parseManifest(finalRaw, finalMT)
	if err != nil {
		return empty, err
	}
	if finalDigest != rootDigest {
		if err := writeBlobRaw(tmp, finalDigest, finalRaw); err != nil {
			return empty, err
		}
	}
	reachable := int64(len(raw))
	if finalDigest != rootDigest {
		reachable += int64(len(finalRaw))
	}
	bearer, n, err := c.downloadBlob(ctx, spec, manifest.Config, bearer, tmp)
	if err != nil {
		return empty, err
	}
	reachable += n
	layers := make([]Descriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		bearer, n, err = c.downloadBlob(ctx, spec, layer, bearer, tmp)
		if err != nil {
			return empty, err
		}
		reachable += n
		layers = append(layers, Descriptor{MediaType: layer.MediaType, Digest: layer.Digest, Size: layer.Size})
	}
	exactRef := spec.SourceRepository + "@" + finalDigest
	index := map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "manifests": []any{map[string]any{"mediaType": finalMT, "digest": finalDigest, "size": len(finalRaw), "platform": map[string]string{"os": spec.OS, "architecture": spec.Architecture}, "annotations": map[string]string{"io.containerd.image.name": exactRef, "org.opencontainers.image.ref.name": exactRef}}}}
	if err := writeJSONAtomicNew(filepath.Join(tmp, "oci-layout"), map[string]string{"imageLayoutVersion": "1.0.0"}); err != nil {
		return empty, err
	}
	if err := writeJSONAtomicNew(filepath.Join(tmp, "index.json"), index); err != nil {
		return empty, err
	}
	result := Result{Authority: Authority, SchemaVersion: 2, Role: spec.Role, ReleaseArtifactDigest: spec.ReleaseArtifactDigest, PlanDigest: spec.PlanDigest, SourceRepository: spec.SourceRepository, SelectedVersion: spec.SelectedVersion, SourceTag: spec.Tag, SelectionChannel: spec.SelectionChannel, SelectionEvidenceURL: spec.SelectionEvidenceURL, RegistryEndpoint: spec.RegistryEndpoint, RegistryRepository: spec.RegistryRepo, PlatformOS: spec.OS, PlatformArch: spec.Architecture, TagRootDigest: rootDigest, TagRootMediaType: rootMT, TagRootBytes: int64(len(raw)), ManifestDigest: finalDigest, ManifestMediaType: finalMT, ExactReference: exactRef, Config: Descriptor{MediaType: manifest.Config.MediaType, Digest: manifest.Config.Digest, Size: manifest.Config.Size}, Layers: layers, ReachableBytes: reachable}
	if err := writeJSONAtomicNew(outLock, result); err != nil {
		return empty, err
	}
	outAbs, _ := filepath.Abs(outLayout)
	if err := os.Rename(tmp, outAbs); err != nil {
		_ = os.Remove(outLock)
		return empty, err
	}
	keep = true
	_ = bearer
	return result, nil
}

func ParsePlanExternal(raw []byte, role, version string) (Spec, error) {
	var empty Spec
	var plan struct {
		Authority      string `json:"authority"`
		SchemaVersion  int    `json:"schemaVersion"`
		ReleaseVersion string `json:"releaseVersion"`
		TargetPlatform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"targetPlatform"`
		CoreImages []struct{ Role, Ownership, Repository, RegistryEndpoint, RegistryRepository, Version, Tag, SelectionChannel, SelectionEvidenceURL, State, Blocker string } `json:"coreImages"`
	}
	if err := decodeJSON(raw, &plan, false); err != nil {
		return empty, fmt.Errorf("decode management workload image plan: %w", err)
	}
	if plan.Authority != "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5" || plan.SchemaVersion != 5 || plan.ReleaseVersion != version {
		return empty, errors.New("management workload image plan is not V5 for the exact release")
	}
	for _, item := range plan.CoreImages {
		if item.Role != role {
			continue
		}
		if item.Ownership != "external" {
			return empty, fmt.Errorf("role %s is not externally acquired", role)
		}
		spec := Spec{Role: item.Role, SourceRepository: item.Repository, RegistryEndpoint: item.RegistryEndpoint, RegistryRepo: item.RegistryRepository, SelectedVersion: item.Version, Tag: item.Tag, SelectionChannel: item.SelectionChannel, SelectionEvidenceURL: item.SelectionEvidenceURL, OS: plan.TargetPlatform.OS, Architecture: plan.TargetPlatform.Architecture}
		if item.Version == "" {
			return empty, fmt.Errorf("role %s has no selected version", role)
		}
		if err := canonicalSpec(spec); err != nil {
			return empty, err
		}
		return spec, nil
	}
	return empty, fmt.Errorf("external image role %s is not present in the plan", role)
}

func SortedLayerDigests(result Result) []string {
	out := make([]string, 0, len(result.Layers))
	for _, x := range result.Layers {
		out = append(out, x.Digest)
	}
	sort.Strings(out)
	return out
}
func ParseSize(v string) (int64, error) { return strconv.ParseInt(v, 10, 64) }

func safeReadLayoutFile(root, rel string, limit int64) ([]byte, error) {
	if strings.TrimSpace(root) != root || root == "" || strings.TrimSpace(rel) != rel || rel == "" || filepath.IsAbs(rel) {
		return nil, errors.New("external OCI layout path is not canonical")
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("external OCI layout path %q is not canonical", rel)
		}
	}
	before, err := os.Lstat(root)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("external OCI layout root must be a real directory")
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open external OCI layout root safely: %w", err)
	}
	for i, part := range parts {
		last := i == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open external OCI layout path %q safely: %w", rel, openErr)
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root, rel))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open external OCI layout path %q safely", rel)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("external OCI layout path %q must be a bounded non-empty regular file", rel)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("read external OCI layout path %q", rel)
	}
	return raw, nil
}

func readVerifiedLayoutBlob(root, digest string, size, limit int64) ([]byte, error) {
	if !digestRE.MatchString(digest) || size <= 0 || size > limit {
		return nil, fmt.Errorf("external OCI blob descriptor is invalid")
	}
	rel := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
	raw, err := safeReadLayoutFile(root, rel, limit)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != size {
		return nil, fmt.Errorf("external OCI blob %s size mismatch", digest)
	}
	if got := digestBytes(raw); got != digest {
		return nil, fmt.Errorf("external OCI blob %s digest mismatch", digest)
	}
	return raw, nil
}

func validateResult(result Result) error {
	if result.Authority != Authority || result.SchemaVersion != 2 {
		return errors.New("external image acquisition lock authority/schema is invalid")
	}
	spec := Spec{Role: result.Role, SourceRepository: result.SourceRepository, RegistryEndpoint: result.RegistryEndpoint, RegistryRepo: result.RegistryRepository, SelectedVersion: result.SelectedVersion, Tag: result.SourceTag, SelectionChannel: result.SelectionChannel, SelectionEvidenceURL: result.SelectionEvidenceURL, ReleaseArtifactDigest: result.ReleaseArtifactDigest, PlanDigest: result.PlanDigest, OS: result.PlatformOS, Architecture: result.PlatformArch}
	if err := canonicalSpec(spec); err != nil {
		return err
	}
	if !digestRE.MatchString(result.ReleaseArtifactDigest) || !digestRE.MatchString(result.PlanDigest) || !digestRE.MatchString(result.TagRootDigest) || !digestRE.MatchString(result.ManifestDigest) {
		return errors.New("external image acquisition lock digest binding is invalid")
	}
	if result.TagRootBytes <= 0 || result.TagRootBytes > maxManifestBytes || result.ReachableBytes <= 0 || result.ReachableBytes > maxImageBytes {
		return errors.New("external image acquisition lock byte accounting is invalid")
	}
	if result.ExactReference != result.SourceRepository+"@"+result.ManifestDigest {
		return errors.New("external image acquisition exact reference is invalid")
	}
	if result.Config.Size <= 0 || result.Config.Size > maxConfigBytes || !digestRE.MatchString(result.Config.Digest) || strings.TrimSpace(result.Config.MediaType) == "" {
		return errors.New("external image acquisition config descriptor is invalid")
	}
	if len(result.Layers) == 0 || len(result.Layers) > 512 {
		return errors.New("external image acquisition layer set is invalid")
	}
	seen := map[string]bool{result.Config.Digest: true}
	for _, layer := range result.Layers {
		if layer.Size <= 0 || layer.Size > maxLayerBytes || !digestRE.MatchString(layer.Digest) || strings.TrimSpace(layer.MediaType) == "" || seen[layer.Digest] {
			return errors.New("external image acquisition layer descriptor is invalid")
		}
		seen[layer.Digest] = true
	}
	return nil
}

func ParseResultLock(raw []byte) (Result, error) {
	var result Result
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return result, errors.New("external image acquisition lock byte size is invalid")
	}
	if err := decodeJSON(raw, &result, true); err != nil {
		return result, fmt.Errorf("decode external image acquisition lock: %w", err)
	}
	if err := validateResult(result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func VerifyOffline(spec Spec, layoutDir, lockPath string) (Result, error) {
	var empty Result
	if err := canonicalSpec(spec); err != nil {
		return empty, err
	}
	if !digestRE.MatchString(spec.ReleaseArtifactDigest) || !digestRE.MatchString(spec.PlanDigest) {
		return empty, errors.New("offline external image verification requires exact release and plan digests")
	}
	lockRaw, err := safeReadLayoutFile(filepath.Dir(lockPath), filepath.Base(lockPath), maxManifestBytes)
	if err != nil {
		return empty, fmt.Errorf("read external image acquisition lock safely: %w", err)
	}
	result, err := ParseResultLock(lockRaw)
	if err != nil {
		return empty, err
	}
	if result.Role != spec.Role || result.SourceRepository != spec.SourceRepository || result.RegistryEndpoint != spec.RegistryEndpoint || result.RegistryRepository != spec.RegistryRepo || result.SelectedVersion != spec.SelectedVersion || result.SourceTag != spec.Tag || result.SelectionChannel != spec.SelectionChannel || result.SelectionEvidenceURL != spec.SelectionEvidenceURL || result.ReleaseArtifactDigest != spec.ReleaseArtifactDigest || result.PlanDigest != spec.PlanDigest || result.PlatformOS != spec.OS || result.PlatformArch != spec.Architecture {
		return empty, errors.New("external image acquisition lock does not match exact release plan selection")
	}
	layoutRaw, err := safeReadLayoutFile(layoutDir, "oci-layout", maxManifestBytes)
	if err != nil {
		return empty, err
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err = decodeJSON(layoutRaw, &layout, true); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return empty, errors.New("external image OCI layout authority is invalid")
	}
	indexRaw, err := safeReadLayoutFile(layoutDir, "index.json", maxManifestBytes)
	if err != nil {
		return empty, err
	}
	var index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Platform  struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err = decodeJSON(indexRaw, &index, true); err != nil || index.SchemaVersion != 2 || index.MediaType != mediaOCIIndex || len(index.Manifests) != 1 {
		return empty, errors.New("external image OCI index authority is invalid")
	}
	idx := index.Manifests[0]
	if idx.Digest != result.ManifestDigest || idx.MediaType != result.ManifestMediaType || idx.Platform.OS != spec.OS || idx.Platform.Architecture != spec.Architecture || idx.Annotations["io.containerd.image.name"] != result.ExactReference || idx.Annotations["org.opencontainers.image.ref.name"] != result.ExactReference {
		return empty, errors.New("external image OCI index does not match acquisition lock")
	}
	rootRaw, err := readVerifiedLayoutBlob(layoutDir, result.TagRootDigest, result.TagRootBytes, maxManifestBytes)
	if err != nil {
		return empty, fmt.Errorf("verify acquisition tag-root evidence: %w", err)
	}
	manifestRaw := rootRaw
	manifestBytes := result.TagRootBytes
	if result.TagRootDigest != result.ManifestDigest {
		if result.TagRootMediaType != mediaOCIIndex && result.TagRootMediaType != mediaDockerList {
			return empty, errors.New("external image acquisition tag root is not a multi-platform index")
		}
		child, chooseErr := choosePlatform(rootRaw, spec.OS, spec.Architecture)
		if chooseErr != nil {
			return empty, fmt.Errorf("verify acquisition tag-root platform binding: %w", chooseErr)
		}
		if child.Digest != result.ManifestDigest || (child.MediaType != "" && child.MediaType != result.ManifestMediaType) {
			return empty, errors.New("external image acquisition tag root does not bind selected platform manifest")
		}
		manifestRaw, err = readVerifiedLayoutBlob(layoutDir, result.ManifestDigest, child.Size, maxManifestBytes)
		if err != nil {
			return empty, fmt.Errorf("verify selected platform manifest: %w", err)
		}
		manifestBytes = child.Size
	} else if result.TagRootMediaType != result.ManifestMediaType {
		return empty, errors.New("external image acquisition single-platform tag media type mismatch")
	}
	if int64(len(manifestRaw)) != idx.Size || idx.Size != manifestBytes {
		return empty, errors.New("external image OCI index manifest size does not match acquisition evidence")
	}
	manifest, err := parseManifest(manifestRaw, result.ManifestMediaType)
	if err != nil {
		return empty, fmt.Errorf("verify selected external image manifest: %w", err)
	}
	if manifest.Config.MediaType != result.Config.MediaType || manifest.Config.Digest != result.Config.Digest || manifest.Config.Size != result.Config.Size || len(manifest.Layers) != len(result.Layers) {
		return empty, errors.New("external image manifest/config does not match acquisition lock")
	}
	uniqueBytes := result.TagRootBytes
	if result.ManifestDigest != result.TagRootDigest {
		uniqueBytes += manifestBytes
	}
	allowed := map[string]bool{"oci-layout": true, "index.json": true}
	addBlob := func(digest string) { allowed["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")] = true }
	addBlob(result.TagRootDigest)
	addBlob(result.ManifestDigest)
	if _, err = readVerifiedLayoutBlob(layoutDir, result.Config.Digest, result.Config.Size, maxConfigBytes); err != nil {
		return empty, fmt.Errorf("verify external image config: %w", err)
	}
	addBlob(result.Config.Digest)
	uniqueBytes += result.Config.Size
	for i, layer := range manifest.Layers {
		expected := result.Layers[i]
		if layer.MediaType != expected.MediaType || layer.Digest != expected.Digest || layer.Size != expected.Size {
			return empty, fmt.Errorf("external image layer %d does not match acquisition lock", i)
		}
		if _, err = readVerifiedLayoutBlob(layoutDir, expected.Digest, expected.Size, maxLayerBytes); err != nil {
			return empty, fmt.Errorf("verify external image layer %d: %w", i, err)
		}
		addBlob(expected.Digest)
		uniqueBytes += expected.Size
	}
	if uniqueBytes != result.ReachableBytes {
		return empty, fmt.Errorf("external image acquisition byte accounting mismatch: lock=%d verified=%d", result.ReachableBytes, uniqueBytes)
	}
	rootAbs, err := filepath.Abs(layoutDir)
	if err != nil {
		return empty, err
	}
	err = filepath.WalkDir(rootAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(rootAbs, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("external OCI layout path %q is a symlink", rel)
		}
		if entry.IsDir() {
			if rel != "blobs" && rel != "blobs/sha256" {
				return fmt.Errorf("external OCI layout contains unowned directory %q", rel)
			}
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("external OCI layout path %q is not a regular file", rel)
		}
		if !allowed[rel] {
			return fmt.Errorf("external OCI layout contains unowned file %q", rel)
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}
