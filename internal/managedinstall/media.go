package managedinstall

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MediaStoreAuthority = "MANAGED_OKD_CONTENT_ADDRESSED_MEDIA_V1"
const mediaRoutePrefix = "/managed-install-media/sha256/"

type MediaURLResolver interface {
	ResolveAgentISOMediaURL(context.Context, Request, Artifact, string) (string, error)
}

type MediaStore struct {
	Root       string
	PublicBase string
	SigningKey []byte
	TTL        time.Duration
	Now        func() time.Time
}

func normalizeDigest(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != 64 {
		return "", errors.New("sha256 digest must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("sha256 digest is not hexadecimal")
	}
	return value, nil
}

func secureMediaRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", errors.New("managed install media root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("managed install media root must be a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("managed install media root must not be group/world writable")
	}
	return abs, nil
}

func (m *MediaStore) validate() (string, *url.URL, error) {
	root, err := secureMediaRoot(m.Root)
	if err != nil {
		return "", nil, err
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(m.PublicBase), "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", nil, errors.New("managed install media public base must be an HTTPS URL without credentials/query/fragment")
	}
	if len(m.SigningKey) < 32 {
		return "", nil, errors.New("managed install media signing key must contain at least 32 bytes")
	}
	return root, base, nil
}

func (m *MediaStore) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *MediaStore) ttl() time.Duration {
	if m.TTL <= 0 {
		return 6 * time.Hour
	}
	if m.TTL > 24*time.Hour {
		return 24 * time.Hour
	}
	return m.TTL
}

func mediaOperationBinding(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (m *MediaStore) sign(digest string, expires int64, binding string) string {
	mac := hmac.New(sha256.New, m.SigningKey)
	_, _ = io.WriteString(mac, MediaStoreAuthority+"\x00"+digest+"\x00"+strconv.FormatInt(expires, 10)+"\x00"+binding)
	return hex.EncodeToString(mac.Sum(nil))
}

func secureOpenMedia(path, expectedDigest string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, errors.New("managed install media must be a regular file")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !hmac.Equal([]byte(got), []byte(expectedDigest)) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("managed install media digest mismatch: got sha256:%s", got)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func mediaPath(root, digest string) string {
	return filepath.Join(root, "sha256", digest, "agent.iso")
}

func (m *MediaStore) ResolveAgentISOMediaURL(_ context.Context, req Request, artifact Artifact, operationToken string) (string, error) {
	root, base, err := m.validate()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(operationToken) == "" {
		return "", errors.New("managed install operation token is required for media URL")
	}
	if artifact.Name != "agent-iso" {
		return "", errors.New("content-addressed media resolver accepts only agent-iso")
	}
	if err := ValidateRequest(req); err != nil {
		return "", err
	}
	digest, err := normalizeDigest(artifact.SHA256)
	if err != nil {
		return "", err
	}
	f, _, err := secureOpenMedia(mediaPath(root, digest), digest)
	if err != nil {
		return "", fmt.Errorf("verify staged agent ISO: %w", err)
	}
	_ = f.Close()
	issued := m.now()
	if at := strings.LastIndex(operationToken, "@"); at > 0 {
		if unix, parseErr := strconv.ParseInt(operationToken[at+1:], 10, 64); parseErr == nil && unix > 0 {
			candidate := time.Unix(unix, 0).UTC()
			if !candidate.After(m.now().Add(5 * time.Minute)) {
				issued = candidate
			}
		}
	}
	expires := issued.Add(m.ttl()).Unix()
	binding := mediaOperationBinding(operationToken)
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + mediaRoutePrefix + digest + "/agent.iso"
	q := u.Query()
	q.Set("expires", strconv.FormatInt(expires, 10))
	q.Set("op", binding)
	q.Set("sig", m.sign(digest, expires, binding))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (m *MediaStore) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root, _, err := m.validate()
		if err != nil {
			http.Error(w, "media service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, mediaRoutePrefix)
		parts := strings.Split(path, "/")
		if len(parts) != 2 || parts[1] != "agent.iso" {
			http.NotFound(w, r)
			return
		}
		digest, err := normalizeDigest(parts[0])
		if err != nil || digest != parts[0] {
			http.NotFound(w, r)
			return
		}
		expires, err := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
		if err != nil || expires <= m.now().Unix() || expires > m.now().Add(24*time.Hour).Unix() {
			http.Error(w, "media URL expired or invalid", http.StatusForbidden)
			return
		}
		binding := strings.TrimSpace(r.URL.Query().Get("op"))
		provided, err := hex.DecodeString(strings.TrimSpace(r.URL.Query().Get("sig")))
		if err != nil || len(binding) != 64 {
			http.Error(w, "media URL signature invalid", http.StatusForbidden)
			return
		}
		expected, _ := hex.DecodeString(m.sign(digest, expires, binding))
		if !hmac.Equal(provided, expected) {
			http.Error(w, "media URL signature invalid", http.StatusForbidden)
			return
		}
		f, info, err := secureOpenMedia(mediaPath(root, digest), digest)
		if err != nil {
			http.Error(w, "media integrity check failed", http.StatusConflict)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "private, max-age=0, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("ETag", `"sha256:`+digest+`"`)
		http.ServeContent(w, r, "agent.iso", info.ModTime(), f)
	})
}

func (m *MediaStore) Validate() error {
	_, _, err := m.validate()
	return err
}
