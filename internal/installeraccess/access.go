package installeraccess

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"platform.4so.io/factory/internal/durablefile"
)

const (
	minimumTokenLength = 32
	tokenFileName      = "bootstrap-token"
)

type TokenSource string

const (
	TokenSourceEnvironment TokenSource = "environment"
	TokenSourceExisting    TokenSource = "existing-file"
	TokenSourceGenerated   TokenSource = "generated-file"
)

type TokenStatus struct {
	Authentication string      `json:"authentication"`
	Source         TokenSource `json:"source"`
	Fingerprint    string      `json:"fingerprint"`
	TokenFile      string      `json:"tokenFile"`
	RotatedAt      time.Time   `json:"rotatedAt"`
}

type LoadResult struct {
	Generated bool
	Status    TokenStatus
}

type Manager struct {
	mu        sync.RWMutex
	token     string
	tokenPath string
	source    TokenSource
	rotatedAt time.Time
}

func LoadOrCreate(stateDir, supplied string, now time.Time) (*Manager, LoadResult, error) {
	var empty LoadResult
	if strings.TrimSpace(stateDir) == "" {
		return nil, empty, errors.New("state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, empty, fmt.Errorf("create installer state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, empty, fmt.Errorf("secure installer state directory: %w", err)
	}
	path := filepath.Join(stateDir, tokenFileName)
	value := ""
	source := TokenSourceExisting
	generated := false
	raw, readErr := os.ReadFile(path)
	switch {
	case readErr == nil:
		// The private state file is authoritative after first initialization so a
		// stale environment seed cannot undo an explicit token rotation on restart.
		value = strings.TrimSpace(string(raw))
		source = TokenSourceExisting
	case errors.Is(readErr, os.ErrNotExist):
		value = strings.TrimSpace(supplied)
		if value != "" {
			source = TokenSourceEnvironment
		} else {
			var err error
			value, err = GenerateToken()
			if err != nil {
				return nil, empty, err
			}
			source = TokenSourceGenerated
			generated = true
		}
	default:
		return nil, empty, fmt.Errorf("read bootstrap token: %w", readErr)
	}
	if err := ValidateToken(value); err != nil {
		return nil, empty, err
	}
	if err := writePrivateAtomic(path, []byte(value+"\n")); err != nil {
		return nil, empty, fmt.Errorf("persist bootstrap token: %w", err)
	}
	rotatedAt := now.UTC()
	if info, err := os.Stat(path); err == nil {
		rotatedAt = info.ModTime().UTC()
	}
	manager := &Manager{token: value, tokenPath: path, source: source, rotatedAt: rotatedAt}
	return manager, LoadResult{Generated: generated, Status: manager.Status()}, nil
}

func ValidateToken(value string) error {
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("bootstrap token must be a single trimmed value")
	}
	if len(value) < minimumTokenLength {
		return fmt.Errorf("bootstrap token must contain at least %d characters", minimumTokenLength)
	}
	return nil
}

func GenerateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate bootstrap token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (m *Manager) VerifyAuthorization(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || strings.Count(header, " ") != 1 {
		return false
	}
	candidate := strings.TrimPrefix(header, prefix)
	m.mu.RLock()
	expected := m.token
	m.mu.RUnlock()
	if len(candidate) != len(expected) {
		// Compare fixed-length digests so the rejection path does not expose token length timing.
		candidateDigest := sha256.Sum256([]byte(candidate))
		expectedDigest := sha256.Sum256([]byte(expected))
		_ = subtle.ConstantTimeCompare(candidateDigest[:], expectedDigest[:])
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func (m *Manager) Rotate(newToken, confirmation string, now time.Time) (TokenStatus, error) {
	if confirmation != "ROTATE" {
		return TokenStatus{}, errors.New("confirmation must be exactly ROTATE")
	}
	if err := ValidateToken(newToken); err != nil {
		return TokenStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(newToken), []byte(m.token)) == 1 {
		return TokenStatus{}, errors.New("new bootstrap token must differ from the current token")
	}
	if err := writePrivateAtomic(m.tokenPath, []byte(newToken+"\n")); err != nil {
		return TokenStatus{}, fmt.Errorf("rotate bootstrap token: %w", err)
	}
	m.token = newToken
	m.source = TokenSourceExisting
	m.rotatedAt = now.UTC()
	return m.statusLocked(), nil
}

func (m *Manager) Status() TokenStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusLocked()
}

func (m *Manager) statusLocked() TokenStatus {
	digest := sha256.Sum256([]byte(m.token))
	return TokenStatus{
		Authentication: "bearer-token",
		Source:         m.source,
		Fingerprint:    "sha256:" + hex.EncodeToString(digest[:])[:16],
		TokenFile:      tokenFileName,
		RotatedAt:      m.rotatedAt,
	}
}

func writePrivateAtomic(path string, raw []byte) error {
	return durablefile.Replace(path, raw, 0o700, 0o600)
}

type AccessStatus struct {
	ProductVersion        string          `json:"productVersion,omitempty"`
	InstallerBinaryDigest string          `json:"installerBinaryDigest,omitempty"`
	Transport             TransportStatus `json:"transport"`
	Token                 TokenStatus     `json:"token"`
}

type TransportStatus struct {
	Mode                   string    `json:"mode"`
	Listen                 string    `json:"listen"`
	TransportProtected     bool      `json:"transportProtected"`
	LoopbackOnly           bool      `json:"loopbackOnly"`
	InsecureOverride       bool      `json:"insecureOverride"`
	CertificateFingerprint string    `json:"certificateFingerprint,omitempty"`
	CertificateNotBefore   time.Time `json:"certificateNotBefore,omitempty"`
	CertificateNotAfter    time.Time `json:"certificateNotAfter,omitempty"`
	CertificateDNSNames    []string  `json:"certificateDnsNames,omitempty"`
}

func ValidateTransport(listen, certFile, keyFile string, allowInsecure bool, now time.Time) (TransportStatus, error) {
	status := TransportStatus{Listen: strings.TrimSpace(listen)}
	if status.Listen == "" {
		return status, errors.New("installer listen address is required")
	}
	host, _, err := net.SplitHostPort(status.Listen)
	if err != nil {
		return status, fmt.Errorf("invalid installer listen address: %w", err)
	}
	loopback := isLoopbackHost(host)
	status.LoopbackOnly = loopback
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" && keyFile == "" {
		if loopback {
			status.Mode = "http-loopback"
			return status, nil
		}
		if !allowInsecure {
			return status, errors.New("non-loopback installer access requires TLS certificate/key; set PLATFORM_INSTALLER_TLS_CERT_FILE and PLATFORM_INSTALLER_TLS_KEY_FILE")
		}
		status.Mode = "http-insecure-override"
		status.InsecureOverride = true
		return status, nil
	}
	if certFile == "" || keyFile == "" {
		return status, errors.New("both installer TLS certificate and key files are required")
	}
	if info, statErr := os.Stat(keyFile); statErr != nil {
		return status, fmt.Errorf("stat installer TLS key: %w", statErr)
	} else if info.Mode().Perm()&0o077 != 0 {
		return status, fmt.Errorf("installer TLS key permissions must not allow group/other access: got %04o", info.Mode().Perm())
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return status, fmt.Errorf("load installer TLS certificate/key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return status, errors.New("installer TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return status, fmt.Errorf("parse installer TLS certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return status, fmt.Errorf("installer TLS certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return status, fmt.Errorf("installer TLS certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	status.Mode = "https"
	status.TransportProtected = true
	status.CertificateFingerprint = "sha256:" + hex.EncodeToString(fingerprint[:])
	status.CertificateNotBefore = leaf.NotBefore.UTC()
	status.CertificateNotAfter = leaf.NotAfter.UTC()
	status.CertificateDNSNames = append([]string(nil), leaf.DNSNames...)
	return status, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
