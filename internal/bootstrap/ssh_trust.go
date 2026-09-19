package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/durablefile"
)

const (
	sshCredentialRef = "secret://installer/ssh-private-key"
	sshKnownHostsRef = "trust://installer/ssh-known-hosts"
)

var sshUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)

type SSHHostTrustEntry struct {
	Host        string `json:"host"`
	KeyType     string `json:"keyType"`
	Fingerprint string `json:"fingerprint"`
}

type SSHTrustStatus struct {
	PrivateKeyStored bool                             `json:"privateKeyStored"`
	KnownHostsStored bool                             `json:"knownHostsStored"`
	KnownHostsRef    string                           `json:"knownHostsRef,omitempty"`
	Entries          []SSHHostTrustEntry              `json:"entries,omitempty"`
	LastRotation     *SSHHostTrustRotationEvidence    `json:"lastRotation,omitempty"`
}

func (r *Runner) sshKeyPath() string { return filepath.Join(r.stateDir, "secrets", "ssh-private-key") }
func (r *Runner) sshKnownHostsPath() string {
	return filepath.Join(r.stateDir, "secrets", "ssh-known-hosts")
}

func (r *Runner) StoreSSHPrivateKey(raw []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return fmt.Errorf("%w: HA SSH private key cannot change while bootstrap execution is active", ErrBootstrapExecutionActive)
	}
	value := strings.TrimSpace(string(raw))
	if !strings.Contains(value, "PRIVATE KEY") {
		return fmt.Errorf("SSH private key format is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(r.sshKeyPath()), 0o700); err != nil {
		return err
	}
	return writePrivateFile(r.sshKeyPath(), []byte(value+"\n"))
}

func (r *Runner) StoreSSHKnownHosts(raw []byte) (SSHTrustStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return SSHTrustStatus{}, fmt.Errorf("%w: HA SSH host trust cannot change while bootstrap execution is active", ErrBootstrapExecutionActive)
	}
	if err := r.reconcileSSHHostTrustRotation(); err != nil {
		return SSHTrustStatus{}, err
	}
	entries, normalized, err := parseSSHKnownHosts(raw)
	if err != nil {
		return SSHTrustStatus{}, err
	}
	if err = os.MkdirAll(filepath.Dir(r.sshKnownHostsPath()), 0o700); err != nil {
		return SSHTrustStatus{}, err
	}
	if err = writePrivateFile(r.sshKnownHostsPath(), normalized); err != nil {
		return SSHTrustStatus{}, err
	}
	status, err := r.SSHTrustStatus()
	if err != nil {
		return SSHTrustStatus{}, err
	}
	status.Entries = entries
	return status, nil
}

func (r *Runner) SSHTrustStatus() (SSHTrustStatus, error) {
	status := SSHTrustStatus{KnownHostsRef: sshKnownHostsRef}
	if info, err := os.Stat(r.sshKeyPath()); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return status, errors.New("HA SSH private key must be a regular mode-0600 file")
		}
		status.PrivateKeyStored = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return status, err
	}
	raw, err := os.ReadFile(r.sshKnownHostsPath())
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	info, err := os.Stat(r.sshKnownHostsPath())
	if err != nil {
		return status, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return status, errors.New("HA SSH known-hosts trust store must be a regular mode-0600 file")
	}
	entries, _, err := parseSSHKnownHosts(raw)
	if err != nil {
		return status, err
	}
	status.KnownHostsStored = true
	status.Entries = entries
	rotation, err := r.LastSSHHostTrustRotation()
	if err != nil {
		return status, err
	}
	status.LastRotation = rotation
	return status, nil
}

func writePrivateFile(path string, data []byte) error {
	return durablefile.Replace(path, data, 0o700, 0o600)
}

func parseSSHKnownHosts(raw []byte) ([]SSHHostTrustEntry, []byte, error) {
	seenLines := map[string]struct{}{}
	seenEntries := map[string]struct{}{}
	var lines []string
	var entries []SSHHostTrustEntry
	for number, original := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(original)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@") {
			return nil, nil, fmt.Errorf("known_hosts line %d uses an unsupported marker", number+1)
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, nil, fmt.Errorf("known_hosts line %d is incomplete", number+1)
		}
		hostField, keyType, encoded := fields[0], fields[1], fields[2]
		if strings.HasPrefix(hostField, "|") || strings.ContainsAny(hostField, "*!?") {
			return nil, nil, fmt.Errorf("known_hosts line %d must use explicit hostnames or IP addresses without hashes or wildcards", number+1)
		}
		if !supportedSSHHostKeyType(keyType) {
			return nil, nil, fmt.Errorf("known_hosts line %d uses unsupported host key type %q", number+1, keyType)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) < 16 {
			return nil, nil, fmt.Errorf("known_hosts line %d contains invalid key data", number+1)
		}
		sum := sha256.Sum256(key)
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		for _, host := range strings.Split(hostField, ",") {
			host, err = normalizeKnownHostToken(host)
			if err != nil {
				return nil, nil, fmt.Errorf("known_hosts line %d: %w", number+1, err)
			}
			if err = validateSSHHost(host); err != nil {
				return nil, nil, fmt.Errorf("known_hosts line %d: %w", number+1, err)
			}
			entryKey := host + "\x00" + keyType + "\x00" + fingerprint
			if _, exists := seenEntries[entryKey]; !exists {
				seenEntries[entryKey] = struct{}{}
				entries = append(entries, SSHHostTrustEntry{Host: host, KeyType: keyType, Fingerprint: fingerprint})
			}
		}
		normalized := hostField + " " + keyType + " " + encoded
		if _, exists := seenLines[normalized]; !exists {
			seenLines[normalized] = struct{}{}
			lines = append(lines, normalized)
		}
	}
	if len(entries) == 0 {
		return nil, nil, errors.New("known_hosts trust store must contain at least one supported host key")
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Host != entries[j].Host {
			return entries[i].Host < entries[j].Host
		}
		if entries[i].KeyType != entries[j].KeyType {
			return entries[i].KeyType < entries[j].KeyType
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
	sort.Strings(lines)
	return entries, []byte(strings.Join(lines, "\n") + "\n"), nil
}

func normalizeKnownHostToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end <= 1 {
			return "", fmt.Errorf("known_hosts host %q is invalid", value)
		}
		suffix := value[end+1:]
		if suffix != "" && suffix != ":22" {
			return "", fmt.Errorf("known_hosts host %q uses unsupported SSH port; only port 22 is supported", value)
		}
		value = value[1:end]
	}
	value = strings.TrimSuffix(value, ".")
	return value, nil
}

func supportedSSHHostKeyType(value string) bool {
	switch value {
	case "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa":
		return true
	default:
		return false
	}
}

func normalizeSSHUser(user string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return "root"
	}
	return user
}

func validateSSHUser(user string) error {
	user = normalizeSSHUser(user)
	if !sshUserPattern.MatchString(user) {
		return fmt.Errorf("SSH user %q is invalid", user)
	}
	return nil
}

func validateSSHHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/@\\") {
		return fmt.Errorf("SSH host %q is invalid", host)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return nil
	}
	candidate := strings.TrimSuffix(host, ".")
	if candidate == "" {
		return fmt.Errorf("SSH host %q is invalid", host)
	}
	for _, label := range strings.Split(candidate, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("SSH host %q is invalid", host)
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("SSH host %q is invalid", host)
		}
	}
	return nil
}

// ParseSSHKnownHosts validates an explicit, non-hashed OpenSSH known_hosts payload.
// It is shared by HA bootstrap and remote installer bootstrap so both trust paths
// enforce the same host-key pinning contract.
func ParseSSHKnownHosts(raw []byte) ([]SSHHostTrustEntry, []byte, error) {
	return parseSSHKnownHosts(raw)
}

// NormalizeSSHUser applies the product default SSH user.
func NormalizeSSHUser(user string) string { return normalizeSSHUser(user) }

// ValidateSSHUser validates an SSH username without invoking a shell.
func ValidateSSHUser(user string) error { return validateSSHUser(user) }

// ValidateSSHHost validates a literal hostname or IP address suitable for SSH.
func ValidateSSHHost(host string) error { return validateSSHHost(host) }

func (r *Runner) validateSSHIdentity(ref, user string) error {
	if strings.TrimSpace(ref) != sshCredentialRef {
		return fmt.Errorf("HA bootstrap requires credentialRef %s", sshCredentialRef)
	}
	if err := validateSSHUser(user); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	info, err := os.Stat(r.sshKeyPath())
	if err != nil {
		return fmt.Errorf("HA SSH private key is not available: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("HA SSH private key permissions must be 0600")
	}
	return nil
}

func (r *Runner) validateSSHHostTrust(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("HA SSH host trust requires at least one remote peer")
	}
	for _, host := range hosts {
		if err := validateSSHHost(host); err != nil {
			return err
		}
	}
	if r.simulation {
		return nil
	}
	raw, err := os.ReadFile(r.sshKnownHostsPath())
	if err != nil {
		return fmt.Errorf("HA SSH pinned host trust is not available: %w", err)
	}
	info, err := os.Stat(r.sshKnownHostsPath())
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("HA SSH known-hosts trust store permissions must be 0600")
	}
	entries, _, err := parseSSHKnownHosts(raw)
	if err != nil {
		return err
	}
	covered := map[string]bool{}
	for _, entry := range entries {
		covered[strings.ToLower(strings.TrimSuffix(entry.Host, "."))] = true
	}
	for _, host := range hosts {
		canonical := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
		if !covered[canonical] {
			return fmt.Errorf("HA SSH host %s has no pinned host key", host)
		}
	}
	return nil
}
