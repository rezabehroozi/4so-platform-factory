package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/durablefile"
)

const sshHostTrustRotationAuthority = "SSH_HOST_KEY_ROTATION_AUTHORITY_V1"

type SSHHostTrustRotationRequest struct {
	Host                        string   `json:"host"`
	ExpectedCurrentFingerprints []string `json:"expectedCurrentFingerprints"`
	ReplacementKnownHosts       string   `json:"replacementKnownHosts"`
}

type SSHHostTrustRotationEvidence struct {
	Authority            string    `json:"authority"`
	ID                   string    `json:"id"`
	Host                 string    `json:"host"`
	PreviousFingerprints []string  `json:"previousFingerprints"`
	NewFingerprints      []string  `json:"newFingerprints"`
	PreviousTrustDigest  string    `json:"previousTrustDigest"`
	NewTrustDigest       string    `json:"newTrustDigest"`
	RotatedAt            time.Time `json:"rotatedAt"`
}

func (r *Runner) sshHostTrustRotationPath() string {
	return filepath.Join(r.stateDir, "evidence", "ssh-host-key-rotation.json")
}

func trustDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalFingerprintSet(entries []SSHHostTrustEntry, host string) []string {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	set := map[string]struct{}{}
	for _, entry := range entries {
		entryHost := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(entry.Host), "[]"), "."))
		if entryHost == host {
			set[entry.Fingerprint] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for fingerprint := range set {
		out = append(out, fingerprint)
	}
	sort.Strings(out)
	return out
}

func canonicalExpectedFingerprints(values []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !strings.HasPrefix(value, "SHA256:") || len(value) <= len("SHA256:") {
			return nil, fmt.Errorf("expected current host-key fingerprint %q is invalid", value)
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("expectedCurrentFingerprints must contain the currently trusted host-key fingerprint set")
	}
	return out, nil
}

func entryIdentity(entry SSHHostTrustEntry) string {
	return strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(entry.Host), "[]"), ".")) + "\x00" + entry.KeyType + "\x00" + entry.Fingerprint
}

func nonTargetEntrySet(entries []SSHHostTrustEntry, host string) []string {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		entryHost := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(entry.Host), "[]"), "."))
		if entryHost == host {
			continue
		}
		out = append(out, entryIdentity(entry))
	}
	sort.Strings(out)
	return out
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (r *Runner) LastSSHHostTrustRotation() (*SSHHostTrustRotationEvidence, error) {
	raw, err := os.ReadFile(r.sshHostTrustRotationPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var evidence SSHHostTrustRotationEvidence
	if err = json.Unmarshal(raw, &evidence); err != nil {
		return nil, fmt.Errorf("decode SSH host-key rotation evidence: %w", err)
	}
	if evidence.Authority != sshHostTrustRotationAuthority || strings.TrimSpace(evidence.ID) == "" || strings.TrimSpace(evidence.Host) == "" || evidence.RotatedAt.IsZero() {
		return nil, errors.New("SSH host-key rotation evidence is invalid")
	}
	return &evidence, nil
}

func (r *Runner) RotateSSHKnownHost(request SSHHostTrustRotationRequest) (SSHTrustStatus, SSHHostTrustRotationEvidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("%w: HA SSH host trust cannot rotate while bootstrap execution is active", ErrBootstrapExecutionActive)
	}
	host, err := normalizeKnownHostToken(request.Host)
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if err = validateSSHHost(host); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	expected, err := canonicalExpectedFingerprints(request.ExpectedCurrentFingerprints)
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	currentRaw, err := os.ReadFile(r.sshKnownHostsPath())
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("read current HA SSH trust before rotation: %w", err)
	}
	currentEntries, currentNormalized, err := parseSSHKnownHosts(currentRaw)
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	currentFingerprints := canonicalFingerprintSet(currentEntries, host)
	if len(currentFingerprints) == 0 {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("HA SSH host %s has no current pinned host key to rotate", host)
	}
	if !equalStrings(currentFingerprints, expected) {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("HA SSH host %s trust changed since operator review; expected fingerprints %v observed %v", host, expected, currentFingerprints)
	}
	replacementEntries, replacementNormalized, err := parseSSHKnownHosts([]byte(request.ReplacementKnownHosts))
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if !equalStrings(nonTargetEntrySet(currentEntries, host), nonTargetEntrySet(replacementEntries, host)) {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, errors.New("SSH host-key rotation may not add, remove or change trust for non-target peers")
	}
	newFingerprints := canonicalFingerprintSet(replacementEntries, host)
	if len(newFingerprints) == 0 {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("replacement trust has no pinned host key for %s", host)
	}
	if equalStrings(currentFingerprints, newFingerprints) {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, errors.New("replacement host-key fingerprint set is unchanged")
	}
	now := r.now().UTC()
	seed := strings.Join([]string{host, strings.Join(currentFingerprints, ","), strings.Join(newFingerprints, ","), now.Format(time.RFC3339Nano)}, "\n")
	idSum := sha256.Sum256([]byte(seed))
	evidence := SSHHostTrustRotationEvidence{
		Authority: sshHostTrustRotationAuthority,
		ID: "ssh-host-key-rotation-" + hex.EncodeToString(idSum[:10]),
		Host: host,
		PreviousFingerprints: currentFingerprints,
		NewFingerprints: newFingerprints,
		PreviousTrustDigest: trustDigest(currentNormalized),
		NewTrustDigest: trustDigest(replacementNormalized),
		RotatedAt: now,
	}
	evidenceRaw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if err = os.MkdirAll(filepath.Dir(r.sshHostTrustRotationPath()), 0o700); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if err = writePrivateFile(r.sshKnownHostsPath(), replacementNormalized); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if err = durablefile.Replace(r.sshHostTrustRotationPath(), append(evidenceRaw, '\n'), 0o700, 0o600); err != nil {
		// The trust store already changed. Fail closed and make the missing evidence
		// visible rather than pretending the rotation is fully authoritative.
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("persist SSH host-key rotation evidence after trust update: %w", err)
	}
	status := SSHTrustStatus{KnownHostsRef: sshKnownHostsRef, KnownHostsStored: true, Entries: replacementEntries, LastRotation: &evidence}
	if info, statErr := os.Stat(r.sshKeyPath()); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
		status.PrivateKeyStored = true
	}
	return status, evidence, nil
}
