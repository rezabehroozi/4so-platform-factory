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

const (
	sshHostTrustRotationAuthority = "SSH_HOST_KEY_ROTATION_AUTHORITY_V1"
	sshHostTrustRotationJournalAuthority = "SSH_HOST_KEY_ROTATION_JOURNAL_V1"
	sshHostTrustRotationPrepared = "PREPARED"
	sshHostTrustRotationSucceeded = "SUCCEEDED"
	sshHostTrustRotationAborted = "ABORTED"
)

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

type sshHostTrustRotationJournal struct {
	Authority string                       `json:"authority"`
	State     string                       `json:"state"`
	Evidence  SSHHostTrustRotationEvidence `json:"evidence"`
	UpdatedAt time.Time                    `json:"updatedAt"`
}

func (r *Runner) sshHostTrustRotationPath() string {
	return filepath.Join(r.stateDir, "evidence", "ssh-host-key-rotation.json")
}

func (r *Runner) sshHostTrustRotationJournalPath() string {
	return filepath.Join(r.stateDir, "evidence", "ssh-host-key-rotation-journal.json")
}

func (r *Runner) writeSSHHostTrustRotationEvidence(evidence SSHHostTrustRotationEvidence) error {
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return durablefile.Replace(r.sshHostTrustRotationPath(), append(raw, '\n'), 0o700, 0o600)
}

func (r *Runner) writeSSHHostTrustRotationJournal(journal sshHostTrustRotationJournal) error {
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return durablefile.Replace(r.sshHostTrustRotationJournalPath(), append(raw, '\n'), 0o700, 0o600)
}

func (r *Runner) loadSSHHostTrustRotationJournal() (*sshHostTrustRotationJournal, error) {
	raw, err := os.ReadFile(r.sshHostTrustRotationJournalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var journal sshHostTrustRotationJournal
	if err = json.Unmarshal(raw, &journal); err != nil {
		return nil, fmt.Errorf("decode SSH host-key rotation journal: %w", err)
	}
	if journal.Authority != sshHostTrustRotationJournalAuthority || journal.Evidence.Authority != sshHostTrustRotationAuthority || strings.TrimSpace(journal.Evidence.ID) == "" {
		return nil, errors.New("SSH host-key rotation journal is invalid")
	}
	switch journal.State {
	case sshHostTrustRotationPrepared, sshHostTrustRotationSucceeded, sshHostTrustRotationAborted:
	default:
		return nil, fmt.Errorf("SSH host-key rotation journal has invalid state %q", journal.State)
	}
	return &journal, nil
}

func (r *Runner) reconcileSSHHostTrustRotation() error {
	journal, err := r.loadSSHHostTrustRotationJournal()
	if err != nil || journal == nil || journal.State != sshHostTrustRotationPrepared {
		return err
	}
	raw, err := os.ReadFile(r.sshKnownHostsPath())
	if err != nil {
		return fmt.Errorf("read HA SSH trust while reconciling host-key rotation: %w", err)
	}
	_, normalized, err := parseSSHKnownHosts(raw)
	if err != nil {
		return err
	}
	observed := trustDigest(normalized)
	journal.UpdatedAt = r.now().UTC()
	switch observed {
	case journal.Evidence.NewTrustDigest:
		if err = r.writeSSHHostTrustRotationEvidence(journal.Evidence); err != nil {
			return fmt.Errorf("finalize applied SSH host-key rotation evidence: %w", err)
		}
		journal.State = sshHostTrustRotationSucceeded
		return r.writeSSHHostTrustRotationJournal(*journal)
	case journal.Evidence.PreviousTrustDigest:
		journal.State = sshHostTrustRotationAborted
		return r.writeSSHHostTrustRotationJournal(*journal)
	default:
		return fmt.Errorf("SSH host-key rotation outcome is ambiguous: trust digest %s matches neither accepted previous nor replacement authority", observed)
	}
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

func equalTrustSlices(left, right []string) bool {
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
	if err := r.reconcileSSHHostTrustRotation(); err != nil {
		return nil, err
	}
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
	if err := r.reconcileSSHHostTrustRotation(); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
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
	if !equalTrustSlices(currentFingerprints, expected) {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("HA SSH host %s trust changed since operator review; expected fingerprints %v observed %v", host, expected, currentFingerprints)
	}
	replacementEntries, replacementNormalized, err := parseSSHKnownHosts([]byte(request.ReplacementKnownHosts))
	if err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if !equalTrustSlices(nonTargetEntrySet(currentEntries, host), nonTargetEntrySet(replacementEntries, host)) {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, errors.New("SSH host-key rotation may not add, remove or change trust for non-target peers")
	}
	newFingerprints := canonicalFingerprintSet(replacementEntries, host)
	if len(newFingerprints) == 0 {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("replacement trust has no pinned host key for %s", host)
	}
	if equalTrustSlices(currentFingerprints, newFingerprints) {
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
	journal := sshHostTrustRotationJournal{
		Authority: sshHostTrustRotationJournalAuthority,
		State: sshHostTrustRotationPrepared,
		Evidence: evidence,
		UpdatedAt: now,
	}
	if err = r.writeSSHHostTrustRotationJournal(journal); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, fmt.Errorf("persist SSH host-key rotation intent: %w", err)
	}
	if err = writePrivateFile(r.sshKnownHostsPath(), replacementNormalized); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	if err = r.reconcileSSHHostTrustRotation(); err != nil {
		return SSHTrustStatus{}, SSHHostTrustRotationEvidence{}, err
	}
	status := SSHTrustStatus{KnownHostsRef: sshKnownHostsRef, KnownHostsStored: true, Entries: replacementEntries, LastRotation: &evidence}
	if info, statErr := os.Stat(r.sshKeyPath()); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
		status.PrivateKeyStored = true
	}
	return status, evidence, nil
}
