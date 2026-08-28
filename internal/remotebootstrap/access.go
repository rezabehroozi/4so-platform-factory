package remotebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/internal/installeraccess"
)

const bootstrapTokenRelativePath = "var/lib/4so-platform-installer/bootstrap-token"

type AccessHandoff struct {
	DeploymentID     string `json:"deploymentId"`
	Version          string `json:"version"`
	Ready            bool   `json:"ready"`
	TokenFingerprint string `json:"tokenFingerprint"`
}

// FetchBootstrapToken retrieves the already-created Installer bootstrap token over the
// same pinned, key-only SSH channel used by remote bootstrap. The token is returned to
// the caller only; it is never included in command arguments or metadata output.
func FetchBootstrapToken(ctx context.Context, specPath string, options Options) ([]byte, AccessHandoff, error) {
	loaded, err := loadAndValidate(specPath)
	if err != nil {
		return nil, AccessHandoff{}, err
	}
	if loaded.Root != "/" {
		return nil, AccessHandoff{}, errors.New("bootstrap access handoff requires a live target root /")
	}
	verification, err := Verify(ctx, specPath, options)
	if err != nil {
		return nil, AccessHandoff{}, fmt.Errorf("verify remote installer before access handoff: %w", err)
	}
	if !verification.Valid || verification.StagedOnly || !verification.Readiness.Ready {
		return nil, AccessHandoff{}, errors.New("remote installer is not a verified live ready deployment")
	}
	runner := options.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	sshBinary := options.SSHBinary
	if strings.TrimSpace(sshBinary) == "" {
		sshBinary = "ssh"
	}
	tokenPath := filepath.Join(loaded.Root, bootstrapTokenRelativePath)
	raw, err := runSSH(ctx, runner, sshBinary, loaded, nil, "cat -- "+shellQuote(tokenPath))
	if err != nil {
		return nil, AccessHandoff{}, fmt.Errorf("retrieve remote bootstrap token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if err = installeraccess.ValidateToken(token); err != nil {
		return nil, AccessHandoff{}, fmt.Errorf("validate retrieved bootstrap token: %w", err)
	}
	sum := sha256.Sum256([]byte(token))
	status := AccessHandoff{
		DeploymentID:     verification.DeploymentID,
		Version:          verification.Version,
		Ready:            true,
		TokenFingerprint: "sha256:" + hex.EncodeToString(sum[:])[:16],
	}
	return []byte(token + "\n"), status, nil
}
