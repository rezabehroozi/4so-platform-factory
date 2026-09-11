package releaseartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	PlatformctlBinaryPath                       = "bin/linux-amd64/platformctl"
	PlatformctlExactReleaseSelfBindingAuthority = "PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1"
)

// RunningExecutableDigest hashes the inode that is actually executing this
// process on Linux. Reading /proc/self/exe is intentional: hashing the launch
// pathname would allow that pathname to be replaced after exec while the
// process continued to execute different, already-mapped bytes.
func RunningExecutableDigest() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("open running executable identity: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat running executable identity: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 {
		return "", errors.New("running executable identity is not a non-empty regular file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return "", fmt.Errorf("hash running executable identity: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("restat running executable identity: %w", err)
	}
	if !os.SameFile(before, after) || written != before.Size() || after.Size() != before.Size() {
		return "", errors.New("running executable identity changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// RequireRunningExecutable verifies that the inode currently executing this
// process has exactly the digest recorded for archivePath in the inspected
// exact release. The returned digest is safe to persist in certification
// evidence after equality is established.
func (i Inspection) RequireRunningExecutable(archivePath string) (string, error) {
	expected, err := i.FileDigest(archivePath)
	if err != nil {
		return "", err
	}
	actual, err := RunningExecutableDigest()
	if err != nil {
		return "", err
	}
	if actual != expected {
		return "", fmt.Errorf("running executable digest %s does not match exact release %s digest %s", actual, archivePath, expected)
	}
	return actual, nil
}
