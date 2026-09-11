package managedinstall

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const WorkspaceRuntimeAuthority = "MANAGED_OKD_EXACT_WORKSPACE_RUNTIME_V1"
const WorkspaceDescriptorAuthority = "MANAGED_OKD_INSTALL_WORKSPACE_V1"
const DisconnectedMirrorAuthority = "DISCONNECTED_OKD_MIRROR_RUNTIME_V1"
const DisconnectedMirrorInventoryAuthority = "DISCONNECTED_OKD_MIRROR_INVENTORY_V1"

type WorkspaceRuntimeConfig struct {
	WorkspaceRoot              string
	WorkRoot                   string
	OpenShiftInstall           string
	OpenShiftInstallSHA        string
	OC                         string
	OCSHA                      string
	OCMirror                   string
	OCMirrorSHA                string
	DisconnectedMirrorRegistry string
	InstallTimeout             time.Duration
	CommandTimeout             time.Duration
}

type WorkspaceRuntime struct {
	Config WorkspaceRuntimeConfig
}

type WorkspaceDescriptor struct {
	Authority          string `json:"authority"`
	RequestDigest      string `json:"requestDigest"`
	OrganizationID     string `json:"organizationId"`
	ProjectID          string `json:"projectId"`
	ClusterName        string `json:"clusterName"`
	TargetVersion      string `json:"targetVersion"`
	ReleasePayloadSHA  string `json:"releasePayloadSha256"`
	FCOSSHA            string `json:"fcosSha256"`
	AgentISOSHA        string `json:"agentIsoSha256"`
	PreparedBy         string `json:"preparedBy"`
	PreparationVersion string `json:"preparationVersion"`
}

func secureDir(path string, secretBearing bool) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("secure directory path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%s must be a real directory", abs)
	}
	mask := os.FileMode(0o022)
	if secretBearing {
		mask = 0o077
	}
	if info.Mode().Perm()&mask != 0 {
		return "", fmt.Errorf("%s has unsafe permissions %o", abs, info.Mode().Perm())
	}
	return abs, nil
}

func normalizeExpectedDigest(value string) (string, error) {
	return normalizeDigest(value)
}

func secureOpenRegular(path string, secretBearing bool) (*os.File, os.FileInfo, error) {
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
		return nil, nil, errors.New("path is not a regular file")
	}
	mask := os.FileMode(0o022)
	if secretBearing {
		mask = 0o077
	}
	if info.Mode().Perm()&mask != 0 {
		_ = f.Close()
		return nil, nil, fmt.Errorf("file has unsafe permissions %o", info.Mode().Perm())
	}
	return f, info, nil
}

func hashOpenFile(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifiedBinary(path, expected string) (*os.File, os.FileInfo, string, error) {
	expected, err := normalizeExpectedDigest(expected)
	if err != nil {
		return nil, nil, "", err
	}
	f, info, err := secureOpenRegular(path, false)
	if err != nil {
		return nil, nil, "", err
	}
	if info.Mode().Perm()&0o111 == 0 {
		_ = f.Close()
		return nil, nil, "", errors.New("configured executable is not executable")
	}
	got, err := hashOpenFile(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, "", err
	}
	if !hmac.Equal([]byte(got), []byte(expected)) {
		_ = f.Close()
		return nil, nil, "", fmt.Errorf("executable digest mismatch: got sha256:%s", got)
	}
	return f, info, got, nil
}

func copyVerifiedExecutable(srcPath, expectedDigest, dstPath string) (string, error) {
	src, _, digest, err := verifiedBinary(srcPath, expectedDigest)
	if err != nil {
		return "", err
	}
	defer src.Close()
	if existing, _, openErr := secureOpenRegular(dstPath, false); openErr == nil {
		got, hashErr := hashOpenFile(existing)
		_ = existing.Close()
		if hashErr == nil && hmac.Equal([]byte(got), []byte(digest)) {
			return digest, nil
		}
		return "", errors.New("existing operation executable copy does not match configured digest")
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return "", openErr
	}
	tmp := dstPath + ".tmp"
	_ = os.Remove(tmp)
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o500)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(dst, src)
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		if copyErr != nil {
			return "", copyErr
		}
		if syncErr != nil {
			return "", syncErr
		}
		return "", closeErr
	}
	if err = os.Chmod(tmp, 0o500); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err = os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return digest, nil
}

func operationWorkKey(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (r *WorkspaceRuntime) Validate() error {
	if r == nil {
		return errors.New("managed OKD workspace runtime is nil")
	}
	if _, err := secureDir(r.Config.WorkspaceRoot, true); err != nil {
		return fmt.Errorf("workspace root: %w", err)
	}
	if _, err := secureDir(r.Config.WorkRoot, true); err != nil {
		return fmt.Errorf("work root: %w", err)
	}
	for label, pair := range map[string][2]string{
		"openshift-install": {r.Config.OpenShiftInstall, r.Config.OpenShiftInstallSHA},
		"oc":                {r.Config.OC, r.Config.OCSHA},
	} {
		f, _, _, err := verifiedBinary(pair[0], pair[1])
		if err != nil {
			return fmt.Errorf("%s exact binary: %w", label, err)
		}
		_ = f.Close()
	}
	return nil
}

func (r *WorkspaceRuntime) ValidateDisconnected() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.Config.OCMirror) == "" || strings.TrimSpace(r.Config.OCMirrorSHA) == "" {
		return errors.New("exact oc-mirror v2 binary path and SHA-256 are required")
	}
	f, _, _, err := verifiedBinary(r.Config.OCMirror, r.Config.OCMirrorSHA)
	if err != nil {
		return fmt.Errorf("oc-mirror exact binary: %w", err)
	}
	_ = f.Close()
	cfg := DisconnectedConfig{MirrorRegistry: strings.TrimSpace(r.Config.DisconnectedMirrorRegistry), ImageSetConfigurationSHA256: "sha256:" + strings.Repeat("0", 64), MirrorInventorySHA256: "sha256:" + strings.Repeat("0", 64)}
	if err := validateDisconnectedConfig(cfg); err != nil {
		return fmt.Errorf("disconnected mirror registry: %w", err)
	}
	return nil
}

type disconnectedMirrorInventoryFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type disconnectedMirrorInventory struct {
	Authority string                            `json:"authority"`
	Files     []disconnectedMirrorInventoryFile `json:"files"`
}

func workspacePath(root string, req Request) (string, string, error) {
	digest, err := DigestRequest(req)
	if err != nil {
		return "", "", err
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(root, "sha256", hexDigest), digest, nil
}

func artifactDigest(req Request, name string) string {
	a, ok := ArtifactByName(req, name)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(a.SHA256))
}

func validateWorkspaceTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace symlink is forbidden: %s", path)
		}
		if entry.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("workspace directory is group/world accessible: %s", path)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("workspace contains special file: %s", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("workspace file is group/world accessible: %s", path)
		}
		return nil
	})
}

func loadWorkspaceDescriptor(workspace string, req Request, requestDigest string) (WorkspaceDescriptor, error) {
	f, _, err := secureOpenRegular(filepath.Join(workspace, "workspace.json"), true)
	if err != nil {
		return WorkspaceDescriptor{}, fmt.Errorf("open workspace descriptor: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 128<<10))
	dec.DisallowUnknownFields()
	var d WorkspaceDescriptor
	if err := dec.Decode(&d); err != nil {
		return WorkspaceDescriptor{}, fmt.Errorf("decode workspace descriptor: %w", err)
	}
	if d.Authority != WorkspaceDescriptorAuthority || d.RequestDigest != requestDigest || d.OrganizationID != req.OrganizationID || d.ProjectID != req.ProjectID || d.ClusterName != req.ClusterName || d.TargetVersion != req.TargetVersion {
		return WorkspaceDescriptor{}, errors.New("workspace descriptor identity does not match sealed managed install request")
	}
	if strings.ToLower(d.ReleasePayloadSHA) != artifactDigest(req, "release-payload") || strings.ToLower(d.FCOSSHA) != artifactDigest(req, "fcos") || strings.ToLower(d.AgentISOSHA) != artifactDigest(req, "agent-iso") {
		return WorkspaceDescriptor{}, errors.New("workspace descriptor artifact digests do not match sealed managed install request")
	}
	if strings.TrimSpace(d.PreparedBy) == "" || strings.TrimSpace(d.PreparationVersion) == "" {
		return WorkspaceDescriptor{}, errors.New("workspace descriptor preparation identity is incomplete")
	}
	return d, nil
}

func (r *WorkspaceRuntime) operationPaths(req Request, operationToken string) (workspace, workDir, installBin, ocBin, requestDigest string, err error) {
	workspaceRoot, err := secureDir(r.Config.WorkspaceRoot, true)
	if err != nil {
		return "", "", "", "", "", err
	}
	workRoot, err := secureDir(r.Config.WorkRoot, true)
	if err != nil {
		return "", "", "", "", "", err
	}
	workspace, requestDigest, err = workspacePath(workspaceRoot, req)
	if err != nil {
		return "", "", "", "", "", err
	}
	if _, err = secureDir(workspace, true); err != nil {
		return "", "", "", "", "", fmt.Errorf("exact install workspace is unavailable: %w", err)
	}
	if err = validateWorkspaceTree(workspace); err != nil {
		return "", "", "", "", "", err
	}
	if _, err = loadWorkspaceDescriptor(workspace, req, requestDigest); err != nil {
		return "", "", "", "", "", err
	}
	if strings.TrimSpace(operationToken) == "" {
		return "", "", "", "", "", errors.New("operation token is required")
	}
	workDir = filepath.Join(workRoot, "sha256", operationWorkKey(operationToken))
	if err = os.MkdirAll(workDir, 0o700); err != nil {
		return "", "", "", "", "", err
	}
	if err = os.Chmod(workDir, 0o700); err != nil {
		return "", "", "", "", "", err
	}
	if _, err = secureDir(workDir, true); err != nil {
		return "", "", "", "", "", err
	}
	installBin = filepath.Join(workDir, "openshift-install")
	ocBin = filepath.Join(workDir, "oc")
	if _, err = copyVerifiedExecutable(r.Config.OpenShiftInstall, r.Config.OpenShiftInstallSHA, installBin); err != nil {
		return "", "", "", "", "", fmt.Errorf("stage exact openshift-install: %w", err)
	}
	if _, err = copyVerifiedExecutable(r.Config.OC, r.Config.OCSHA, ocBin); err != nil {
		return "", "", "", "", "", fmt.Errorf("stage exact oc: %w", err)
	}
	return workspace, workDir, installBin, ocBin, requestDigest, nil
}

func sanitizedCommandEnv() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		name := item
		if at := strings.IndexByte(item, '='); at >= 0 {
			name = item[:at]
		}
		switch strings.ToUpper(strings.TrimSpace(name)) {
		case "KUBECONFIG", "OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE", "OPENSHIFT_INSTALL_OS_IMAGE_OVERRIDE":
			continue
		default:
			out = append(out, item)
		}
	}
	return out
}

type boundedOutput struct {
	buf bytes.Buffer
	max int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *boundedOutput) Bytes() []byte  { return b.buf.Bytes() }
func (b *boundedOutput) String() string { return b.buf.String() }

func sanitizedDisconnectedCommandEnv(workDir string) []string {
	out := make([]string, 0, len(os.Environ())+2)
	for _, item := range sanitizedCommandEnv() {
		name := item
		if at := strings.IndexByte(item, '='); at >= 0 {
			name = item[:at]
		}
		switch strings.ToUpper(strings.TrimSpace(name)) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "HOME", "XDG_CACHE_HOME":
			continue
		default:
			out = append(out, item)
		}
	}
	out = append(out, "HOME="+workDir, "XDG_CACHE_HOME="+filepath.Join(workDir, "cache"))
	return out
}

func runBoundedEnv(ctx context.Context, dir, path string, env []string, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = stdin
	out := &boundedOutput{max: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(out.String())
		if len(message) > 4096 {
			message = message[len(message)-4096:]
		}
		return nil, fmt.Errorf("command %s failed: %w: %s", filepath.Base(path), err, message)
	}
	return append([]byte(nil), out.Bytes()...), nil
}

func runBounded(ctx context.Context, dir, path string, stdin io.Reader, args ...string) ([]byte, error) {
	return runBoundedEnv(ctx, dir, path, sanitizedCommandEnv(), stdin, args...)
}

func (r *WorkspaceRuntime) installTimeout() time.Duration {
	if r.Config.InstallTimeout <= 0 {
		return 90 * time.Minute
	}
	return r.Config.InstallTimeout
}

func (r *WorkspaceRuntime) commandTimeout() time.Duration {
	if r.Config.CommandTimeout <= 0 {
		return 2 * time.Minute
	}
	return r.Config.CommandTimeout
}

func copySecureFile(srcPath, dstPath string) error {
	src, _, err := secureOpenRegular(srcPath, true)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := dstPath + ".tmp"
	_ = os.Remove(tmp)
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, src)
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

type clusterVersionResponse struct {
	Status struct {
		Desired struct {
			Version string `json:"version"`
		} `json:"desired"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

type nodeListResponse struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

type operatorListResponse struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

func conditionValue(conditions []struct{ Type, Status string }, name string) string {
	for _, c := range conditions {
		if strings.EqualFold(c.Type, name) {
			return strings.ToUpper(strings.TrimSpace(c.Status))
		}
	}
	return ""
}

func (r *WorkspaceRuntime) ocJSON(ctx context.Context, workspace, ocBin, kubeconfig string, out any, args ...string) error {
	commandCtx, cancel := context.WithTimeout(ctx, r.commandTimeout())
	defer cancel()
	full := append([]string{"--kubeconfig", kubeconfig}, args...)
	raw, err := runBounded(commandCtx, workspace, ocBin, nil, full...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode oc JSON: %w", err)
	}
	return nil
}

func (r *WorkspaceRuntime) verifyClusterHealth(ctx context.Context, req Request, workspace, ocBin, kubeconfig string) (map[string]any, error) {
	var cv clusterVersionResponse
	if err := r.ocJSON(ctx, workspace, ocBin, kubeconfig, &cv, "get", "clusterversion", "version", "-o", "json"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cv.Status.Desired.Version) != strings.TrimSpace(req.TargetVersion) {
		return nil, fmt.Errorf("ClusterVersion desired version %q does not match sealed target %q", cv.Status.Desired.Version, req.TargetVersion)
	}
	cvConds := make([]struct{ Type, Status string }, len(cv.Status.Conditions))
	for i, c := range cv.Status.Conditions {
		cvConds[i] = struct{ Type, Status string }{c.Type, c.Status}
	}
	if conditionValue(cvConds, "Available") != "TRUE" || conditionValue(cvConds, "Failing") == "TRUE" || conditionValue(cvConds, "Progressing") == "TRUE" {
		return nil, errors.New("ClusterVersion does not prove Available=True, Failing!=True and Progressing!=True")
	}
	var nodes nodeListResponse
	if err := r.ocJSON(ctx, workspace, ocBin, kubeconfig, &nodes, "get", "nodes", "-o", "json"); err != nil {
		return nil, err
	}
	readyNames := make([]string, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		conds := make([]struct{ Type, Status string }, len(node.Status.Conditions))
		for i, c := range node.Status.Conditions {
			conds[i] = struct{ Type, Status string }{c.Type, c.Status}
		}
		if conditionValue(conds, "Ready") == "TRUE" {
			readyNames = append(readyNames, node.Metadata.Name)
		}
	}
	if len(readyNames) < 3 {
		return nil, fmt.Errorf("Compact-3 health requires at least 3 Ready nodes; got %d", len(readyNames))
	}
	sort.Strings(readyNames)
	var operators operatorListResponse
	if err := r.ocJSON(ctx, workspace, ocBin, kubeconfig, &operators, "get", "clusteroperators", "-o", "json"); err != nil {
		return nil, err
	}
	if len(operators.Items) == 0 {
		return nil, errors.New("no ClusterOperator health evidence returned")
	}
	operatorNames := make([]string, 0, len(operators.Items))
	for _, operator := range operators.Items {
		conds := make([]struct{ Type, Status string }, len(operator.Status.Conditions))
		for i, c := range operator.Status.Conditions {
			conds[i] = struct{ Type, Status string }{c.Type, c.Status}
		}
		if conditionValue(conds, "Available") != "TRUE" || conditionValue(conds, "Degraded") == "TRUE" || conditionValue(conds, "Progressing") == "TRUE" {
			return nil, fmt.Errorf("ClusterOperator %s is not Available=True/Degraded!=True/Progressing!=True", operator.Metadata.Name)
		}
		operatorNames = append(operatorNames, operator.Metadata.Name)
	}
	sort.Strings(operatorNames)
	return map[string]any{"authority": WorkspaceRuntimeAuthority, "clusterVersion": cv.Status.Desired.Version, "readyNodes": readyNames, "clusterOperators": operatorNames, "healthVerified": true}, nil
}

func hashSecureRegularFile(path string, secretBearing bool) (string, error) {
	f, _, err := secureOpenRegular(path, secretBearing)
	if err != nil {
		return "", err
	}
	defer f.Close()
	digest, err := hashOpenFile(f)
	if err != nil {
		return "", err
	}
	return "sha256:" + digest, nil
}

func verifyDisconnectedArchive(archiveRoot, inventoryPath, expectedInventoryDigest string) (int, error) {
	got, err := hashSecureRegularFile(inventoryPath, true)
	if err != nil {
		return 0, fmt.Errorf("mirror inventory: %w", err)
	}
	if !hmac.Equal([]byte(strings.ToLower(got)), []byte(strings.ToLower(strings.TrimSpace(expectedInventoryDigest)))) {
		return 0, fmt.Errorf("mirror inventory digest mismatch: got %s", got)
	}
	f, _, err := secureOpenRegular(inventoryPath, true)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 8<<20))
	dec.DisallowUnknownFields()
	var inventory disconnectedMirrorInventory
	if err := dec.Decode(&inventory); err != nil {
		return 0, fmt.Errorf("decode mirror inventory: %w", err)
	}
	if inventory.Authority != DisconnectedMirrorInventoryAuthority || len(inventory.Files) == 0 || len(inventory.Files) > 200000 {
		return 0, errors.New("mirror inventory authority or bounded file set is invalid")
	}
	expected := make(map[string]string, len(inventory.Files))
	last := ""
	for _, entry := range inventory.Files {
		rel := filepath.ToSlash(strings.TrimSpace(entry.Path))
		if rel == "" || filepath.IsAbs(rel) || rel == "." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "\\") || filepath.ToSlash(filepath.Clean(rel)) != rel || rel <= last {
			return 0, fmt.Errorf("mirror inventory path is non-canonical or unsorted: %q", rel)
		}
		last = rel
		digest, err := normalizeExpectedDigest(entry.SHA256)
		if err != nil {
			return 0, fmt.Errorf("mirror inventory %s digest: %w", rel, err)
		}
		expected[rel] = digest
		actual, err := hashSecureRegularFile(filepath.Join(archiveRoot, filepath.FromSlash(rel)), true)
		if err != nil {
			return 0, fmt.Errorf("mirror archive %s: %w", rel, err)
		}
		if !hmac.Equal([]byte(strings.TrimPrefix(strings.ToLower(actual), "sha256:")), []byte(digest)) {
			return 0, fmt.Errorf("mirror archive %s digest mismatch", rel)
		}
	}
	seen := 0
	err = filepath.WalkDir(archiveRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("mirror archive symlink is forbidden: %s", path)
		}
		if entry.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("mirror archive directory is group/world accessible: %s", path)
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("mirror archive file is unsafe: %s", path)
		}
		rel, err := filepath.Rel(archiveRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, ok := expected[rel]; !ok {
			return fmt.Errorf("mirror archive contains unsealed file %s", rel)
		}
		seen++
		return nil
	})
	if err != nil {
		return 0, err
	}
	if seen != len(expected) {
		return 0, fmt.Errorf("mirror archive coverage mismatch: seen=%d inventory=%d", seen, len(expected))
	}
	return seen, nil
}

func writeDisconnectedMarker(workDir string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tmp := filepath.Join(workDir, "disconnected-mirror-complete.json.tmp")
	final := filepath.Join(workDir, "disconnected-mirror-complete.json")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (r *WorkspaceRuntime) PrepareDisconnectedMirror(ctx context.Context, req Request, operationToken string) (map[string]any, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	if !IsDisconnected(canonical) || canonical.Disconnected == nil {
		return nil, errors.New("disconnected request is required")
	}
	if err := r.ValidateDisconnected(); err != nil {
		return nil, err
	}
	configuredRegistry := strings.Trim(strings.ToLower(strings.TrimSpace(r.Config.DisconnectedMirrorRegistry)), "/")
	if canonical.Disconnected.MirrorRegistry != configuredRegistry {
		return nil, errors.New("sealed mirror registry does not match product-managed disconnected registry")
	}
	workspace, workDir, _, _, requestDigest, err := r.operationPaths(canonical, operationToken)
	if err != nil {
		return nil, err
	}
	disconnectedRoot := filepath.Join(workspace, "disconnected")
	if _, err = secureDir(disconnectedRoot, true); err != nil {
		return nil, fmt.Errorf("disconnected workspace: %w", err)
	}
	configPath := filepath.Join(disconnectedRoot, "imageset-config.yaml")
	gotConfig, err := hashSecureRegularFile(configPath, true)
	if err != nil {
		return nil, fmt.Errorf("imageset configuration: %w", err)
	}
	if !hmac.Equal([]byte(strings.ToLower(gotConfig)), []byte(strings.ToLower(canonical.Disconnected.ImageSetConfigurationSHA256))) {
		return nil, fmt.Errorf("ImageSetConfiguration digest mismatch: got %s", gotConfig)
	}
	archiveRoot := filepath.Join(disconnectedRoot, "archive")
	if _, err = secureDir(archiveRoot, true); err != nil {
		return nil, fmt.Errorf("mirror archive: %w", err)
	}
	inventoryPath := filepath.Join(disconnectedRoot, "mirror-inventory.json")
	fileCount, err := verifyDisconnectedArchive(archiveRoot, inventoryPath, canonical.Disconnected.MirrorInventorySHA256)
	if err != nil {
		return nil, err
	}
	ocMirrorBin := filepath.Join(workDir, "oc-mirror")
	if _, err = copyVerifiedExecutable(r.Config.OCMirror, r.Config.OCMirrorSHA, ocMirrorBin); err != nil {
		return nil, fmt.Errorf("stage exact oc-mirror: %w", err)
	}
	cacheDir := filepath.Join(workDir, "oc-mirror-cache")
	if err = os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	mirrorCtx, cancel := context.WithTimeout(ctx, r.installTimeout())
	defer cancel()
	_, err = runBoundedEnv(mirrorCtx, workspace, ocMirrorBin, sanitizedDisconnectedCommandEnv(workDir), nil,
		"--config", configPath, "--from", "file://"+archiveRoot, "docker://"+configuredRegistry, "--v2", "--dest-tls-verify=true", "--cache-dir", cacheDir)
	if err != nil {
		return nil, fmt.Errorf("oc-mirror v2 disk-to-mirror: %w", err)
	}
	marker := map[string]any{"authority": DisconnectedMirrorAuthority, "requestDigest": requestDigest, "mirrorRegistry": configuredRegistry, "imageSetConfigurationSha256": canonical.Disconnected.ImageSetConfigurationSHA256, "mirrorInventorySha256": canonical.Disconnected.MirrorInventorySHA256, "archiveFileCount": fileCount, "networkSourceRequired": false, "ocMirrorV2": true}
	if err = writeDisconnectedMarker(workDir, marker); err != nil {
		return nil, fmt.Errorf("seal disconnected mirror checkpoint: %w", err)
	}
	return marker, nil
}

func (r *WorkspaceRuntime) installOKD(ctx context.Context, req Request, operationToken, connectivity string) (map[string]any, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	workspace, workDir, installBin, ocBin, requestDigest, err := r.operationPaths(canonical, operationToken)
	if err != nil {
		return nil, err
	}
	if connectivity == "disconnected" {
		marker, _, err := secureOpenRegular(filepath.Join(workDir, "disconnected-mirror-complete.json"), true)
		if err != nil {
			return nil, errors.New("disconnected mirror checkpoint is missing")
		}
		var checkpoint map[string]any
		decodeErr := json.NewDecoder(io.LimitReader(marker, 128<<10)).Decode(&checkpoint)
		_ = marker.Close()
		if decodeErr != nil || checkpoint["requestDigest"] != requestDigest || checkpoint["mirrorRegistry"] != canonical.Disconnected.MirrorRegistry {
			return nil, errors.New("disconnected mirror checkpoint does not match sealed request")
		}
	}
	installCtx, cancel := context.WithTimeout(ctx, r.installTimeout())
	defer cancel()
	if _, err = runBounded(installCtx, workspace, installBin, nil, "agent", "wait-for", "install-complete", "--dir", workspace, "--log-level=info"); err != nil {
		return nil, err
	}
	if err = validateWorkspaceTree(workspace); err != nil {
		return nil, fmt.Errorf("post-install workspace integrity: %w", err)
	}
	kubeconfig := filepath.Join(workDir, "kubeconfig")
	if err = copySecureFile(filepath.Join(workspace, "auth", "kubeconfig"), kubeconfig); err != nil {
		return nil, fmt.Errorf("copy exact install kubeconfig: %w", err)
	}
	health, err := r.verifyClusterHealth(ctx, canonical, workspace, ocBin, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("verify %s OKD health: %w", connectivity, err)
	}
	health["requestDigest"] = requestDigest
	health["workspaceDigestBound"] = true
	health["connectivity"] = connectivity
	if connectivity == "disconnected" {
		health["mirrorRegistry"] = canonical.Disconnected.MirrorRegistry
		health["publicRegistryRequired"] = false
	}
	return health, nil
}

func (r *WorkspaceRuntime) InstallDisconnectedOKD(ctx context.Context, req Request, operationToken string) (map[string]any, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	if !IsDisconnected(canonical) {
		return nil, errors.New("disconnected install requires disconnected request")
	}
	return r.installOKD(ctx, canonical, operationToken, "disconnected")
}

func (r *WorkspaceRuntime) InstallConnectedOKD(ctx context.Context, req Request, operationToken string) (map[string]any, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	if IsDisconnected(canonical) {
		return nil, errors.New("connected install runtime refuses disconnected request")
	}
	return r.installOKD(ctx, canonical, operationToken, "connected")
}

func (r *WorkspaceRuntime) ApplyRegistrationManifest(ctx context.Context, req Request, operationToken, manifest string) (map[string]any, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	workspace, workDir, _, ocBin, requestDigest, err := r.operationPaths(canonical, operationToken)
	if err != nil {
		return nil, err
	}
	kubeconfig := filepath.Join(workDir, "kubeconfig")
	if _, _, err := secureOpenRegular(kubeconfig, true); err != nil {
		if err = copySecureFile(filepath.Join(workspace, "auth", "kubeconfig"), kubeconfig); err != nil {
			return nil, fmt.Errorf("prepare registration kubeconfig: %w", err)
		}
	}
	commandCtx, cancel := context.WithTimeout(ctx, r.commandTimeout())
	defer cancel()
	if _, err = runBounded(commandCtx, workspace, ocBin, strings.NewReader(manifest), "--kubeconfig", kubeconfig, "apply", "-f", "-"); err != nil {
		return nil, err
	}
	manifestDigest := sha256.Sum256([]byte(manifest))
	return map[string]any{"authority": WorkspaceRuntimeAuthority, "requestDigest": requestDigest, "manifestDigest": "sha256:" + hex.EncodeToString(manifestDigest[:]), "applied": true}, nil
}
