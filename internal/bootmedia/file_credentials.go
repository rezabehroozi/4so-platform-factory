package bootmedia

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const FileCredentialResolverAuthority = "REDFISH_FILE_CREDENTIAL_RESOLVER_V1"

var credentialPathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type FileCredentialResolver struct {
	Root string
}

type fileCredentialDocument struct {
	Authority      string `json:"authority"`
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
	MachineID      string `json:"machineId"`
	Endpoint       string `json:"endpoint"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

func validCredentialSegment(value string) bool {
	value = strings.TrimSpace(value)
	return credentialPathSegment.MatchString(value) && value != "." && value != ".."
}

func secureCredentialRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", errors.New("redfish credential root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve redfish credential root: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("stat redfish credential root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("redfish credential root must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("redfish credential root must not be group/world writable")
	}
	return abs, nil
}

func openCredentialDocument(path string) (*os.File, os.FileInfo, error) {
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
		return nil, nil, errors.New("credential document must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, nil, errors.New("credential document must not be group/world accessible")
	}
	return f, info, nil
}

func (r FileCredentialResolver) ResolveBootMediaCredential(_ context.Context, scope CredentialScope) (Credentials, error) {
	root, err := secureCredentialRoot(r.Root)
	if err != nil {
		return Credentials{}, err
	}
	for name, value := range map[string]string{
		"organizationId": scope.OrganizationID,
		"projectId":      scope.ProjectID,
		"machineId":      scope.MachineID,
		"reference":      scope.Reference,
	} {
		if !validCredentialSegment(value) {
			return Credentials{}, fmt.Errorf("%s is not a safe credential path segment", name)
		}
	}
	endpoint := strings.TrimSpace(scope.Endpoint)
	if endpoint == "" {
		return Credentials{}, errors.New("credential scope endpoint is required")
	}
	path := filepath.Join(root, strings.TrimSpace(scope.OrganizationID), strings.TrimSpace(scope.ProjectID), strings.TrimSpace(scope.MachineID), strings.TrimSpace(scope.Reference)+".json")
	cleanRoot := root + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(path)+string(os.PathSeparator), cleanRoot) {
		return Credentials{}, errors.New("credential path escaped configured root")
	}
	f, _, err := openCredentialDocument(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("open scoped redfish credential: %w", err)
	}
	defer f.Close()
	limited := io.LimitReader(f, 64<<10)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	var doc fileCredentialDocument
	if err := dec.Decode(&doc); err != nil {
		return Credentials{}, fmt.Errorf("decode scoped redfish credential: %w", err)
	}
	if doc.Authority != FileCredentialResolverAuthority || strings.TrimSpace(doc.OrganizationID) != strings.TrimSpace(scope.OrganizationID) || strings.TrimSpace(doc.ProjectID) != strings.TrimSpace(scope.ProjectID) || strings.TrimSpace(doc.MachineID) != strings.TrimSpace(scope.MachineID) || strings.TrimSpace(doc.Endpoint) != endpoint {
		return Credentials{}, errors.New("redfish credential document scope does not match the requested organization/project/machine/endpoint")
	}
	if strings.TrimSpace(doc.Username) == "" || doc.Password == "" {
		return Credentials{}, errors.New("redfish credential document is incomplete")
	}
	return Credentials{Username: strings.TrimSpace(doc.Username), Password: doc.Password}, nil
}

func (r FileCredentialResolver) Validate() error {
	_, err := secureCredentialRoot(r.Root)
	return err
}
