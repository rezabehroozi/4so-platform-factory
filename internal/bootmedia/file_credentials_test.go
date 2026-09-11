package bootmedia

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeCredentialFixture(t *testing.T, root string, scope CredentialScope, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(root, scope.OrganizationID, scope.ProjectID, scope.MachineID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, scope.Reference+".json")
	raw, _ := json.Marshal(fileCredentialDocument{Authority: FileCredentialResolverAuthority, OrganizationID: scope.OrganizationID, ProjectID: scope.ProjectID, MachineID: scope.MachineID, Endpoint: scope.Endpoint, Username: "svc", Password: "secret"})
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileCredentialResolverBindsOrganizationProjectMachineAndEndpoint(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := CredentialScope{OrganizationID: "org-1", ProjectID: "prj-1", MachineID: "cp-1", Endpoint: "https://bmc-1.example.test", Reference: "redfish-cp-1"}
	writeCredentialFixture(t, root, scope, 0o600)
	resolver := FileCredentialResolver{Root: root}
	got, err := resolver.ResolveBootMediaCredential(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "svc" || got.Password != "secret" {
		t.Fatalf("unexpected credential %#v", got)
	}
	wrong := scope
	wrong.Endpoint = "https://bmc-2.example.test"
	if _, err = resolver.ResolveBootMediaCredential(context.Background(), wrong); err == nil {
		t.Fatal("endpoint scope confusion was accepted")
	}
}

func TestFileCredentialResolverRejectsSymlinkAndWeakPermissions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := CredentialScope{OrganizationID: "org-1", ProjectID: "prj-1", MachineID: "cp-1", Endpoint: "https://bmc-1.example.test", Reference: "redfish-cp-1"}
	path := writeCredentialFixture(t, root, scope, 0o644)
	resolver := FileCredentialResolver{Root: root}
	if _, err := resolver.ResolveBootMediaCredential(context.Background(), scope); err == nil {
		t.Fatal("world-readable credential file was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := resolver.ResolveBootMediaCredential(context.Background(), scope); err == nil {
		t.Fatal("credential symlink was accepted")
	}
}

func TestFileCredentialResolverRejectsTraversalReference(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver := FileCredentialResolver{Root: root}
	_, err := resolver.ResolveBootMediaCredential(context.Background(), CredentialScope{OrganizationID: "org-1", ProjectID: "prj-1", MachineID: "cp-1", Endpoint: "https://bmc.example.test", Reference: "../secret"})
	if err == nil {
		t.Fatal("path traversal reference was accepted")
	}
}
