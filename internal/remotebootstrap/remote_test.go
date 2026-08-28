package remotebootstrap

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageArchiveRoundTripAndTamperDetection(t *testing.T) {
	sources := map[string]stageSource{
		"deployment.json":    {data: []byte("{\"version\":1}\n"), mode: 0o600},
		"platform-installer": {data: []byte("binary"), mode: 0o755},
		"bundle/bundle.json": {data: []byte("bundle"), mode: 0o644},
		"tls.key":            {data: []byte("private"), mode: 0o600},
	}
	manifest, raw, err := makeArchive(sources)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	destination := filepath.Join(root, "var/lib/4so-platform-installer/remote-bootstrap/test-stage")
	received, err := ReceiveStage(destination, manifest.Digest, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if received.Digest != manifest.Digest {
		t.Fatalf("digest mismatch %s != %s", received.Digest, manifest.Digest)
	}
	if _, err = VerifyStage(destination, manifest.Digest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected key mode %o", info.Mode().Perm())
	}
	if err = os.WriteFile(filepath.Join(destination, "bundle/bundle.json"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyStage(destination, manifest.Digest); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestReceiveStageRejectsSymlinkAndPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "var/lib/4so-platform-installer/remote-bootstrap/test-stage")
	if _, err := ReceiveStage(destination, "sha256:"+strings.Repeat("0", 64), bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("expected path traversal rejection")
	}

	buf.Reset()
	tw = tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Mode: 0o777, Typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReceiveStage(destination, "sha256:"+strings.Repeat("0", 64), bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestRemoteRootValidation(t *testing.T) {
	for _, value := range []string{"relative", "/tmp/../etc", "/tmp/root;id", "/tmp/root\nnext"} {
		if err := validateRemoteRoot(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
	for _, value := range []string{"/", "/tmp/4so-root", "/srv/platform_root"} {
		if err := validateRemoteRoot(value); err != nil {
			t.Fatalf("expected %q valid: %v", value, err)
		}
	}
}

func TestSSHArgsAreFailClosed(t *testing.T) {
	loaded := loadedSpec{IdentityFile: "/secure/id", KnownHostsFile: "/secure/known_hosts", User: "root", Host: "node1.example"}
	joined := strings.Join(sshArgs(loaded), " ")
	for _, required := range []string{"BatchMode=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "LogLevel=ERROR"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %s in %s", required, joined)
		}
	}
	for _, forbidden := range []string{"accept-new", "StrictHostKeyChecking=no", "sshpass", "sudo", "scp"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden SSH behavior %s in %s", forbidden, joined)
		}
	}
}

func TestStageDestinationRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(link, "var/lib/4so-platform-installer/remote-bootstrap/test-stage")
	if err := validateStageDestination(destination); err == nil || !strings.Contains(err.Error(), "symlink ancestor") {
		t.Fatalf("expected symlink ancestor rejection, got %v", err)
	}
}

func TestReceiveStageRecoversInterruptedSwapAndReplacesPreviousStage(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "var/lib/4so-platform-installer/remote-bootstrap/test-stage")
	oldManifest, oldArchive, err := makeArchive(map[string]stageSource{
		"deployment.json": {data: []byte("old\n"), mode: 0o600},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReceiveStage(destination, oldManifest.Digest, bytes.NewReader(oldArchive)); err != nil {
		t.Fatal(err)
	}
	backup := stageBackupPath(destination)
	if err = os.Rename(destination, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyStage(destination, oldManifest.Digest); err != nil {
		t.Fatalf("interrupted stage swap was not recovered: %v", err)
	}
	if _, err = os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("expected recovered backup path to be absent, got %v", err)
	}

	newManifest, newArchive, err := makeArchive(map[string]stageSource{
		"deployment.json": {data: []byte("new\n"), mode: 0o600},
		"platformctl":     {data: []byte("binary"), mode: 0o755},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReceiveStage(destination, newManifest.Digest, bytes.NewReader(newArchive)); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyStage(destination, newManifest.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("expected successful replacement to remove backup path, got %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(destination, "deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "new\n" {
		t.Fatalf("unexpected replaced stage payload %q", raw)
	}
}

type stagedRunner struct {
	commands        []string
	failRM          bool
	failRemoveStage bool
}

func (r *stagedRunner) Run(_ context.Context, _ io.Reader, _ string, args ...string) ([]byte, error) {
	command := ""
	if len(args) > 0 {
		command = args[len(args)-1]
	}
	r.commands = append(r.commands, command)
	if r.failRM && strings.Contains(command, "rm -f --") {
		return nil, errors.New("synthetic cleanup failure")
	}
	if r.failRemoveStage && strings.Contains(command, "remove-stage") {
		return nil, errors.New("synthetic stage cleanup failure")
	}
	return nil, nil
}

func TestRemoteBootstrapAttemptPathsAreIsolated(t *testing.T) {
	base := loadedSpec{StageDirectory: "/var/lib/4so-platform-installer/remote-bootstrap/base"}
	a, err := isolateRemoteStage(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := isolateRemoteStage(base)
	if err != nil {
		t.Fatal(err)
	}
	if a.StageDirectory == b.StageDirectory || a.StageDirectory == base.StageDirectory || b.StageDirectory == base.StageDirectory {
		t.Fatalf("expected per-operation stage paths, got base=%q a=%q b=%q", base.StageDirectory, a.StageDirectory, b.StageDirectory)
	}
	if !strings.HasPrefix(a.StageDirectory, base.StageDirectory+"-") || !strings.HasPrefix(b.StageDirectory, base.StageDirectory+"-") {
		t.Fatalf("isolated stages escaped expected authority: %q %q", a.StageDirectory, b.StageDirectory)
	}
}

func TestStagedControlBinaryIsPerOperationAndCleanupErrorsSurface(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "platformctl")
	if err := os.WriteFile(binary, []byte("test-control-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := loadedSpec{Platformctl: binary, IdentityFile: "/id", KnownHostsFile: "/known", User: "root", Host: "node.test"}
	runner := &stagedRunner{}
	pathA, cleanupA, err := stageControlBinary(context.Background(), runner, "ssh", loaded)
	if err != nil {
		t.Fatal(err)
	}
	pathB, cleanupB, err := stageControlBinary(context.Background(), runner, "ssh", loaded)
	if err != nil {
		t.Fatal(err)
	}
	if pathA == pathB {
		t.Fatalf("concurrent operations shared staged control path %q", pathA)
	}
	if err := cleanupA(); err != nil {
		t.Fatal(err)
	}
	if err := cleanupB(); err != nil {
		t.Fatal(err)
	}

	failing := &stagedRunner{failRM: true}
	_, cleanup, err := stageControlBinary(context.Background(), failing, "ssh", loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err == nil || !strings.Contains(err.Error(), "synthetic cleanup failure") {
		t.Fatalf("expected cleanup failure to surface, got %v", err)
	}
}

func TestRemoteStageCleanupFailureIsAuthoritative(t *testing.T) {
	loaded := loadedSpec{StageDirectory: "/var/lib/4so-platform-installer/remote-bootstrap/base-attempt", IdentityFile: "/id", KnownHostsFile: "/known", User: "root", Host: "node.test"}
	runner := &stagedRunner{failRemoveStage: true}
	err := cleanupRemoteStage(runner, "ssh", loaded, "/tmp/platformctl")
	if err == nil || !strings.Contains(err.Error(), "synthetic stage cleanup failure") {
		t.Fatalf("expected remote stage cleanup failure to surface, got %v", err)
	}
}

func TestRemoveStageRemovesOnlyItsAttemptFamily(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "var/lib/4so-platform-installer/remote-bootstrap")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(parent, "base-attempt-a")
	b := filepath.Join(parent, "base-attempt-b")
	for _, path := range []string{a, stageBackupPath(a), filepath.Join(parent, ".base-attempt-a.123.incoming"), b, stageBackupPath(b), filepath.Join(parent, ".base-attempt-b.456.incoming")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveStage(a); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a, stageBackupPath(a), filepath.Join(parent, ".base-attempt-a.123.incoming")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected own attempt residue removed at %s, got %v", path, err)
		}
	}
	for _, path := range []string{b, stageBackupPath(b), filepath.Join(parent, ".base-attempt-b.456.incoming")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("concurrent attempt path %s was touched: %v", path, err)
		}
	}
}
