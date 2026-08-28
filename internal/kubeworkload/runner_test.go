package kubeworkload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSystem struct {
	commands          []string
	object            string
	replaceAfterPatch bool
	driftAfterPatch   bool
	patchErr          error
}

func (s *fakeSystem) MkdirAll(string, fs.FileMode) error          { return nil }
func (s *fakeSystem) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (s *fakeSystem) CopyFile(string, string, fs.FileMode) error  { return nil }
func (s *fakeSystem) Exists(string) bool                          { return false }
func (s *fakeSystem) IsRoot() bool                                { return true }
func (s *fakeSystem) Run(ctx context.Context, n string, a []string, e map[string]string) error {
	_, err := s.Output(ctx, n, a, e)
	return err
}
func (s *fakeSystem) RunInput(context.Context, string, []string, map[string]string, io.Reader) error {
	return nil
}
func (s *fakeSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	c := name + " " + strings.Join(args, " ")
	s.commands = append(s.commands, c)
	if strings.Contains(c, " get deployment platform-api -o json") {
		return []byte(s.object), nil
	}
	if strings.Contains(c, " patch deployment platform-api --type=json ") {
		if s.patchErr != nil {
			return nil, s.patchErr
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(s.object), &obj); err != nil {
			return nil, err
		}
		metadata := obj["metadata"].(map[string]any)
		metadata["resourceVersion"] = "12"
		spec := obj["spec"].(map[string]any)
		if strings.Contains(c, `"path":"/spec/replicas","value":0`) {
			spec["replicas"] = float64(0)
		}
		if strings.Contains(c, `"path":"/spec/template/spec/containers/0/image"`) {
			template := spec["template"].(map[string]any)
			podSpec := template["spec"].(map[string]any)
			containers := podSpec["containers"].([]any)
			container := containers[0].(map[string]any)
			container["image"] = "registry/api@sha256:" + strings.Repeat("b", 64)
		}
		applied, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		// The PATCH response is the state atomically accepted by the API server.
		// Replacement/drift below models a mutation that occurs after that response.
		if s.replaceAfterPatch {
			s.object = `{"metadata":{"uid":"uid-foreign","resourceVersion":"22"},"spec":{"replicas":0,"template":{"spec":{"containers":[{"name":"api","image":"registry/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}}}`
		} else if s.driftAfterPatch {
			s.object = `{"metadata":{"uid":"uid-owned","resourceVersion":"13"},"spec":{"replicas":2,"template":{"spec":{"containers":[{"name":"api","image":"registry/api@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}}}}`
		} else {
			s.object = string(applied)
		}
		return applied, nil
	}
	return nil, errors.New("unexpected command: " + c)
}
func opts(t *testing.T, s *fakeSystem) Options {
	return Options{System: s, StateDir: t.TempDir(), StateSubdir: "test", Kubeconfig: "/k", Namespace: "platform-system", Owner: "test-owner", OperationID: "op-1", Kind: "deployment", Name: "platform-api"}
}
func initial() string {
	return `{"metadata":{"uid":"uid-owned","resourceVersion":"11"},"spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"api","image":"registry/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}`
}

func TestScalePersistsUIDAndUsesUIDResourceVersionTests(t *testing.T) {
	s := &fakeSystem{object: initial()}
	o := opts(t, s)
	if err := Scale(context.Background(), o, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(o.StateDir, o.StateSubdir, "workload-identities", o.OperationID, "deployment-platform-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"uid": "uid-owned"`) {
		t.Fatalf("identity=%s", raw)
	}
	joined := strings.Join(s.commands, "\n")
	for _, want := range []string{`"path":"/metadata/uid","value":"uid-owned"`, `"path":"/metadata/resourceVersion","value":"11"`, `"path":"/spec/replicas","value":0`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	if strings.Contains(joined, " scale ") {
		t.Fatalf("name-only scale used: %s", joined)
	}
}
func TestSameNameReplacementAfterMutationFailsClosed(t *testing.T) {
	s := &fakeSystem{object: initial(), replaceAfterPatch: true}
	o := opts(t, s)
	err := Scale(context.Background(), o, 0)
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected replacement rejection, got %v", err)
	}
}
func TestStoredUIDRejectsReplacementBeforeFurtherMutation(t *testing.T) {
	s := &fakeSystem{object: initial()}
	o := opts(t, s)
	if err := Verify(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	s.object = `{"metadata":{"uid":"uid-foreign","resourceVersion":"21"},"spec":{"replicas":3}}`
	before := len(s.commands)
	err := Scale(context.Background(), o, 0)
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected replacement rejection, got %v", err)
	}
	for _, c := range s.commands[before:] {
		if strings.Contains(c, " patch ") {
			t.Fatalf("replacement was mutated: %s", c)
		}
	}
}
func TestSetImageUsesContainerAndIdentityPreconditions(t *testing.T) {
	s := &fakeSystem{object: initial()}
	o := opts(t, s)
	old, err := SetImage(context.Background(), o, "api", "registry/api@sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(old, "sha256:aaaa") {
		t.Fatalf("old=%s", old)
	}
	joined := strings.Join(s.commands, "\n")
	for _, want := range []string{`"path":"/metadata/uid"`, `"path":"/metadata/resourceVersion"`, `"path":"/spec/template/spec/containers/0/name","value":"api"`, `"path":"/spec/template/spec/containers/0/image"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(joined, " set image ") {
		t.Fatalf("name-only set image used")
	}
}

func TestVerifyReplicasRejectsSameUIDPostconditionDrift(t *testing.T) {
	s := &fakeSystem{object: initial(), driftAfterPatch: true}
	o := opts(t, s)
	if err := Scale(context.Background(), o, 0); err != nil {
		t.Fatal(err)
	}
	err := VerifyReplicas(context.Background(), o, 0)
	if err == nil || !strings.Contains(err.Error(), "replicas postcondition mismatch") {
		t.Fatalf("expected same-UID replica drift rejection, got %v", err)
	}
}

func TestVerifyImageRejectsSameUIDPostconditionDrift(t *testing.T) {
	s := &fakeSystem{object: initial(), driftAfterPatch: true}
	o := opts(t, s)
	want := "registry/api@sha256:" + strings.Repeat("b", 64)
	if _, err := SetImage(context.Background(), o, "api", want); err != nil {
		t.Fatal(err)
	}
	err := VerifyImage(context.Background(), o, "api", want)
	if err == nil || !strings.Contains(err.Error(), "image postcondition mismatch") {
		t.Fatalf("expected same-UID image drift rejection, got %v", err)
	}
}
