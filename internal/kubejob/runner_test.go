package kubejob

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
	"time"
)

type fakeSystem struct {
	root       string
	commands   []string
	jobs       map[string]snapshot
	getCount   map[string]int
	replaceOn  map[string]int
	createFail error
}

func newFakeSystem(t *testing.T) *fakeSystem {
	t.Helper()
	return &fakeSystem{root: t.TempDir(), jobs: map[string]snapshot{}, getCount: map[string]int{}, replaceOn: map[string]int{}}
}
func (s *fakeSystem) MkdirAll(path string, mode fs.FileMode) error {
	return os.MkdirAll(filepath.Join(s.root, path), mode)
}
func (s *fakeSystem) WriteFile(path string, data []byte, mode fs.FileMode) error {
	target := filepath.Join(s.root, path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}
func (s *fakeSystem) CopyFile(source, destination string, mode fs.FileMode) error {
	return errors.New("not implemented")
}
func (s *fakeSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	_, err := s.Output(ctx, name, args, environment)
	return err
}
func (s *fakeSystem) RunInput(context.Context, string, []string, map[string]string, io.Reader) error {
	return errors.New("not implemented")
}
func (s *fakeSystem) Exists(path string) bool {
	_, err := os.Stat(filepath.Join(s.root, path))
	return err == nil
}
func (s *fakeSystem) IsRoot() bool { return true }
func (s *fakeSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.commands = append(s.commands, command)
	verb := ""
	for _, candidate := range []string{"get", "create"} {
		for _, arg := range args {
			if arg == candidate {
				verb = candidate
				break
			}
		}
		if verb != "" {
			break
		}
	}
	switch verb {
	case "get":
		var jobName string
		for i, arg := range args {
			if arg == "job" && i+1 < len(args) {
				jobName = args[i+1]
				break
			}
		}
		if jobName == "" {
			return nil, errors.New("missing job name")
		}
		s.getCount[jobName]++
		if threshold := s.replaceOn[jobName]; threshold > 0 && s.getCount[jobName] == threshold {
			v := s.jobs[jobName]
			v.Metadata.UID = "replacement-uid"
			v.Metadata.ResourceVersion = "99"
			s.jobs[jobName] = v
		}
		value, ok := s.jobs[jobName]
		if !ok {
			return nil, nil
		}
		raw, _ := json.Marshal(value)
		return raw, nil
	case "create":
		if s.createFail != nil {
			return nil, s.createFail
		}
		manifestPath := ""
		for i, arg := range args {
			if arg == "-f" && i+1 < len(args) {
				manifestPath = args[i+1]
				break
			}
		}
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, err
		}
		text := string(raw)
		jobName := quotedAnnotation(text, AnnotationJobName)
		operationID := quotedAnnotation(text, AnnotationOperationID)
		owner := quotedAnnotation(text, AnnotationOwner)
		if jobName == "" || operationID == "" || owner == "" {
			return nil, errors.New("manifest annotations missing")
		}
		value := completedSnapshot(jobName, "uid-created", owner, operationID)
		s.jobs[jobName] = value
		encoded, _ := json.Marshal(value)
		return encoded, nil
	}
	return nil, nil
}

func quotedAnnotation(manifest, key string) string {
	needle := `"` + key + `": "`
	start := strings.Index(manifest, needle)
	if start < 0 {
		return ""
	}
	start += len(needle)
	end := strings.Index(manifest[start:], `"`)
	if end < 0 {
		return ""
	}
	return manifest[start : start+end]
}

func completedSnapshot(name, uid, owner, operationID string) snapshot {
	var value snapshot
	value.Metadata.Name = name
	value.Metadata.UID = uid
	value.Metadata.ResourceVersion = "1"
	value.Metadata.Annotations = map[string]string{AnnotationOwner: owner, AnnotationOperationID: operationID, AnnotationJobName: name}
	value.Status.Conditions = append(value.Status.Conditions, struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}{Type: "Complete", Status: "True"})
	return value
}

func manifest(name, owner, operationID string) string {
	return `apiVersion: batch/v1
kind: Job
metadata:
  name: ` + name + `
  annotations: {"` + AnnotationOwner + `": "` + owner + `", "` + AnnotationOperationID + `": "` + operationID + `", "` + AnnotationJobName + `": "` + name + `"}
spec: {template: {spec: {restartPolicy: Never, containers: [{name: noop, image: example.invalid/noop}]}}}
`
}

func options(t *testing.T, system *fakeSystem) Options {
	t.Helper()
	return Options{System: system, StateDir: t.TempDir(), StateSubdir: "jobs", Kubeconfig: "/kubeconfig", Namespace: "platform-system", Owner: "test-owner", OperationID: "operation-1", Name: "job-operation-1", Manifest: manifest("job-operation-1", "test-owner", "operation-1"), Timeout: time.Second, PollInterval: time.Millisecond}
}

func TestExecuteCreatesPersistsIdentityAndCompletesWithoutDeleteOrApply(t *testing.T) {
	system := newFakeSystem(t)
	opts := options(t, system)
	if err := Execute(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.commands, "\n")
	if !strings.Contains(commands, " create -f ") {
		t.Fatalf("create not used:\n%s", commands)
	}
	if strings.Contains(commands, " delete ") || strings.Contains(commands, " apply ") {
		t.Fatalf("unsafe delete/apply used:\n%s", commands)
	}
	raw, err := os.ReadFile(filepath.Join(opts.StateDir, opts.StateSubdir, "job-identities", opts.Name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"uid": "uid-created"`) {
		t.Fatalf("identity not persisted: %s", raw)
	}
}

func TestExecuteRejectsForeignExistingJobWithoutDurableIdentity(t *testing.T) {
	system := newFakeSystem(t)
	opts := options(t, system)
	foreign := completedSnapshot(opts.Name, "foreign-uid", "someone-else", "other-operation")
	system.jobs[opts.Name] = foreign
	err := Execute(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "exists without durable identity") {
		t.Fatalf("expected foreign adoption rejection, got %v", err)
	}
	if strings.Contains(strings.Join(system.commands, "\n"), " create -f ") {
		t.Fatalf("must not create over existing foreign job")
	}
}

func TestExecuteRejectsSameNameReplacementAfterDurableUID(t *testing.T) {
	system := newFakeSystem(t)
	opts := options(t, system)
	if err := Execute(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	value := system.jobs[opts.Name]
	value.Metadata.UID = "replacement-uid"
	value.Metadata.ResourceVersion = "2"
	system.jobs[opts.Name] = value
	err := Execute(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected replacement rejection, got %v", err)
	}
}

func TestExecuteRejectsLegacyJobRatherThanBlindReplay(t *testing.T) {
	system := newFakeSystem(t)
	opts := options(t, system)
	opts.LegacyName = "legacy-job"
	system.jobs[opts.LegacyName] = completedSnapshot(opts.LegacyName, "legacy-uid", "legacy", "legacy")
	err := Execute(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "refusing upgrade-time replay") {
		t.Fatalf("expected legacy ambiguity rejection, got %v", err)
	}
	if strings.Contains(strings.Join(system.commands, "\n"), " create -f ") {
		t.Fatalf("must not replay while legacy job exists")
	}
}

func TestExecuteRejectsJobReplacementWhileWaiting(t *testing.T) {
	system := newFakeSystem(t)
	opts := options(t, system)
	var active snapshot
	active.Metadata.Name = opts.Name
	active.Metadata.UID = "uid-created"
	active.Metadata.ResourceVersion = "1"
	active.Metadata.Annotations = map[string]string{AnnotationOwner: opts.Owner, AnnotationOperationID: opts.OperationID, AnnotationJobName: opts.Name}
	// Create returns a completed object by default, so force the persisted identity first and then exercise resume/wait.
	identityDir := filepath.Join(opts.StateDir, opts.StateSubdir, "job-identities")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	idRaw, _ := json.Marshal(identity{Owner: opts.Owner, OperationID: opts.OperationID, Name: opts.Name, UID: active.Metadata.UID, ResourceVersion: active.Metadata.ResourceVersion})
	if err := os.WriteFile(filepath.Join(identityDir, opts.Name+".json"), idRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	system.jobs[opts.Name] = active
	system.replaceOn[opts.Name] = 2
	err := Execute(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected wait-time replacement rejection, got %v", err)
	}
}
