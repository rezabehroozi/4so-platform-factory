package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestBuildOSPatchJobIsNodePinnedPrivilegedAndDigestPinned(t *testing.T) {
	task := controlplane.ClusterMaintenanceTask{RunID: "run-1", ClusterID: "cluster-1", InventoryDigest: "sha256:inventory", HostActionTimeoutSeconds: 900}
	job := buildOSPatchJob(task, "node-a", "uid-a", "registry.local/platform-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, required := range []string{"node-a", "uid-a", hostMaintenanceAuthority, "sha256:inventory", "privileged", "/host", "host-maintenance", "os-patch", "@sha256:"} {
		if !strings.Contains(body, required) {
			t.Fatalf("job contract missing %q: %s", required, body)
		}
	}
	if strings.Contains(body, "reboot") {
		t.Fatalf("OS patch job must never request automatic reboot: %s", body)
	}
}

func TestMaintenanceJobNameStableAndIdentityScoped(t *testing.T) {
	a := maintenanceJobName("run-1", "uid-a")
	if a != maintenanceJobName("run-1", "uid-a") {
		t.Fatal("job name is not deterministic")
	}
	if a == maintenanceJobName("run-1", "uid-b") || a == maintenanceJobName("run-2", "uid-a") {
		t.Fatal("job name is not identity scoped")
	}
	if len(a) > 63 {
		t.Fatalf("job name too long: %s", a)
	}
}

func TestParseHostMaintenanceTerminationFailsClosed(t *testing.T) {
	if _, err := parseHostMaintenanceTermination(`{"authority":"WRONG","action":"os-patch"}`); err == nil {
		t.Fatal("expected authority mismatch")
	}
	good := hostMaintenanceResult{Authority: hostMaintenanceAuthority, Action: "os-patch", OSID: "ubuntu", PackageManager: "apt-get", Commands: []string{"apt-get update"}, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(good)
	if _, err := parseHostMaintenanceTermination(string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClusterMaintenanceTaskRequiresBoundedPatchTimeout(t *testing.T) {
	base := controlplane.ClusterMaintenanceTask{Method: controlplane.ClusterMaintenanceAuthorityMethod, RunID: "run", RunRevision: 1, OperationID: "op", OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster", Action: controlplane.TargetNodeActionOSPatch, NodeNames: []string{"n"}, NodeUIDs: map[string]string{"n": "uid"}, InventoryDigest: "sha256:x", DrainTimeoutSeconds: 60}
	if err := validateClusterMaintenanceTask(base); err == nil {
		t.Fatal("expected missing host timeout rejection")
	}
	base.HostActionTimeoutSeconds = 3600
	if err := validateClusterMaintenanceTask(base); err != nil {
		t.Fatal(err)
	}
}

func TestValidateExistingPatchJobRejectsSpecDrift(t *testing.T) {
	task := controlplane.ClusterMaintenanceTask{RunID: "run-1", ClusterID: "cluster-1", InventoryDigest: "sha256:inventory", HostActionTimeoutSeconds: 900}
	image := "registry.local/platform-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw, err := json.Marshal(buildOSPatchJob(task, "node-a", "uid-a", image))
	if err != nil {
		t.Fatal(err)
	}
	var job osPatchJobStatus
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	job.Metadata.UID = "job-uid"
	if err := validateExistingPatchJob(job, task, "node-a", "uid-a", image); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	job.Spec.Template.Spec.NodeName = "node-b"
	if err := validateExistingPatchJob(job, task, "node-a", "uid-a", image); err == nil {
		t.Fatal("expected node pin drift rejection")
	}
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	job.Metadata.UID = "job-uid"
	job.Spec.Template.Spec.Containers[0].Image = "registry.local/platform-agent:latest"
	if err := validateExistingPatchJob(job, task, "node-a", "uid-a", image); err == nil {
		t.Fatal("expected executor image drift rejection")
	}
}
