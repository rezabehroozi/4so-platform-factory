package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneIdentityConflictsAndRepairTargetsPreserveFirstNode(t *testing.T) {
	ids := []cloneHostIdentity{
		{Host: "10.0.0.1", Hostname: "clone", MachineID: "m1", DMIUUID: "d1", SSHKey: "ssh-ed25519 AAAA", MACs: []string{"00:11:22:33:44:55"}},
		{Host: "10.0.0.2", Hostname: "clone", MachineID: "m1", DMIUUID: "d2", SSHKey: "ssh-ed25519 AAAA", MACs: []string{"00:11:22:33:44:66"}},
		{Host: "10.0.0.3", Hostname: "node3", MachineID: "m3", DMIUUID: "d3", SSHKey: "ssh-ed25519 BBBB", MACs: []string{"00:11:22:33:44:77"}},
	}
	conflicts := cloneIdentityConflicts(ids)
	if len(conflicts) != 3 {
		t.Fatalf("conflicts=%#v", conflicts)
	}
	for _, field := range []string{"hostname", "machine-id", "ssh-host-key"} {
		targets := duplicateRepairTargets(ids, field)
		if targets["10.0.0.1"] || !targets["10.0.0.2"] || targets["10.0.0.3"] {
			t.Fatalf("%s repair targets=%#v", field, targets)
		}
	}
}
func TestCloneIdentityConflictsFailClosedForHypervisorIdentity(t *testing.T) {
	ids := []cloneHostIdentity{
		{Host: "a", Hostname: "a", MachineID: "m1", DMIUUID: "same", SSHKey: "ssh-ed25519 A", MACs: []string{"00:11:22:33:44:55"}},
		{Host: "b", Hostname: "b", MachineID: "m2", DMIUUID: "same", SSHKey: "ssh-ed25519 B", MACs: []string{"00:11:22:33:44:55"}},
	}
	conflicts := cloneIdentityConflicts(ids)
	fields := map[string]bool{}
	for _, conflict := range conflicts {
		fields[conflict.Field] = true
	}
	if !fields["dmi-uuid"] || !fields["mac"] {
		t.Fatalf("hypervisor conflicts=%#v", conflicts)
	}
}

func TestCloneRepairCommandPreservesAccessContract(t *testing.T) {
	command := cloneRepairCommand(1, true, true, true)
	for _, required := range []string{"hostnamectl set-hostname 4so-mgmt-2", "systemd-machine-id-setup", "cp -a /etc/ssh/ssh_host_", "ssh-keygen -A", "sshd -t", "systemctl reload ssh", "4SO_NEW_SSH_KEY="} {
		if !strings.Contains(command, required) {
			t.Fatalf("repair command missing %q: %s", required, command)
		}
	}
	if strings.Contains(command, "systemctl restart ssh") || strings.Contains(command, "reboot") {
		t.Fatalf("repair command must preserve the authenticated session: %s", command)
	}
}
func TestReplaceKnownHostDuringCloneRepairReplacesOnlyTarget(t *testing.T) {
	state := t.TempDir()
	runner := &Runner{stateDir: state}
	if err := os.MkdirAll(filepath.Dir(runner.sshKnownHostsPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := strings.Replace(testKnownHostLine("10.0.0.2", 1), "10.0.0.2", "10.0.0.2,10.0.0.3", 1) + "\n"
	if err := writePrivateFile(runner.sshKnownHostsPath(), []byte(initial)); err != nil {
		t.Fatal(err)
	}
	newLine := testKnownHostLine("ignored", 3)
	fields := strings.Fields(newLine)
	if err := runner.replaceKnownHostDuringCloneRepair("10.0.0.2", fields[1]+" "+fields[2]); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(runner.sshKnownHostsPath())
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := parseSSHKnownHosts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%#v", entries)
	}
	seen := map[string]string{}
	for _, entry := range entries {
		seen[entry.Host] = entry.Fingerprint
	}
	if seen["10.0.0.2"] == "" || seen["10.0.0.3"] == "" {
		t.Fatalf("hosts=%#v", seen)
	}
	if seen["10.0.0.2"] == seen["10.0.0.3"] {
		t.Fatalf("target key was not replaced: %#v", seen)
	}
}
