package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"platform.4so.io/factory/internal/installation"
	"strings"
	"testing"
)

func testKnownHostLine(host string, fill byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return host + " ssh-ed25519 " + base64.StdEncoding.EncodeToString(key)
}

func TestSSHKnownHostsStoreAndCoverage(t *testing.T) {
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.32", BundleDir: t.TempDir(), StateDir: state, System: LocalSystem{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.StoreSSHPrivateKey([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----")); err != nil {
		t.Fatal(err)
	}
	raw := testKnownHostLine("10.0.0.12", 1) + "\n" + testKnownHostLine("node-3.internal", 2) + "\n"
	status, err := runner.StoreSSHKnownHosts([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !status.PrivateKeyStored || !status.KnownHostsStored || len(status.Entries) != 2 {
		t.Fatalf("unexpected SSH trust status: %#v", status)
	}
	if err = runner.validateSSHIdentity(sshCredentialRef, "root"); err != nil {
		t.Fatal(err)
	}
	if err = runner.validateSSHHostTrust([]string{"10.0.0.12", "node-3.internal"}); err != nil {
		t.Fatal(err)
	}
	if err = runner.validateSSHHostTrust([]string{"10.0.0.99"}); err == nil || !strings.Contains(err.Error(), "no pinned host key") {
		t.Fatalf("missing peer trust was accepted: %v", err)
	}
}

func TestSSHTrustRejectsUnsafeTargetsAndKnownHosts(t *testing.T) {
	if err := validateSSHUser("-oProxyCommand=bad"); err == nil {
		t.Fatal("unsafe SSH user accepted")
	}
	for _, host := range []string{"-oProxyCommand=bad", "node name", "node/internal", "bad_name"} {
		if err := validateSSHHost(host); err == nil {
			t.Fatalf("unsafe SSH host %q accepted", host)
		}
	}
	if _, _, err := parseSSHKnownHosts([]byte("*.internal ssh-ed25519 " + base64.StdEncoding.EncodeToString(make([]byte, 32)))); err == nil {
		t.Fatal("wildcard known_hosts entry accepted")
	}
	if _, _, err := parseSSHKnownHosts([]byte("|1|hash|hash ssh-ed25519 " + base64.StdEncoding.EncodeToString(make([]byte, 32)))); err == nil {
		t.Fatal("hashed known_hosts entry accepted")
	}
	if _, _, err := parseSSHKnownHosts([]byte("[node.internal]:2222 ssh-ed25519 " + base64.StdEncoding.EncodeToString(make([]byte, 32)))); err == nil {
		t.Fatal("non-default SSH port known_hosts entry accepted")
	}
	entries, _, err := parseSSHKnownHosts([]byte("node.internal. ssh-ed25519 " + base64.StdEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Host != "node.internal" {
		t.Fatalf("known_hosts hostname was not canonicalized: %#v", entries)
	}
}

func TestHASSHCommandsUsePinnedTrustAndStreamedInput(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	root := t.TempDir()
	system := &SimulatedSystem{Root: root}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: state, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Start(context.Background(), haBootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.State != RunSucceeded {
		t.Fatalf("HA simulation failed: %s", run.LastError)
	}
	joined := strings.Join(system.Commands, "\n")
	for _, required := range []string{"StrictHostKeyChecking=yes", "UserKnownHostsFile=", "PasswordAuthentication=no", "IdentitiesOnly=yes", "<stdin>"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("HA SSH command contract missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"StrictHostKeyChecking=accept-new", "scp ", "base64 -d", "token:"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("HA SSH command leaked/used forbidden pattern %q:\n%s", forbidden, joined)
		}
	}
}

func TestHAPeerPreflightCommandIsReadOnlyAndChecksReadiness(t *testing.T) {
	command := haPeerPreflightCommand(installation.ApplianceSizing{MinimumVCPU: 8, MinimumMemoryGiB: 16, MinimumDiskGiB: 160, MinimumFreeDiskGiB: 120})
	for _, required := range []string{"uname -s", "id -u", "test -d /run/systemd/system", "systemctl show --property=Version --value", "timedatectl show --property=NTPSynchronized --value", "getconf _NPROCESSORS_ONLN", "df -Pk /var/lib", "findmnt -n -o FSTYPE -T /var/lib", "ip -4 route show default", "/etc/rancher/rke2", "/var/lib/rancher/rke2", "/etc/rancher/k3s", "/var/lib/rancher/k3s", "/etc/kubernetes", "/var/lib/kubelet", "/usr/local/bin/rke2", "/usr/local/bin/k3s", "/usr/local/bin/kubelet", "/usr/local/bin/kubeadm", "rke2-server.service", "rke2-agent.service", "k3s.service", "k3s-agent.service", "kubelet.service", "ss -H -ltn", "80 443 6443 9345"} {
		if !strings.Contains(command, required) {
			t.Fatalf("HA peer preflight command missing %q: %s", required, command)
		}
	}
	for _, forbidden := range []string{"mkdir ", "rm -", "curl ", "wget ", "systemctl enable", "systemctl start", "rke2-install"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("HA peer preflight command mutates host via %q: %s", forbidden, command)
		}
	}
}

func TestSSHTrustInputsCannotChangeDuringActiveBootstrap(t *testing.T) {
	runner := &Runner{stateDir: t.TempDir(), active: true}
	if err := runner.StoreSSHPrivateKey([]byte("-----BEGIN PRIVATE KEY-----\nblocked\n-----END PRIVATE KEY-----\n")); err == nil || !errors.Is(err, ErrBootstrapExecutionActive) {
		t.Fatalf("active bootstrap private-key replacement was not blocked: %v", err)
	}
	if _, err := runner.StoreSSHKnownHosts([]byte("node.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm\n")); err == nil || !errors.Is(err, ErrBootstrapExecutionActive) {
		t.Fatalf("active bootstrap host-trust replacement was not blocked: %v", err)
	}
}

func TestSSHTrustInputsRemainRepairableBetweenInterruptedAttempts(t *testing.T) {
	state := t.TempDir()
	runner := &Runner{stateDir: state, journal: NewJournal(state)}
	if err := runner.journal.Save(Run{ID: "bootstrap-interrupted", State: RunFailed}); err != nil {
		t.Fatal(err)
	}
	if err := runner.StoreSSHPrivateKey([]byte("-----BEGIN PRIVATE KEY-----\nrepair-input\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatalf("interrupted bootstrap must permit SSH credential repair before Resume: %v", err)
	}
}

func TestHAPeerTimePreparationSeparatesConnectedRepairFromDisconnectedVerify(t *testing.T) {
	connected := haPeerTimePreparationCommand(installation.ConnectivityConnected)
	for _, required := range []string{"time.windows.com", "time.apple.com", "rolex.ripe.net", "162.159.200.1", "162.159.200.123", "chronyc reload sources", "chronyc waitsync", "systemctl enable --now"} {
		if !strings.Contains(connected, required) {
			t.Fatalf("connected HA time preparation missing %q: %s", required, connected)
		}
	}
	disconnected := haPeerTimePreparationCommand(installation.ConnectivityDisconnected)
	for _, forbidden := range []string{"time.windows.com", "time.apple.com", "rolex.ripe.net", "systemctl enable --now", "apt-get install", "dnf install", "yum install"} {
		if strings.Contains(disconnected, forbidden) {
			t.Fatalf("disconnected HA time preparation mutates public time authority via %q: %s", forbidden, disconnected)
		}
	}
	if !strings.Contains(disconnected, "requires reachable local NTP") || !strings.Contains(disconnected, "NTPSynchronized") {
		t.Fatalf("disconnected HA time preparation must fail closed on local NTP: %s", disconnected)
	}
}
