package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/installation"
)

type cloneHostIdentity struct {
	Host      string
	Hostname  string
	MachineID string
	DMIUUID   string
	SSHKey    string
	MACs      []string
}

type cloneIdentityConflict struct {
	Field string
	Value string
	Hosts []string
}

const cloneIdentityProbeCommand = `set -eu
printf 'hostname=%s\n' "$(hostname)"
printf 'machine-id=%s\n' "$(cat /etc/machine-id)"
printf 'dmi-uuid=%s\n' "$(cat /sys/class/dmi/id/product_uuid)"
printf 'ssh-key=%s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
ip -o link | sed -n 's/.*link\/ether \([^ ]*\).*/mac=\1/p'
`

func parseCloneHostIdentity(host string, raw []byte) (cloneHostIdentity, error) {
	id := cloneHostIdentity{Host: host}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			id.Hostname = value
		case "machine-id":
			id.MachineID = strings.ToLower(value)
		case "dmi-uuid":
			id.DMIUUID = strings.ToLower(value)
		case "ssh-key":
			id.SSHKey = value
		case "mac":
			id.MACs = append(id.MACs, strings.ToLower(value))
		}
	}
	if id.Hostname == "" || id.MachineID == "" || id.DMIUUID == "" || id.SSHKey == "" {
		return cloneHostIdentity{}, fmt.Errorf("host %s clone identity is incomplete", host)
	}
	filtered := id.MACs[:0]
	for _, mac := range id.MACs {
		if mac != "00:00:00:00:00:00" {
			filtered = append(filtered, mac)
		}
	}
	id.MACs = filtered
	if len(id.MACs) == 0 {
		return cloneHostIdentity{}, fmt.Errorf("host %s has no physical MAC identity", host)
	}
	return id, nil
}

func cloneIdentityConflicts(ids []cloneHostIdentity) []cloneIdentityConflict {
	values := map[string]map[string][]string{}
	add := func(field, value, host string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		if values[field] == nil {
			values[field] = map[string][]string{}
		}
		values[field][value] = append(values[field][value], host)
	}
	for _, id := range ids {
		add("hostname", id.Hostname, id.Host)
		add("machine-id", id.MachineID, id.Host)
		add("dmi-uuid", id.DMIUUID, id.Host)
		add("ssh-host-key", id.SSHKey, id.Host)
		for _, mac := range id.MACs {
			add("mac", mac, id.Host)
		}
	}
	var out []cloneIdentityConflict
	for field, byValue := range values {
		for value, hosts := range byValue {
			if len(hosts) < 2 {
				continue
			}
			sort.Strings(hosts)
			out = append(out, cloneIdentityConflict{Field: field, Value: value, Hosts: hosts})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func (r *Runner) collectCloneIdentities(ctx context.Context, request installation.InstallRequest) ([]cloneHostIdentity, error) {
	addresses := request.Infrastructure.NodeAddresses
	if len(addresses) == 0 {
		return nil, errors.New("clone identity requires at least one management node")
	}
	localRaw, err := r.system.Output(ctx, "sh", []string{"-c", cloneIdentityProbeCommand}, nil)
	if err != nil {
		return nil, fmt.Errorf("probe local clone identity: %w", err)
	}
	local, err := parseCloneHostIdentity(addresses[0], localRaw)
	if err != nil {
		return nil, err
	}
	ids := []cloneHostIdentity{local}
	if request.ProfileID != "production-standard-ha" {
		return ids, nil
	}
	run := Run{Request: request}
	for _, host := range addresses[1:] {
		raw, err := r.system.Output(ctx, "ssh", r.sshArgs(run, host, cloneIdentityProbeCommand), nil)
		if err != nil {
			return nil, fmt.Errorf("probe clone identity %s: %w", host, err)
		}
		id, err := parseCloneHostIdentity(host, raw)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
func (r *Runner) verifyCloneSafety(ctx context.Context, request installation.InstallRequest) error {
	if r.simulation {
		return nil
	}
	ids, err := r.collectCloneIdentities(ctx, request)
	if err != nil {
		return err
	}
	conflicts := cloneIdentityConflicts(ids)
	if len(conflicts) == 0 {
		return nil
	}
	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		parts = append(parts, fmt.Sprintf("%s=%s hosts=%s", c.Field, c.Value, strings.Join(c.Hosts, ",")))
	}
	return fmt.Errorf("cloned host identity detected: %s", strings.Join(parts, "; "))
}

func cloneRepairCommand(index int, repairHostname, repairMachineID, repairSSH bool) string {
	parts := []string{"set -eu"}
	if repairHostname {
		parts = append(parts, fmt.Sprintf("hostnamectl set-hostname 4so-mgmt-%d", index+1))
	}
	if repairMachineID {
		parts = append(parts,
			"truncate -s 0 /etc/machine-id",
			"rm -f /var/lib/dbus/machine-id",
			"systemd-machine-id-setup",
			"command -v dbus-uuidgen >/dev/null 2>&1 && dbus-uuidgen --ensure=/var/lib/dbus/machine-id || true")
	}
	if repairSSH {
		parts = append(parts,
			"backup=/var/lib/4so-platform-installer/clone-hygiene/$(date +%s)",
			"mkdir -p \"$backup\"",
			"cp -a /etc/ssh/ssh_host_* \"$backup/\" 2>/dev/null || true",
			"rm -f /etc/ssh/ssh_host_*",
			"ssh-keygen -A",
			"sshd -t",
			"systemctl reload ssh 2>/dev/null || systemctl reload sshd",
			"printf '4SO_NEW_SSH_KEY=%s\\n' \"$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)\"")
	}
	parts = append(parts, "printf '4SO_CLONE_REPAIR_DONE\\n'")
	return strings.Join(parts, "; ")
}
func (r *Runner) replaceKnownHostDuringCloneRepair(host, publicKey string) error {
	fields := strings.Fields(strings.TrimSpace(publicKey))
	if len(fields) < 2 || !supportedSSHHostKeyType(fields[0]) {
		return errors.New("clone repair returned invalid SSH public key")
	}
	raw, err := os.ReadFile(r.sshKnownHostsPath())
	if err != nil {
		return err
	}
	var lines []string
	for _, original := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(original)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		remaining := make([]string, 0, len(strings.Split(parts[0], ",")))
		for _, token := range strings.Split(parts[0], ",") {
			normalized, _ := normalizeKnownHostToken(token)
			if normalized != host {
				remaining = append(remaining, token)
			}
		}
		if len(remaining) > 0 {
			lines = append(lines, strings.Join(remaining, ",")+" "+parts[1]+" "+parts[2])
		}
	}
	lines = append(lines, host+" "+fields[0]+" "+fields[1])
	_, normalized, err := parseSSHKnownHosts([]byte(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		return err
	}
	return writePrivateFile(r.sshKnownHostsPath(), normalized)
}

func cloneConflictHosts(conflicts []cloneIdentityConflict, field string) map[string]bool {
	out := map[string]bool{}
	for _, c := range conflicts {
		if c.Field != field {
			continue
		}
		for _, host := range c.Hosts[1:] {
			out[host] = true
		}
	}
	return out
}
func duplicateRepairTargets(ids []cloneHostIdentity, field string) map[string]bool {
	seen := map[string]string{}
	out := map[string]bool{}
	values := func(id cloneHostIdentity) []string {
		switch field {
		case "hostname":
			return []string{id.Hostname}
		case "machine-id":
			return []string{id.MachineID}
		case "ssh-host-key":
			return []string{id.SSHKey}
		default:
			return nil
		}
	}
	for _, id := range ids {
		for _, value := range values(id) {
			key := strings.ToLower(strings.TrimSpace(value))
			if key == "" {
				continue
			}
			if _, exists := seen[key]; exists {
				out[id.Host] = true
			} else {
				seen[key] = id.Host
			}
		}
	}
	return out
}

func (r *Runner) prepareCloneSafety(ctx context.Context, request installation.InstallRequest) error {
	if r.simulation {
		return nil
	}
	ids, err := r.collectCloneIdentities(ctx, request)
	if err != nil {
		return err
	}
	conflicts := cloneIdentityConflicts(ids)
	for _, c := range conflicts {
		if c.Field == "dmi-uuid" || c.Field == "mac" {
			return fmt.Errorf("cloned infrastructure identity requires hypervisor repair before bootstrap: %s=%s hosts=%s", c.Field, c.Value, strings.Join(c.Hosts, ","))
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	hostnameTargets := duplicateRepairTargets(ids, "hostname")
	machineTargets := duplicateRepairTargets(ids, "machine-id")
	sshTargets := duplicateRepairTargets(ids, "ssh-host-key")
	if request.ProfileID != "production-standard-ha" {
		return r.verifyCloneSafety(ctx, request)
	}
	if err := r.validateSSHIdentity(request.Infrastructure.CredentialRef, request.Infrastructure.SSHUser); err != nil {
		return err
	}
	if err := r.validateSSHHostTrust(request.Infrastructure.NodeAddresses[1:]); err != nil {
		return err
	}
	run := Run{Request: request}
	for index, host := range request.Infrastructure.NodeAddresses[1:] {
		repairHostname := hostnameTargets[host]
		repairMachine := machineTargets[host]
		repairSSH := sshTargets[host]
		if !repairHostname && !repairMachine && !repairSSH {
			continue
		}
		raw, err := r.system.Output(ctx, "ssh", r.sshArgs(run, host, cloneRepairCommand(index+1, repairHostname, repairMachine, repairSSH)), nil)
		if err != nil {
			return fmt.Errorf("repair cloned identity %s: %w", host, err)
		}
		if repairSSH {
			var publicKey string
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "4SO_NEW_SSH_KEY=") {
					publicKey = strings.TrimPrefix(line, "4SO_NEW_SSH_KEY=")
				}
			}
			if publicKey == "" {
				return fmt.Errorf("repair cloned SSH identity %s returned no authenticated replacement key", host)
			}
			if err = r.replaceKnownHostDuringCloneRepair(host, publicKey); err != nil {
				return fmt.Errorf("update SSH trust after clone repair %s: %w", host, err)
			}
			if err = r.remoteRun(ctx, run, host, "true"); err != nil {
				return fmt.Errorf("reconnect after clone repair %s: %w", host, err)
			}
		}
	}
	return r.verifyCloneSafety(ctx, request)
}
