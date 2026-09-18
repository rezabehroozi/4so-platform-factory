package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/installation"
)

const (
	longhornNamespace     = "longhorn-system"
	longhornMountRoot     = "/var/lib/longhorn/disks"
	storageClaimRoot      = "/var/lib/4so-platform-installer/storage-claims"
	storageClaimAuthority = "MANAGEMENT_PLANE_STORAGE_CLAIM_V1"
)

func longhornDiskLabel(index int) string {
	return fmt.Sprintf("4so-lh-%02d", index)
}

func longhornDiskMount(index int) string {
	return fmt.Sprintf("%s/disk-%02d", longhornMountRoot, index)
}

func storageDeviceClaimPath(index int) string {
	return fmt.Sprintf("%s/disk-%02d.claim", storageClaimRoot, index)
}

func validateLocalStorageDeviceList(devices []string) error {
	if len(devices) == 0 {
		return fmt.Errorf("at least one storage device is required")
	}
	seen := make(map[string]struct{}, len(devices))
	for _, raw := range devices {
		device := strings.TrimSpace(raw)
		if device == "" || !strings.HasPrefix(device, "/dev/") || strings.Contains(device, "..") {
			return fmt.Errorf("storage device %q must be a canonical /dev path", raw)
		}
		for _, ch := range strings.TrimPrefix(device, "/dev/") {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '/' {
				continue
			}
			return fmt.Errorf("storage device %q contains unsafe characters", raw)
		}
		if _, ok := seen[device]; ok {
			return fmt.Errorf("storage device %q is duplicated", device)
		}
		seen[device] = struct{}{}
	}
	return nil
}

// VerifyLocalHAStorageDevices runs the same fail-closed block-device admission
// used by production HA bootstrap, but only against the local node. It is
// intended for staged Lab/recovery workflows where the Kubernetes quorum is
// already healthy and SSH fan-out is neither necessary nor desirable.
func VerifyLocalHAStorageDevices(ctx context.Context, devices []string) error {
	if err := validateLocalStorageDeviceList(devices); err != nil {
		return err
	}
	system := LocalSystem{}
	if !system.IsRoot() {
		return fmt.Errorf("local HA storage verification requires root")
	}
	if _, err := system.Output(ctx, "sh", []string{"-c", storageDeviceProbeCommand(devices)}, nil); err != nil {
		return fmt.Errorf("verify local HA storage devices: %w", err)
	}
	return nil
}

// PrepareLocalHAStorageDevices performs the idempotent claim-before-format
// lifecycle used by bootstrap. Blank whole disks are formatted only after the
// durable 4SO claim is persisted; already-owned disks are verified/reused.
func PrepareLocalHAStorageDevices(ctx context.Context, devices []string) error {
	if err := validateLocalStorageDeviceList(devices); err != nil {
		return err
	}
	system := LocalSystem{}
	if !system.IsRoot() {
		return fmt.Errorf("local HA storage preparation requires root")
	}
	if _, err := system.Output(ctx, "sh", []string{"-c", storageDevicePrepareCommand(devices)}, nil); err != nil {
		return fmt.Errorf("prepare local HA storage devices: %w", err)
	}
	return nil
}

func storageDeviceProbeCommand(devices []string) string {
	command := `set -eu; command -v lsblk >/dev/null 2>&1; command -v findmnt >/dev/null 2>&1; command -v readlink >/dev/null 2>&1; command -v blkid >/dev/null 2>&1; command -v wipefs >/dev/null 2>&1; command -v mkfs.ext4 >/dev/null 2>&1; command -v mountpoint >/dev/null 2>&1; root_source="$(findmnt -n -o SOURCE /)"; root_real="$(readlink -f "$root_source" 2>/dev/null || printf '%s' "$root_source")"; root_parent="$(lsblk -ndo PKNAME "$root_real" 2>/dev/null | head -n1 || true)"; if [ -n "$root_parent" ]; then root_disk="/dev/$root_parent"; else root_disk="$root_real"; fi`
	for index, device := range devices {
		label := longhornDiskLabel(index)
		mount := longhornDiskMount(index)
		marker := mount + "/.4so-storage-owner"
		claim := storageDeviceClaimPath(index)
		command += "; dev=" + haShellQuote(device) +
			`; canonical="$(readlink -f "$dev" 2>/dev/null || true)"; [ -n "$canonical" ] && [ -b "$canonical" ] || { echo "storage device is missing or not block-backed: $dev" >&2; exit 18; }; [ "$canonical" != "$root_real" ] && [ "$canonical" != "$root_disk" ] || { echo "storage device resolves to the root/system disk: $dev -> $canonical" >&2; exit 18; }; dtype="$(lsblk -ndo TYPE "$canonical" | head -n1)"; [ "$dtype" = disk ] || { echo "storage device must be a whole disk: $dev type=$dtype" >&2; exit 18; }; [ "$(lsblk -nrpo NAME "$canonical" | sed '/^[[:space:]]*$/d' | wc -l)" -eq 1 ] || { echo "storage device has child partitions or mappings: $dev" >&2; exit 18; }; base="$(basename "$canonical")"; if [ -d "/sys/class/block/$base/holders" ] && [ -n "$(ls -A "/sys/class/block/$base/holders" 2>/dev/null)" ]; then echo "storage device has active holders: $dev" >&2; exit 18; fi; [ "$(lsblk -ndo RO "$canonical" | head -n1)" = 0 ] || { echo "storage device is read-only: $dev" >&2; exit 18; }; [ "$(lsblk -ndo RM "$canonical" | head -n1)" = 0 ] || { echo "storage device is removable: $dev" >&2; exit 18; }; fstype="$(blkid -s TYPE -o value "$canonical" 2>/dev/null || true)"; fslabel="$(blkid -s LABEL -o value "$canonical" 2>/dev/null || true)"; signatures="$(wipefs -n "$canonical" 2>/dev/null | tail -n +2 | sed '/^[[:space:]]*$/d')"; mounts="$(lsblk -nrpo MOUNTPOINTS "$canonical" | sed '/^[[:space:]]*$/d')"; if [ -z "$fstype" ]; then [ -z "$signatures" ] || { echo "unowned storage signatures exist on $dev" >&2; exit 18; }; else [ "$fstype" = ext4 ] && [ "$fslabel" = ` + haShellQuote(label) + ` ] || { echo "storage device contains non-4SO filesystem/signature: $dev type=$fstype label=$fslabel" >&2; exit 18; }; claim_ok=false; if [ -f ` + haShellQuote(claim) + ` ]; then claim_authority="$(sed -n '1p' ` + haShellQuote(claim) + `)"; claim_device="$(sed -n '2p' ` + haShellQuote(claim) + `)"; [ "$claim_authority" = ` + haShellQuote(storageClaimAuthority) + ` ] && [ "$claim_device" = "$canonical" ] && claim_ok=true; fi; marker_ok=false; if [ "$mounts" = ` + haShellQuote(mount) + ` ] && [ -f ` + haShellQuote(marker) + ` ]; then marker_authority="$(sed -n '1p' ` + haShellQuote(marker) + `)"; marker_device="$(sed -n '2p' ` + haShellQuote(marker) + `)"; [ "$marker_authority" = MANAGEMENT_PLANE_STORAGE_DEVICE_V1 ] && [ "$marker_device" = "$canonical" ] && marker_ok=true; fi; [ "$claim_ok" = true ] || [ "$marker_ok" = true ] || { echo "storage device has 4SO-like label without durable ownership claim: $dev" >&2; exit 18; }; fi; if [ -n "$mounts" ] && [ "$mounts" != ` + haShellQuote(mount) + ` ]; then echo "storage device is mounted outside its 4SO mountpoint: $dev mounts=$mounts" >&2; exit 18; fi`
	}
	return command
}

func storageDevicePrepareCommand(devices []string) string {
	command := storageDeviceProbeCommand(devices)
	for index, device := range devices {
		label := longhornDiskLabel(index)
		mount := longhornDiskMount(index)
		marker := mount + "/.4so-storage-owner"
		claim := storageDeviceClaimPath(index)
		command += "; dev=" + haShellQuote(device) +
			`; canonical="$(readlink -f "$dev")"; mkdir -p ` + haShellQuote(storageClaimRoot) + `; claim_tmp="$(mktemp ` + haShellQuote(storageClaimRoot+"/.claim.XXXXXX") + `)"; printf '` + storageClaimAuthority + `\n%s\n' "$canonical" > "$claim_tmp"; chmod 0600 "$claim_tmp"; mv -f "$claim_tmp" ` + haShellQuote(claim) + `; sync; fstype="$(blkid -s TYPE -o value "$canonical" 2>/dev/null || true)"; if [ -z "$fstype" ]; then mkfs.ext4 -F -L ` + haShellQuote(label) + ` "$canonical" >/dev/null; else [ "$fstype" = ext4 ] && [ "$(blkid -s LABEL -o value "$canonical" 2>/dev/null || true)" = ` + haShellQuote(label) + ` ] || { echo "storage device changed after admission: $dev" >&2; exit 19; }; fi; mkdir -p ` + haShellQuote(mount) + `; uuid="$(blkid -s UUID -o value "$canonical")"; [ -n "$uuid" ] || { echo "storage device UUID unavailable after format: $dev" >&2; exit 19; }; entry="UUID=$uuid ` + mount + ` ext4 defaults,noatime,nofail 0 2"; if grep -Eq '^[^#]+[[:space:]]+` + mount + `[[:space:]]+' /etc/fstab && ! grep -Fqx "$entry" /etc/fstab; then echo "conflicting fstab entry for ` + mount + `" >&2; exit 19; fi; if ! grep -Fqx "$entry" /etc/fstab; then tmp="$(mktemp /etc/4so-fstab.XXXXXX)"; cat /etc/fstab > "$tmp"; printf '%s\n' "$entry" >> "$tmp"; chmod 0644 "$tmp"; mv -f "$tmp" /etc/fstab; sync; fi; mountpoint -q ` + haShellQuote(mount) + ` || mount ` + haShellQuote(mount) + `; printf 'MANAGEMENT_PLANE_STORAGE_DEVICE_V1\n%s\n' "$canonical" > ` + haShellQuote(marker) + `; chmod 0600 ` + haShellQuote(marker) + `; sync`
	}
	return command
}

func (r *Runner) verifyHAStorageDevices(ctx context.Context, request installation.InstallRequest) (string, error) {
	if request.ProfileID != "production-standard-ha" {
		return "dedicated HA storage devices are not required by this profile", nil
	}
	if len(request.Infrastructure.StorageDataDevices) == 0 || request.Infrastructure.StorageDeviceMode != "format-empty" {
		return "", fmt.Errorf("production HA requires explicit format-empty storage data devices")
	}
	command := storageDeviceProbeCommand(request.Infrastructure.StorageDataDevices)
	if _, err := r.system.Output(ctx, "sh", []string{"-c", command}, nil); err != nil {
		return "", fmt.Errorf("local HA storage device admission: %w", err)
	}
	if r.simulation {
		return fmt.Sprintf("%d dedicated storage device(s) declared; simulation does not inspect remote block devices", len(request.Infrastructure.StorageDataDevices)), nil
	}
	run := Run{Request: request}
	for _, peer := range request.Infrastructure.NodeAddresses[1:] {
		if _, err := r.system.Output(ctx, "ssh", r.sshArgs(run, peer, command), nil); err != nil {
			return "", fmt.Errorf("HA storage device admission on %s: %w", peer, err)
		}
	}
	return fmt.Sprintf("%d dedicated storage device(s) are blank or 4SO-owned on all %d management nodes and exclude the root disk", len(request.Infrastructure.StorageDataDevices), len(request.Infrastructure.NodeAddresses)), nil
}

func (r *Runner) prepareHAStorageDevices(ctx context.Context, run Run) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	command := storageDevicePrepareCommand(run.Request.Infrastructure.StorageDataDevices)
	if _, err := r.system.Output(ctx, "sh", []string{"-c", command}, nil); err != nil {
		return fmt.Errorf("prepare local HA storage devices: %w", err)
	}
	for _, peer := range run.Request.Infrastructure.NodeAddresses[1:] {
		if _, err := r.system.Output(ctx, "ssh", r.sshArgs(run, peer, command), nil); err != nil {
			return fmt.Errorf("prepare HA storage devices on %s: %w", peer, err)
		}
	}
	return nil
}

func storageDeviceResetCommand(devices []string) string {
	command := `set -eu; command -v readlink >/dev/null 2>&1; command -v blkid >/dev/null 2>&1; command -v wipefs >/dev/null 2>&1; command -v lsblk >/dev/null 2>&1; command -v mountpoint >/dev/null 2>&1; command -v findmnt >/dev/null 2>&1`
	for index, device := range devices {
		label := longhornDiskLabel(index)
		mount := longhornDiskMount(index)
		marker := mount + "/.4so-storage-owner"
		claim := storageDeviceClaimPath(index)
		command += "; dev=" + haShellQuote(device) +
			`; canonical="$(readlink -f "$dev" 2>/dev/null || true)"; [ -n "$canonical" ] && [ -b "$canonical" ] || { echo "reset storage device is missing: $dev" >&2; exit 41; }; fstype="$(blkid -s TYPE -o value "$canonical" 2>/dev/null || true)"; fslabel="$(blkid -s LABEL -o value "$canonical" 2>/dev/null || true)"; signatures="$(wipefs -n "$canonical" 2>/dev/null | tail -n +2 | sed '/^[[:space:]]*$/d')"; if [ -z "$fstype" ] && [ -z "$signatures" ]; then :; else [ "$fstype" = ext4 ] && [ "$fslabel" = ` + haShellQuote(label) + ` ] || { echo "refusing to reset non-4SO storage device: $dev type=$fstype label=$fslabel" >&2; exit 41; }; mounts="$(lsblk -nrpo MOUNTPOINTS "$canonical" | sed '/^[[:space:]]*$/d')"; [ "$mounts" = ` + haShellQuote(mount) + ` ] || { echo "refusing to reset storage device without exact 4SO mount ownership: $dev mounts=$mounts" >&2; exit 41; }; mountpoint -q ` + haShellQuote(mount) + ` || { echo "refusing to reset unmounted 4SO storage device: $dev" >&2; exit 41; }; [ -f ` + haShellQuote(marker) + ` ] || { echo "refusing to reset storage device without 4SO ownership marker: $dev" >&2; exit 41; }; marker_authority="$(sed -n '1p' ` + haShellQuote(marker) + `)"; marker_device="$(sed -n '2p' ` + haShellQuote(marker) + `)"; [ "$marker_authority" = MANAGEMENT_PLANE_STORAGE_DEVICE_V1 ] && [ "$marker_device" = "$canonical" ] || { echo "refusing to reset storage device with mismatched 4SO ownership marker: $dev" >&2; exit 41; }; source="$(findmnt -n -o SOURCE --target ` + haShellQuote(mount) + `)"; source_real="$(readlink -f "$source" 2>/dev/null || true)"; [ "$source_real" = "$canonical" ] || { echo "refusing to reset storage device mounted from unexpected source: $dev source=$source" >&2; exit 41; }; [ -f ` + haShellQuote(claim) + ` ] || { echo "refusing to reset storage device without durable 4SO claim: $dev" >&2; exit 41; }; claim_authority="$(sed -n '1p' ` + haShellQuote(claim) + `)"; claim_device="$(sed -n '2p' ` + haShellQuote(claim) + `)"; [ "$claim_authority" = ` + haShellQuote(storageClaimAuthority) + ` ] && [ "$claim_device" = "$canonical" ] || { echo "refusing to reset storage device with mismatched durable 4SO claim: $dev" >&2; exit 41; }; umount ` + haShellQuote(mount) + `; tmp="$(mktemp /etc/4so-fstab-reset.XXXXXX)"; awk '$2 != "` + mount + `" {print}' /etc/fstab > "$tmp"; chmod 0644 "$tmp"; mv -f "$tmp" /etc/fstab; sync; wipefs -a "$canonical" >/dev/null; sync; rm -f ` + haShellQuote(marker) + ` ` + haShellQuote(claim) + ` 2>/dev/null || true; rmdir ` + haShellQuote(mount) + ` 2>/dev/null || true; fi`
	}
	return command
}

func storageDeviceBlankVerificationCommand(devices []string) string {
	command := `set -eu; command -v readlink >/dev/null 2>&1; command -v wipefs >/dev/null 2>&1; command -v blkid >/dev/null 2>&1`
	for _, device := range devices {
		command += "; dev=" + haShellQuote(device) +
			`; canonical="$(readlink -f "$dev" 2>/dev/null || true)"; [ -n "$canonical" ] && [ -b "$canonical" ] || { echo "reset storage device is missing: $dev" >&2; exit 42; }; [ -z "$(blkid -s TYPE -o value "$canonical" 2>/dev/null || true)" ] || { echo "filesystem remains after storage reset: $dev" >&2; exit 42; }; [ -z "$(wipefs -n "$canonical" 2>/dev/null | tail -n +2 | sed '/^[[:space:]]*$/d')" ] || { echo "signature remains after storage reset: $dev" >&2; exit 42; }`
	}
	return command
}

func (r *Runner) resetHAStorageDevices(ctx context.Context, request installation.InstallRequest) error {
	if request.ProfileID != "production-standard-ha" || r.simulation || len(request.Infrastructure.StorageDataDevices) == 0 {
		return nil
	}
	command := storageDeviceResetCommand(request.Infrastructure.StorageDataDevices)
	run := Run{Request: request}
	for _, peer := range request.Infrastructure.NodeAddresses[1:] {
		if _, err := r.system.Output(ctx, "ssh", r.sshArgs(run, peer, command), nil); err != nil {
			return fmt.Errorf("reset HA storage devices on %s: %w", peer, err)
		}
	}
	if _, err := r.system.Output(ctx, "sh", []string{"-c", command}, nil); err != nil {
		return fmt.Errorf("reset local HA storage devices: %w", err)
	}
	return nil
}

func (r *Runner) verifyHAStorageReset(ctx context.Context, request installation.InstallRequest) error {
	if request.ProfileID != "production-standard-ha" || r.simulation || len(request.Infrastructure.StorageDataDevices) == 0 {
		return nil
	}
	command := storageDeviceBlankVerificationCommand(request.Infrastructure.StorageDataDevices)
	run := Run{Request: request}
	if _, err := r.system.Output(ctx, "sh", []string{"-c", command}, nil); err != nil {
		return fmt.Errorf("verify local HA storage reset: %w", err)
	}
	for _, peer := range request.Infrastructure.NodeAddresses[1:] {
		if _, err := r.system.Output(ctx, "ssh", r.sshArgs(run, peer, command), nil); err != nil {
			return fmt.Errorf("verify HA storage reset on %s: %w", peer, err)
		}
	}
	return nil
}

type longhornNodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Disks map[string]map[string]any `json:"disks"`
		} `json:"spec"`
	} `json:"items"`
}

func desiredLonghornDisks(existing map[string]map[string]any, deviceCount int) map[string]map[string]any {
	out := make(map[string]map[string]any, len(existing)+deviceCount)
	for name, disk := range existing {
		copyDisk := make(map[string]any, len(disk))
		for key, value := range disk {
			copyDisk[key] = value
		}
		copyDisk["allowScheduling"] = false
		out[name] = copyDisk
	}
	for index := 0; index < deviceCount; index++ {
		mount := longhornDiskMount(index)
		name := fmt.Sprintf("4so-data-%02d", index)
		for existingName, disk := range out {
			if strings.TrimSpace(fmt.Sprint(disk["path"])) == mount {
				name = existingName
				break
			}
		}
		out[name] = map[string]any{
			"path":            mount,
			"allowScheduling": true,
			"storageReserved": 0,
			"tags":            []string{"4so-managed"},
			"diskType":        "filesystem",
		}
	}
	return out
}

func longhornDisksReady(disks map[string]map[string]any, deviceCount int) bool {
	wanted := make(map[string]bool, deviceCount)
	for index := 0; index < deviceCount; index++ {
		wanted[longhornDiskMount(index)] = false
	}
	for _, disk := range disks {
		path := strings.TrimSpace(fmt.Sprint(disk["path"]))
		allowed, _ := disk["allowScheduling"].(bool)
		if _, ok := wanted[path]; ok {
			if !allowed {
				return false
			}
			wanted[path] = true
			continue
		}
		if allowed {
			return false
		}
	}
	for _, ready := range wanted {
		if !ready {
			return false
		}
	}
	return true
}

func (r *Runner) configureLonghornNodeStorage(ctx context.Context, run Run) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kc := "/etc/rancher/rke2/rke2.yaml"
	var nodes longhornNodeList
	err := waitUntil(ctx, 3*time.Second, 10*time.Minute, func() error {
		raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kc, "-n", longhornNamespace, "get", "nodes.longhorn.io", "-o", "json"}, nil)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &nodes); err != nil {
			return err
		}
		if len(nodes.Items) != len(run.Request.Infrastructure.NodeAddresses) {
			return fmt.Errorf("expected %d Longhorn nodes, got %d", len(run.Request.Infrastructure.NodeAddresses), len(nodes.Items))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("wait for Longhorn node inventory: %w", err)
	}
	for _, node := range nodes.Items {
		disks := desiredLonghornDisks(node.Spec.Disks, len(run.Request.Infrastructure.StorageDataDevices))
		patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"allowScheduling": true, "disks": disks}})
		if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kc, "-n", longhornNamespace, "patch", "nodes.longhorn.io/" + node.Metadata.Name, "--type=merge", "-p", string(patch)}, nil); err != nil {
			return fmt.Errorf("bind Longhorn storage on %s: %w", node.Metadata.Name, err)
		}
	}
	return waitUntil(ctx, 3*time.Second, 5*time.Minute, func() error {
		raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kc, "-n", longhornNamespace, "get", "nodes.longhorn.io", "-o", "json"}, nil)
		if err != nil {
			return err
		}
		var observed longhornNodeList
		if err = json.Unmarshal(raw, &observed); err != nil {
			return err
		}
		if len(observed.Items) != len(run.Request.Infrastructure.NodeAddresses) {
			return fmt.Errorf("Longhorn node count changed during storage binding")
		}
		for _, node := range observed.Items {
			if !longhornDisksReady(node.Spec.Disks, len(run.Request.Infrastructure.StorageDataDevices)) {
				return fmt.Errorf("Longhorn node %s has not converged to dedicated 4SO disks", node.Metadata.Name)
			}
		}
		return nil
	})
}
