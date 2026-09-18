package bootstrap

import (
	"strings"
	"testing"
)

func TestStorageDeviceProbeFailsClosedOnSystemAndForeignState(t *testing.T) {
	command := storageDeviceProbeCommand([]string{"/dev/sdb", "/dev/disk/by-id/wwn-test"})
	for _, contract := range []string{
		"storage device resolves to the root/system disk",
		"storage device must be a whole disk",
		"storage device has child partitions or mappings",
		"storage device has active holders",
		"storage device is read-only",
		"storage device is removable",
		"unowned storage signatures exist",
		"storage device contains non-4SO filesystem/signature",
		"storage device is mounted outside its 4SO mountpoint",
	} {
		if !strings.Contains(command, contract) {
			t.Fatalf("storage device admission command missing fail-closed contract %q", contract)
		}
	}
	if strings.Contains(command, "wipefs -a") || strings.Contains(command, "mkfs.ext4") && !strings.Contains(command, "command -v mkfs.ext4") {
		t.Fatalf("read-only storage admission unexpectedly contains destructive mutation: %s", command)
	}
}

func TestStorageDevicePrepareIsExplicitAndResumeSafe(t *testing.T) {
	command := storageDevicePrepareCommand([]string{"/dev/sdb"})
	for _, contract := range []string{
		"4so-lh-00",
		"/var/lib/longhorn/disks/disk-00",
		"storage device changed after admission",
		"mkfs.ext4 -F",
		"MANAGEMENT_PLANE_STORAGE_DEVICE_V1",
		"mountpoint -q",
		"UUID=$uuid",
		"conflicting fstab entry",
	} {
		if !strings.Contains(command, contract) {
			t.Fatalf("storage preparation command missing %q", contract)
		}
	}
	rootGuard := strings.Index(command, "storage device resolves to the root/system disk")
	format := strings.Index(command, "mkfs.ext4 -F")
	if rootGuard < 0 || format < 0 || rootGuard > format {
		t.Fatalf("destructive format is not ordered after root-disk admission")
	}
}

func TestDesiredLonghornDisksDisableImplicitRootScheduling(t *testing.T) {
	existing := map[string]map[string]any{
		"default-disk": {
			"path":            "/var/lib/longhorn",
			"allowScheduling": true,
			"storageReserved": float64(0),
		},
	}
	got := desiredLonghornDisks(existing, 3)
	if allowed, _ := got["default-disk"]["allowScheduling"].(bool); allowed {
		t.Fatalf("implicit root-backed Longhorn disk remained schedulable: %#v", got["default-disk"])
	}
	for index := 0; index < 3; index++ {
		path := longhornDiskMount(index)
		found := false
		for _, disk := range got {
			if strings.TrimSpace(disk["path"].(string)) == path {
				allowed, _ := disk["allowScheduling"].(bool)
				if !allowed {
					t.Fatalf("4SO-managed Longhorn disk %s is not schedulable", path)
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("4SO-managed Longhorn disk %s missing", path)
		}
	}
	if !longhornDisksReady(got, 3) {
		t.Fatalf("expected dedicated Longhorn disk map to be ready: %#v", got)
	}
}

func TestLonghornDisksReadyRejectsAnyForeignSchedulableDisk(t *testing.T) {
	got := desiredLonghornDisks(nil, 1)
	got["foreign-root"] = map[string]any{"path": "/var/lib/longhorn", "allowScheduling": true}
	if longhornDisksReady(got, 1) {
		t.Fatalf("foreign root-backed Longhorn disk must fail readiness")
	}
}
