package hostdeployment

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
)

const (
	AdmissionPass    = "PASS"
	AdmissionWarning = "WARNING"
	AdmissionBlocked = "BLOCKED"
	AdmissionSkipped = "SKIPPED"

	admissionWarningReserveBytes int64 = 64 << 20
)

type AdmissionCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

type FilesystemCapacity struct {
	Device          uint64 `json:"device"`
	ProbePath       string `json:"probePath"`
	RequiredBytes   int64  `json:"requiredBytes"`
	AvailableBytes  int64  `json:"availableBytes"`
	RequiredInodes  uint64 `json:"requiredInodes"`
	AvailableInodes uint64 `json:"availableInodes"`
	ReadOnly        bool   `json:"readOnly"`
}

type HostAdmissionReport struct {
	SchemaVersion         int                  `json:"schemaVersion"`
	Ready                 bool                 `json:"ready"`
	Mode                  string               `json:"mode"`
	TargetOS              string               `json:"targetOs"`
	TargetArchitecture    string               `json:"targetArchitecture"`
	TargetVersion         string               `json:"targetVersion"`
	ExistingBinaryVersion string               `json:"existingBinaryVersion,omitempty"`
	ExistingBundleVersion string               `json:"existingBundleVersion,omitempty"`
	UpgradeMode           string               `json:"upgradeMode"`
	AllowDowngrade        bool                 `json:"allowDowngrade"`
	Checks                []AdmissionCheck     `json:"checks"`
	Filesystems           []FilesystemCapacity `json:"filesystems"`
	GeneratedAt           time.Time            `json:"generatedAt"`
	Digest                string               `json:"digest"`
}

type capacityNeed struct {
	path   string
	bytes  int64
	inodes uint64
}

type filesystemNeed struct {
	device uint64
	probe  string
	bytes  int64
	inodes uint64
	statfs syscall.Statfs_t
}

func buildHostAdmission(spec Spec, plan Plan, options Options) HostAdmissionReport {
	report := HostAdmissionReport{
		SchemaVersion:      1,
		Ready:              true,
		Mode:               "live",
		TargetOS:           runtime.GOOS,
		TargetArchitecture: runtime.GOARCH,
		TargetVersion:      plan.Version,
		UpgradeMode:        "INSTALL",
		AllowDowngrade:     spec.Spec.Admission.AllowDowngrade,
		GeneratedAt:        now(options).UTC(),
	}
	if plan.Root != "/" {
		report.Mode = "staged"
	}
	add := func(id, status, summary, detail string) {
		report.Checks = append(report.Checks, AdmissionCheck{ID: id, Status: status, Summary: summary, Detail: detail})
		if status == AdmissionBlocked {
			report.Ready = false
		}
	}

	if runtime.GOOS != "linux" {
		add("target-os", AdmissionBlocked, "installer host deployment requires Linux", runtime.GOOS)
	} else {
		add("target-os", AdmissionPass, "Linux target confirmed", runtime.GOOS)
	}
	if plan.Root == "/" && os.Geteuid() != 0 {
		add("root-privileges", AdmissionBlocked, "live host deployment requires root privileges", "run platformctl as root")
	} else if plan.Root == "/" {
		add("root-privileges", AdmissionPass, "root privileges confirmed", "")
	} else {
		add("root-privileges", AdmissionSkipped, "root privilege check skipped for staged root", plan.Root)
	}

	binaryArch, archErr := installerBinaryArchitecture(spec.Spec.InstallerBinary)
	switch {
	case archErr == nil && binaryArch == runtime.GOARCH:
		add("binary-architecture", AdmissionPass, "installer binary architecture matches host", binaryArch)
	case archErr == nil:
		add("binary-architecture", AdmissionBlocked, "installer binary architecture does not match host", binaryArch+" != "+runtime.GOARCH)
	case errors.Is(archErr, errNotELF):
		add("binary-architecture", AdmissionWarning, "installer binary architecture could not be read from a non-ELF test artifact", archErr.Error())
	default:
		add("binary-architecture", AdmissionBlocked, "installer binary architecture inspection failed", archErr.Error())
	}

	if plan.Root == "/" && (plan.Service.Enable || plan.Service.Start) {
		runner := options.Runner
		if runner == nil {
			runner = LocalCommandRunner{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, systemctlErr := runner.Run(ctx, "systemctl", "show", "--property=Version", "--value")
		cancel()
		if systemctlErr != nil {
			add("systemd", AdmissionBlocked, "a running systemd manager is required for live service deployment", systemctlErr.Error())
		} else if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
			add("systemd", AdmissionBlocked, "systemd is not running on the target host", "/run/systemd/system is unavailable")
		} else {
			add("systemd", AdmissionPass, "systemd is available and running", "")
		}
	} else {
		add("systemd", AdmissionSkipped, "systemd activation is not required for this staged plan", "")
	}

	for _, target := range []string{plan.Paths.Binary, plan.Paths.Bundle, plan.Paths.Environment, plan.Paths.Unit, plan.Paths.State, plan.Paths.BackupDirectory, plan.Paths.TLSCertificate, plan.Paths.TLSPrivateKey} {
		if strings.TrimSpace(target) == "" {
			continue
		}
		if err := rejectSymlinkAncestors(plan.Root, target); err != nil {
			add("path-safety", AdmissionBlocked, "deployment destination contains a symlink ancestor", err.Error())
			break
		}
	}
	if report.Ready || !hasCheck(report.Checks, "path-safety") {
		add("path-safety", AdmissionPass, "deployment destination paths have no symlink ancestors", "")
	}

	existingBinary, binaryErr := existingBinaryVersion(plan.Paths.Binary)
	existingBundle, bundleErr := existingBundleVersion(plan.Paths.Bundle)
	report.ExistingBinaryVersion = existingBinary
	report.ExistingBundleVersion = existingBundle
	if binaryErr != nil && !errors.Is(binaryErr, os.ErrNotExist) {
		add("existing-binary", AdmissionWarning, "existing installer binary version could not be verified; deployment will repair it", binaryErr.Error())
	}
	if bundleErr != nil && !errors.Is(bundleErr, os.ErrNotExist) {
		add("existing-bundle", AdmissionWarning, "existing bundle version could not be verified; deployment will replace it", bundleErr.Error())
	}
	report.UpgradeMode = determineUpgradeMode(plan.Version, existingBinary, existingBundle)
	if downgradeFrom := highestVersion(existingBinary, existingBundle); downgradeFrom != "" && compareVersion(plan.Version, downgradeFrom) < 0 {
		if spec.Spec.Admission != nil && spec.Spec.Admission.AllowDowngrade {
			add("version-transition", AdmissionWarning, "explicit downgrade is enabled", downgradeFrom+" -> "+plan.Version)
		} else {
			add("version-transition", AdmissionBlocked, "downgrade is blocked unless spec.admission.allowDowngrade is true", downgradeFrom+" -> "+plan.Version)
		}
	} else {
		add("version-transition", AdmissionPass, "version transition is allowed", report.UpgradeMode)
	}

	needs, needErr := deploymentCapacityNeeds(spec, plan)
	if needErr != nil {
		add("capacity", AdmissionBlocked, "deployment capacity requirements could not be calculated", needErr.Error())
	} else {
		filesystems, capacityErr := inspectFilesystemCapacity(needs)
		report.Filesystems = filesystems
		if capacityErr != nil {
			add("capacity", AdmissionBlocked, "target filesystem capacity could not be inspected", capacityErr.Error())
		} else {
			blocked := false
			warning := false
			for _, volume := range filesystems {
				if volume.ReadOnly || volume.AvailableBytes < volume.RequiredBytes || volume.AvailableInodes < volume.RequiredInodes {
					blocked = true
				}
				if !blocked && volume.AvailableBytes-volume.RequiredBytes < admissionWarningReserveBytes {
					warning = true
				}
			}
			switch {
			case blocked:
				add("capacity", AdmissionBlocked, "insufficient writable filesystem capacity for atomic deployment and backup", capacitySummary(filesystems))
			case warning:
				add("capacity", AdmissionWarning, "deployment fits but remaining free space is below the recommended reserve", capacitySummary(filesystems))
			default:
				add("capacity", AdmissionPass, "filesystem byte and inode capacity is sufficient", capacitySummary(filesystems))
			}
		}
	}

	sort.SliceStable(report.Checks, func(i, j int) bool { return report.Checks[i].ID < report.Checks[j].ID })
	sort.SliceStable(report.Filesystems, func(i, j int) bool { return report.Filesystems[i].Device < report.Filesystems[j].Device })
	report.Digest = admissionDigest(report)
	return report
}

func admissionBlockedSummary(report HostAdmissionReport) string {
	var reasons []string
	for _, check := range report.Checks {
		if check.Status == AdmissionBlocked {
			reasons = append(reasons, check.ID+": "+check.Summary)
		}
	}
	if len(reasons) == 0 {
		return "host admission did not pass"
	}
	return strings.Join(reasons, "; ")
}

func admissionDigest(report HostAdmissionReport) string {
	copy := report
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	return digest(raw)
}

func hasCheck(checks []AdmissionCheck, id string) bool {
	for _, check := range checks {
		if check.ID == id {
			return true
		}
	}
	return false
}

var errNotELF = errors.New("installer binary is not an ELF executable")

func installerBinaryArchitecture(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "bad magic") {
			return "", errNotELF
		}
		return "", err
	}
	defer f.Close()
	switch f.Machine {
	case elf.EM_X86_64:
		return "amd64", nil
	case elf.EM_AARCH64:
		return "arm64", nil
	default:
		return strings.ToLower(f.Machine.String()), nil
	}
}

func existingBinaryVersion(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	return readBinaryVersion(path)
}

func existingBundleVersion(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	status, err := bootstrap.InspectBundle(path, true)
	if err != nil {
		return "", err
	}
	return status.Version, nil
}

func determineUpgradeMode(target, binary, bundle string) string {
	existing := highestVersion(binary, bundle)
	if existing == "" {
		if binary != "" || bundle != "" {
			return "REPAIR"
		}
		return "INSTALL"
	}
	cmp := compareVersion(target, existing)
	switch {
	case cmp > 0:
		return "UPGRADE"
	case cmp < 0:
		return "DOWNGRADE"
	default:
		return "REINSTALL"
	}
}

func highestVersion(values ...string) string {
	var highest string
	for _, value := range values {
		if value == "" {
			continue
		}
		if highest == "" || compareVersion(value, highest) > 0 {
			highest = value
		}
	}
	return highest
}

func compareVersion(a, b string) int {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return strings.Compare(a, b)
	}
	for i := range pa {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseVersion(value string) ([3]int, bool) {
	var result [3]int
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return result, false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return result, false
		}
		result[i] = n
	}
	return result, true
}

func rejectSymlinkAncestors(root, target string) error {
	cleanRoot := filepath.Clean(root)
	cleanTarget := filepath.Clean(target)
	rel, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("target %s escapes root %s", cleanTarget, cleanRoot)
	}
	current := cleanRoot
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", current)
		}
	}
	return nil
}

func deploymentCapacityNeeds(spec Spec, plan Plan) ([]capacityNeed, error) {
	binaryInfo, err := os.Stat(spec.Spec.InstallerBinary)
	if err != nil {
		return nil, err
	}
	bundleBytes, bundleInodes, err := treeMetrics(spec.Spec.BundleDirectory)
	if err != nil {
		return nil, err
	}
	needs := []capacityNeed{
		{path: filepath.Dir(plan.Paths.Binary), bytes: binaryInfo.Size(), inodes: 2},
		{path: filepath.Dir(plan.Paths.Bundle), bytes: bundleBytes, inodes: bundleInodes + 2},
		{path: filepath.Dir(plan.Paths.Environment), bytes: int64(len(renderEnvironment(spec))), inodes: 2},
		{path: filepath.Dir(plan.Paths.Unit), bytes: int64(len(renderUnit())), inodes: 2},
	}
	if plan.Paths.TLSCertificate != "" {
		cert, err := os.Stat(spec.Spec.TLS.CertificateFile)
		if err != nil {
			return nil, err
		}
		key, err := os.Stat(spec.Spec.TLS.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		needs = append(needs, capacityNeed{path: filepath.Dir(plan.Paths.TLSCertificate), bytes: cert.Size() + key.Size(), inodes: 4})
	}
	backupBytes, backupInodes := existingBackupMetrics(plan)
	needs = append(needs, capacityNeed{path: filepath.Dir(plan.Paths.State), bytes: backupBytes + 4<<20, inodes: backupInodes + 16})
	return needs, nil
}

func existingBackupMetrics(plan Plan) (int64, uint64) {
	var bytes int64
	var inodes uint64
	for _, path := range []string{plan.Paths.Binary, plan.Paths.Environment, plan.Paths.Unit, plan.Paths.TLSCertificate, plan.Paths.TLSPrivateKey} {
		if path == "" {
			continue
		}
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			bytes += info.Size()
			inodes++
		}
	}
	return bytes, inodes
}

func treeMetrics(root string) (int64, uint64, error) {
	var bytes int64
	var inodes uint64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle tree contains symlink %s", path)
		}
		inodes++
		if info.Mode().IsRegular() {
			bytes += info.Size()
		}
		return nil
	})
	return bytes, inodes, err
}

func inspectFilesystemCapacity(needs []capacityNeed) ([]FilesystemCapacity, error) {
	grouped := map[uint64]*filesystemNeed{}
	for _, need := range needs {
		probe, err := nearestExistingAncestor(need.path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(probe)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("cannot inspect filesystem device for %s", probe)
		}
		var fsStat syscall.Statfs_t
		if err := syscall.Statfs(probe, &fsStat); err != nil {
			return nil, err
		}
		item := grouped[uint64(stat.Dev)]
		if item == nil {
			item = &filesystemNeed{device: uint64(stat.Dev), probe: probe, statfs: fsStat}
			grouped[item.device] = item
		}
		item.bytes += need.bytes
		item.inodes += need.inodes
	}
	result := make([]FilesystemCapacity, 0, len(grouped))
	for _, item := range grouped {
		result = append(result, FilesystemCapacity{
			Device:          item.device,
			ProbePath:       item.probe,
			RequiredBytes:   item.bytes,
			AvailableBytes:  int64(item.statfs.Bavail) * int64(item.statfs.Bsize),
			RequiredInodes:  item.inodes,
			AvailableInodes: item.statfs.Ffree,
			ReadOnly:        item.statfs.Flags&1 != 0,
		})
	}
	return result, nil
}

func nearestExistingAncestor(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				current = filepath.Dir(current)
				continue
			}
			return current, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", path)
		}
		current = parent
	}
}

func capacitySummary(items []FilesystemCapacity) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("dev=%d required=%d available=%d inodes=%d/%d readonly=%t", item.Device, item.RequiredBytes, item.AvailableBytes, item.RequiredInodes, item.AvailableInodes, item.ReadOnly))
	}
	return strings.Join(parts, "; ")
}
