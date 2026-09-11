package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const hostMaintenanceAuthority = "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1"

type hostMaintenanceResult struct {
	Authority      string   `json:"authority"`
	Action         string   `json:"action"`
	OSID           string   `json:"osId"`
	PackageManager string   `json:"packageManager"`
	Commands       []string `json:"commands"`
	RebootRequired bool     `json:"rebootRequired"`
	StartedAt      string   `json:"startedAt"`
	FinishedAt     string   `json:"finishedAt"`
}

type hostCommandRunner interface {
	Run(root, command string, args ...string) error
	Exists(root, path string) bool
}

type chrootHostRunner struct{}

func (chrootHostRunner) Run(root, command string, args ...string) error {
	root = filepath.Clean(root)
	if root == "" || root == "." || !filepath.IsAbs(root) {
		return fmt.Errorf("host root must be an absolute path")
	}
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	return cmd.Run()
}

func (chrootHostRunner) Exists(root, path string) bool {
	path = strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if path == "." || strings.HasPrefix(path, "..") {
		return false
	}
	info, err := os.Stat(filepath.Join(root, path))
	return err == nil && !info.IsDir()
}

func parseOSRelease(raw []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		out[strings.ToUpper(strings.TrimSpace(key))] = value
	}
	return out
}

func hostOSID(root string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "etc", "os-release"))
	if err != nil {
		return "", fmt.Errorf("read host /etc/os-release: %w", err)
	}
	values := parseOSRelease(raw)
	id := strings.ToLower(strings.TrimSpace(values["ID"]))
	if id == "" {
		return "", errors.New("host /etc/os-release has no ID")
	}
	return id, nil
}

func patchCommandForHost(root, osID string, runner hostCommandRunner) (manager string, commands [][]string, err error) {
	switch osID {
	case "ubuntu", "debian":
		if !runner.Exists(root, "/usr/bin/apt-get") {
			return "", nil, errors.New("apt-get is not present on the target host")
		}
		return "apt-get", [][]string{
			{"/usr/bin/apt-get", "update"},
			{"/usr/bin/apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"},
		}, nil
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol":
		if runner.Exists(root, "/usr/bin/dnf") {
			return "dnf", [][]string{{"/usr/bin/dnf", "-y", "upgrade", "--refresh"}}, nil
		}
		if runner.Exists(root, "/usr/bin/yum") {
			return "yum", [][]string{{"/usr/bin/yum", "-y", "update"}}, nil
		}
		return "", nil, errors.New("dnf/yum is not present on the target host")
	case "sles", "opensuse-leap", "opensuse-tumbleweed":
		if !runner.Exists(root, "/usr/bin/zypper") {
			return "", nil, errors.New("zypper is not present on the target host")
		}
		return "zypper", [][]string{{"/usr/bin/zypper", "--non-interactive", "patch"}}, nil
	default:
		return "", nil, fmt.Errorf("unsupported host OS %q for controlled patching", osID)
	}
}

func hostRebootRequired(root, osID string, runner hostCommandRunner) bool {
	if runner.Exists(root, "/var/run/reboot-required") || runner.Exists(root, "/run/reboot-required") {
		return true
	}
	// Enterprise Linux exposes needs-restarting when dnf-utils is installed. A
	// non-zero code from that command is meaningful, but the narrow runner
	// contract intentionally avoids treating command failure as a successful
	// reboot probe. The explicit marker above remains authoritative here.
	_ = osID
	return false
}

func executeHostOSPatch(root string, runner hostCommandRunner, now func() time.Time) (hostMaintenanceResult, error) {
	if runtime.GOOS != "linux" {
		return hostMaintenanceResult{}, errors.New("host maintenance executor is supported on Linux only")
	}
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	osID, err := hostOSID(root)
	if err != nil {
		return hostMaintenanceResult{}, err
	}
	manager, commands, err := patchCommandForHost(root, osID, runner)
	if err != nil {
		return hostMaintenanceResult{}, err
	}
	rendered := make([]string, 0, len(commands))
	for _, command := range commands {
		if len(command) == 0 {
			return hostMaintenanceResult{}, errors.New("empty patch command")
		}
		rendered = append(rendered, strings.Join(command, " "))
		if err := runner.Run(root, command[0], command[1:]...); err != nil {
			return hostMaintenanceResult{}, fmt.Errorf("host patch command %s failed: %w", command[0], err)
		}
	}
	finished := now().UTC()
	return hostMaintenanceResult{
		Authority:      hostMaintenanceAuthority,
		Action:         "OS_PATCH",
		OSID:           osID,
		PackageManager: manager,
		Commands:       rendered,
		RebootRequired: hostRebootRequired(root, osID, runner),
		StartedAt:      started.Format(time.RFC3339Nano),
		FinishedAt:     finished.Format(time.RFC3339Nano),
	}, nil
}

func writeTerminationResult(w io.Writer, result hostMaintenanceResult) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(result)
}

func runHostMaintenanceCommand(args []string) error {
	if len(args) == 0 || args[0] != "os-patch" {
		return errors.New("host-maintenance requires action os-patch")
	}
	root := "/host"
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--host-root":
			i++
			if i >= len(args) {
				return errors.New("--host-root requires a value")
			}
			root = args[i]
		default:
			return fmt.Errorf("unsupported host-maintenance argument %q", args[i])
		}
	}
	result, err := executeHostOSPatch(root, chrootHostRunner{}, time.Now)
	if err != nil {
		return err
	}
	// Kubernetes copies this file into the terminated-container message. The
	// cluster agent can therefore persist structured evidence without granting
	// log-streaming access or trusting free-form stdout.
	f, openErr := os.OpenFile("/dev/termination-log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if openErr == nil {
		_ = writeTerminationResult(f, result)
		_ = f.Close()
	}
	return writeTerminationResult(os.Stdout, result)
}
