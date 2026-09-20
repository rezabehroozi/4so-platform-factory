package virtualcluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

)

const Authority = "VIRTUAL_CLUSTER_PROFILE_AUTHORITY_V1"

type ProfileID string

const (
	ProfileDeveloper ProfileID = "developer"
	ProfileTeam      ProfileID = "team"
)

type Limits struct {
	MaxCPUMilli      int
	MaxMemoryMiB     int
	MaxStorageGiB    int
	MaxNamespaces    int
	MinSleepAfterMin int
	MaxSleepAfterMin int
}

type Profile struct {
	ID            ProfileID
	DeveloperMode bool
	Limits        Limits
}

var profiles = map[ProfileID]Profile{
	ProfileDeveloper: {
		ID: ProfileDeveloper, DeveloperMode: true,
		Limits: Limits{MaxCPUMilli: 4000, MaxMemoryMiB: 8192, MaxStorageGiB: 100, MaxNamespaces: 5, MinSleepAfterMin: 15, MaxSleepAfterMin: 1440},
	},
	ProfileTeam: {
		ID: ProfileTeam, DeveloperMode: false,
		Limits: Limits{MaxCPUMilli: 16000, MaxMemoryMiB: 32768, MaxStorageGiB: 500, MaxNamespaces: 20, MinSleepAfterMin: 0, MaxSleepAfterMin: 10080},
	},
}

type WorkspaceAuthority struct {
	WorkspaceID     string
	ProjectID       string
	WorkspaceDigest string
	BindingID       string
	BindingRevision int64
	HostClusterID   string
	HostNamespace   string
	BindingActive   bool
}

type Request struct {
	Name              string
	Profile           ProfileID
	KubernetesVersion string
	CPUMilli          int
	MemoryMiB         int
	StorageGiB        int
	MaxNamespaces     int
	SleepAfterMinutes int
}

type Plan struct {
	Authority         string
	ProjectID         string
	WorkspaceID       string
	WorkspaceDigest   string
	BindingID         string
	BindingRevision   int64
	HostClusterID     string
	HostNamespace     string
	Name              string
	Profile           ProfileID
	DeveloperMode     bool
	KubernetesVersion string
	CPUMilli          int
	MemoryMiB         int
	StorageGiB        int
	MaxNamespaces     int
	SleepAfterMinutes int
	DesiredDigest     string
	MutationEligible  bool
}

var (
	namePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,39}$")
	versionPattern = regexp.MustCompile("^v1\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
)

func Profiles() []Profile {
	return []Profile{profiles[ProfileDeveloper], profiles[ProfileTeam]}
}

func ProfileFor(id ProfileID) (Profile, bool) {
	p, ok := profiles[ProfileID(strings.ToLower(strings.TrimSpace(string(id))))]
	return p, ok
}

func BuildPlan(authority WorkspaceAuthority, request Request) (Plan, error) {
	authority.WorkspaceID = strings.TrimSpace(authority.WorkspaceID)
	authority.ProjectID = strings.TrimSpace(authority.ProjectID)
	authority.WorkspaceDigest = strings.TrimSpace(authority.WorkspaceDigest)
	authority.BindingID = strings.TrimSpace(authority.BindingID)
	authority.HostClusterID = strings.TrimSpace(authority.HostClusterID)
	authority.HostNamespace = strings.TrimSpace(authority.HostNamespace)
	if authority.WorkspaceID == "" || authority.ProjectID == "" || !strings.HasPrefix(authority.WorkspaceDigest, "sha256:") {
		return Plan{}, errors.New("workspace authority is incomplete")
	}
	if authority.BindingID == "" || authority.BindingRevision <= 0 || authority.HostClusterID == "" || authority.HostNamespace == "" {
		return Plan{}, errors.New("workspace binding host authority is incomplete")
	}
	if !authority.BindingActive {
		return Plan{}, errors.New("workspace binding must be ACTIVE")
	}

	request.Name = strings.ToLower(strings.TrimSpace(request.Name))
	if !namePattern.MatchString(request.Name) {
		return Plan{}, errors.New("virtual cluster name must be a DNS-style identifier up to 40 characters")
	}
	profile, ok := ProfileFor(request.Profile)
	if !ok {
		return Plan{}, fmt.Errorf("unsupported virtual cluster profile %q", request.Profile)
	}
	request.Profile = profile.ID
	request.KubernetesVersion = strings.TrimSpace(request.KubernetesVersion)
	if !versionPattern.MatchString(request.KubernetesVersion) {
		return Plan{}, errors.New("kubernetesVersion must be an exact v1.x.y version")
	}
	if request.CPUMilli < 250 || request.CPUMilli > profile.Limits.MaxCPUMilli {
		return Plan{}, fmt.Errorf("cpuMilli must be between 250 and %d for profile %s", profile.Limits.MaxCPUMilli, profile.ID)
	}
	if request.MemoryMiB < 512 || request.MemoryMiB > profile.Limits.MaxMemoryMiB {
		return Plan{}, fmt.Errorf("memoryMiB must be between 512 and %d for profile %s", profile.Limits.MaxMemoryMiB, profile.ID)
	}
	if request.StorageGiB < 1 || request.StorageGiB > profile.Limits.MaxStorageGiB {
		return Plan{}, fmt.Errorf("storageGiB must be between 1 and %d for profile %s", profile.Limits.MaxStorageGiB, profile.ID)
	}
	if request.MaxNamespaces < 1 || request.MaxNamespaces > profile.Limits.MaxNamespaces {
		return Plan{}, fmt.Errorf("maxNamespaces must be between 1 and %d for profile %s", profile.Limits.MaxNamespaces, profile.ID)
	}
	if profile.DeveloperMode {
		if request.SleepAfterMinutes < profile.Limits.MinSleepAfterMin || request.SleepAfterMinutes > profile.Limits.MaxSleepAfterMin {
			return Plan{}, fmt.Errorf("developer sleepAfterMinutes must be between %d and %d", profile.Limits.MinSleepAfterMin, profile.Limits.MaxSleepAfterMin)
		}
	} else if request.SleepAfterMinutes != 0 && (request.SleepAfterMinutes < profile.Limits.MinSleepAfterMin || request.SleepAfterMinutes > profile.Limits.MaxSleepAfterMin) {
		return Plan{}, fmt.Errorf("sleepAfterMinutes must be zero or between %d and %d", profile.Limits.MinSleepAfterMin, profile.Limits.MaxSleepAfterMin)
	}

	plan := Plan{
		Authority: Authority, ProjectID: authority.ProjectID, WorkspaceID: authority.WorkspaceID, WorkspaceDigest: authority.WorkspaceDigest,
		BindingID: authority.BindingID, BindingRevision: authority.BindingRevision, HostClusterID: authority.HostClusterID, HostNamespace: authority.HostNamespace,
		Name: request.Name, Profile: request.Profile, DeveloperMode: profile.DeveloperMode, KubernetesVersion: request.KubernetesVersion,
		CPUMilli: request.CPUMilli, MemoryMiB: request.MemoryMiB, StorageGiB: request.StorageGiB, MaxNamespaces: request.MaxNamespaces,
		SleepAfterMinutes: request.SleepAfterMinutes, MutationEligible: true,
	}
	raw, err := json.Marshal([]any{
		plan.Authority, plan.ProjectID, plan.WorkspaceID, plan.WorkspaceDigest, plan.BindingID, plan.BindingRevision,
		plan.HostClusterID, plan.HostNamespace, plan.Name, plan.Profile, plan.DeveloperMode, plan.KubernetesVersion,
		plan.CPUMilli, plan.MemoryMiB, plan.StorageGiB, plan.MaxNamespaces, plan.SleepAfterMinutes,
	})
	if err != nil {
		return Plan{}, fmt.Errorf("encode virtual cluster plan: %w", err)
	}
	sum := sha256.Sum256(raw)
	plan.DesiredDigest = "sha256:" + hex.EncodeToString(sum[:])
	return plan, nil
}
