package bootstrap

import (
	"time"

	"platform.4so.io/factory/internal/installation"
)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type BundleManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Version             string `json:"version"`
		SourceReleaseDigest string `json:"sourceReleaseDigest"`
	} `json:"metadata"`
	Spec struct {
		RKE2 struct {
			Version          string     `json:"version"`
			Installer        Artifact   `json:"installer"`
			InstallArtifacts []Artifact `json:"installArtifacts"`
			ImageArchives    []Artifact `json:"imageArchives"`
		} `json:"rke2"`
		Airgap struct {
			Complete       bool     `json:"complete"`
			Index          Artifact `json:"index"`
			RequiredImages []string `json:"requiredImages"`
		} `json:"airgap"`
		Workloads struct {
			ImageArchives         []Artifact `json:"imageArchives"`
			PostgreSQLImage       string     `json:"postgresqlImage"`
			PlatformAPIImage      string     `json:"platformApiImage"`
			ForgejoImage          string     `json:"forgejoImage"`
			ZotImage              string     `json:"zotImage"`
			KeycloakImage         string     `json:"keycloakImage"`
			MaintenanceImage      string     `json:"maintenanceImage"`
			GitOpsManifest        Artifact   `json:"gitOpsManifest"`
			GitOpsHAManifest      Artifact   `json:"gitOpsHAManifest,omitempty"`
			CloudNativePGManifest Artifact   `json:"cloudNativePGManifest"`
			StorageManifest       Artifact   `json:"storageManifest"`
			OCMManifest           Artifact   `json:"ocmManifest"`
			FleetAgentImage       string     `json:"fleetAgentImage"`
			RuntimeProbeImage     string     `json:"runtimeProbeImage"`
		} `json:"workloads"`
	} `json:"spec"`
}

type StepState string

const (
	StepPending   StepState = "PENDING"
	StepRunning   StepState = "RUNNING"
	StepSucceeded StepState = "SUCCEEDED"
	StepFailed    StepState = "FAILED"
	StepSkipped   StepState = "SKIPPED"
)

type RunState string

const (
	RunPending   RunState = "PENDING"
	RunRunning   RunState = "RUNNING"
	RunSucceeded RunState = "SUCCEEDED"
	RunFailed    RunState = "FAILED"
)

type Step struct {
	Key        string     `json:"key"`
	Title      string     `json:"title"`
	State      StepState  `json:"state"`
	Attempt    int        `json:"attempt"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}

type Run struct {
	ID              string                      `json:"id"`
	Version         string                      `json:"version"`
	State           RunState                    `json:"state"`
	Request         installation.InstallRequest `json:"request"`
	SpecDigest      string                      `json:"specDigest"`
	BundleDigest    string                      `json:"bundleDigest"`
	PreflightDigest string                      `json:"preflightDigest"`
	Steps           []Step                      `json:"steps"`
	CreatedAt       time.Time                   `json:"createdAt"`
	UpdatedAt       time.Time                   `json:"updatedAt"`
	LastError       string                      `json:"lastError,omitempty"`
	Simulation      bool                        `json:"simulation"`
}

type StartRequest struct {
	Installation installation.InstallRequest `json:"installation"`
}

type Status struct {
	ExecutionEnabled bool   `json:"executionEnabled"`
	BundleDirectory  string `json:"bundleDirectory"`
	StateDirectory   string `json:"stateDirectory"`
	Run              *Run   `json:"run,omitempty"`
}
