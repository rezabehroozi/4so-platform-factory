package managedinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/bootmedia"
)

const ExecutorAuthority = "BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1"

type ConnectedInstallRuntime interface {
	InstallConnectedOKD(context.Context, Request, string) (map[string]any, error)
}

type ArtifactValidationRuntime interface {
	ValidateManagedInstallArtifacts(context.Context, Request, string) (map[string]any, error)
}

type AgentISOMediaValidator interface {
	ValidateAgentISOMedia(context.Context, Request, Artifact) (map[string]any, error)
}

type DisconnectedInstallRuntime interface {
	PrepareDisconnectedMirror(context.Context, Request, string) (map[string]any, error)
	InstallDisconnectedOKD(context.Context, Request, string) (map[string]any, error)
}

type ManagedClusterRegistrar interface {
	RegisterManagedCluster(context.Context, Request, string) (map[string]any, error)
}

type ConnectedInstaller interface {
	ConnectedInstallRuntime
	ManagedClusterRegistrar
}

type CompositeInstaller struct {
	InstallRuntime ConnectedInstallRuntime
	Registrar      ManagedClusterRegistrar
}

func (c CompositeInstaller) InstallConnectedOKD(ctx context.Context, req Request, token string) (map[string]any, error) {
	if c.InstallRuntime == nil {
		return nil, errors.New("connected install runtime is not configured")
	}
	return c.InstallRuntime.InstallConnectedOKD(ctx, req, token)
}

func (c CompositeInstaller) RegisterManagedCluster(ctx context.Context, req Request, token string) (map[string]any, error) {
	if c.Registrar == nil {
		return nil, errors.New("managed cluster registrar is not configured")
	}
	return c.Registrar.RegisterManagedCluster(ctx, req, token)
}

type Executor struct {
	BootProvider          bootmedia.Provider
	MediaResolver         MediaURLResolver
	ArtifactValidator     ArtifactValidationRuntime
	MediaValidator        AgentISOMediaValidator
	Installer             ConnectedInstaller
	DisconnectedInstaller DisconnectedInstallRuntime
}

func (e *Executor) ConnectedReady() bool {
	return e != nil && e.BootProvider != nil && e.MediaResolver != nil && e.ArtifactValidator != nil && e.MediaValidator != nil && e.Installer != nil
}

func (e *Executor) DisconnectedReady() bool {
	return e.ConnectedReady() && e.DisconnectedInstaller != nil
}

type machineEvidence struct {
	MachineID   string                 `json:"machineId"`
	Observation *bootmedia.Observation `json:"observation,omitempty"`
}

type stepEvidence struct {
	Authority     string            `json:"authority"`
	Step          Step              `json:"step"`
	RequestDigest string            `json:"requestDigest"`
	Machines      []machineEvidence `json:"machines,omitempty"`
	Result        map[string]any    `json:"result,omitempty"`
}

func bootRequest(req Request, machine Machine, mediaURL string) (bootmedia.Request, error) {
	iso, ok := ArtifactByName(req, "agent-iso")
	if !ok {
		return bootmedia.Request{}, errors.New("agent-iso artifact is required")
	}
	digest := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(iso.SHA256)), "sha256:")
	if strings.TrimSpace(mediaURL) == "" {
		mediaURL = iso.URL
	}
	return bootmedia.Request{
		OrganizationID:       req.OrganizationID,
		ProjectID:            req.ProjectID,
		MachineID:            machine.ID,
		Provider:             "redfish",
		Endpoint:             machine.Endpoint,
		CredentialRef:        machine.CredentialRef,
		MediaURL:             mediaURL,
		MediaSHA256:          digest,
		SystemResource:       machine.SystemResource,
		VirtualMediaResource: machine.VirtualMediaResource,
		IdempotencyKey:       req.ClusterName + ":" + machine.ID + ":" + req.TargetVersion,
	}, nil
}

func (e *Executor) ExecuteStep(ctx context.Context, step Step, req Request, operationToken string) ([]byte, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	digest, err := DigestRequest(canonical)
	if err != nil {
		return nil, err
	}
	result := stepEvidence{Authority: ExecutorAuthority, Step: step, RequestDigest: digest}
	switch step {
	case StepValidateArtifacts:
		if strings.TrimSpace(operationToken) == "" {
			return nil, errors.New("artifact validation operation token is required")
		}
		if e == nil || (!IsDisconnected(canonical) && !e.ConnectedReady()) || (IsDisconnected(canonical) && !e.DisconnectedReady()) {
			return nil, errors.New("managed OKD runtime is not fully configured for pre-mutation artifact validation")
		}
		workspaceEvidence, validationErr := e.ArtifactValidator.ValidateManagedInstallArtifacts(ctx, canonical, strings.TrimSpace(operationToken))
		if validationErr != nil {
			return nil, fmt.Errorf("validate exact managed OKD workspace artifacts: %w", validationErr)
		}
		iso, ok := ArtifactByName(canonical, "agent-iso")
		if !ok {
			return nil, errors.New("agent-iso artifact is required")
		}
		mediaEvidence, validationErr := e.MediaValidator.ValidateAgentISOMedia(ctx, canonical, iso)
		if validationErr != nil {
			return nil, fmt.Errorf("validate exact managed OKD agent ISO: %w", validationErr)
		}
		result.Result = map[string]any{
			"validated": true,
			"machineCount": len(canonical.Machines),
			"artifactCount": len(canonical.Artifacts),
			"connectivity": canonical.Connectivity,
			"workspace": workspaceEvidence,
			"agentISO": mediaEvidence,
			"preMutationValidation": true,
		}
	case StepPrepareMirror:
		if !IsDisconnected(canonical) {
			return nil, errors.New("disconnected mirror step is forbidden for connected request")
		}
		if e == nil || e.DisconnectedInstaller == nil {
			return nil, errors.New("disconnected OKD runtime is not configured")
		}
		if strings.TrimSpace(operationToken) == "" {
			return nil, errors.New("disconnected mirror operation token is required")
		}
		result.Result, err = e.DisconnectedInstaller.PrepareDisconnectedMirror(ctx, canonical, strings.TrimSpace(operationToken))
		if err != nil {
			return nil, fmt.Errorf("prepare disconnected OKD mirror: %w", err)
		}
	case StepAttachMedia, StepOneTimeBoot, StepPowerCycle, StepObserveBootstrap:
		if e == nil || e.BootProvider == nil {
			return nil, errors.New("boot-media provider is not configured")
		}
		iso, ok := ArtifactByName(canonical, "agent-iso")
		if !ok {
			return nil, errors.New("agent-iso artifact is required")
		}
		mediaURL := iso.URL
		if e.MediaResolver != nil {
			if strings.TrimSpace(operationToken) == "" {
				return nil, errors.New("managed install operation token is required for content-addressed boot media")
			}
			mediaURL, err = e.MediaResolver.ResolveAgentISOMediaURL(ctx, canonical, iso, strings.TrimSpace(operationToken))
			if err != nil {
				return nil, fmt.Errorf("resolve agent ISO boot media: %w", err)
			}
		}
		for _, machine := range canonical.Machines {
			br, buildErr := bootRequest(canonical, machine, mediaURL)
			if buildErr != nil {
				return nil, buildErr
			}
			entry := machineEvidence{MachineID: machine.ID}
			contextual, hasContext := e.BootProvider.(bootmedia.ContextualProvider)
			switch step {
			case StepAttachMedia:
				if hasContext {
					err = contextual.AttachContext(ctx, br)
				} else {
					err = e.BootProvider.Attach(br)
				}
			case StepOneTimeBoot:
				if hasContext {
					err = contextual.SetOneTimeBootContext(ctx, br)
				} else {
					err = e.BootProvider.SetOneTimeBoot(br)
				}
			case StepPowerCycle:
				if hasContext {
					err = contextual.PowerCycleContext(ctx, br)
				} else {
					err = e.BootProvider.PowerCycle(br)
				}
			case StepObserveBootstrap:
				var obs bootmedia.Observation
				if hasContext {
					obs, err = contextual.ObserveContext(ctx, br)
				} else {
					obs, err = e.BootProvider.Observe(br)
				}
				if err == nil && (!obs.Attached || !obs.OneTimeBootSet || !obs.Powered || strings.TrimSpace(obs.BootState) == "") {
					err = errors.New("boot-media observation does not prove bootstrap boot state")
				}
				entry.Observation = &obs
			}
			if err != nil {
				return nil, fmt.Errorf("%s machine %s: %w", step, machine.ID, err)
			}
			result.Machines = append(result.Machines, entry)
		}
		sort.Slice(result.Machines, func(i, j int) bool { return result.Machines[i].MachineID < result.Machines[j].MachineID })
	case StepConnectedInstall:
		if e == nil || e.Installer == nil {
			return nil, errors.New("connected OKD installer is not configured")
		}
		if strings.TrimSpace(operationToken) == "" {
			return nil, errors.New("connected install operation token is required")
		}
		result.Result, err = e.Installer.InstallConnectedOKD(ctx, canonical, strings.TrimSpace(operationToken))
		if err != nil {
			return nil, fmt.Errorf("connected OKD install: %w", err)
		}
	case StepDisconnectedInstall:
		if !IsDisconnected(canonical) {
			return nil, errors.New("disconnected install step is forbidden for connected request")
		}
		if e == nil || e.DisconnectedInstaller == nil {
			return nil, errors.New("disconnected OKD installer is not configured")
		}
		if strings.TrimSpace(operationToken) == "" {
			return nil, errors.New("disconnected install operation token is required")
		}
		result.Result, err = e.DisconnectedInstaller.InstallDisconnectedOKD(ctx, canonical, strings.TrimSpace(operationToken))
		if err != nil {
			return nil, fmt.Errorf("disconnected OKD install: %w", err)
		}
	case StepRegisterCluster:
		if e == nil || e.Installer == nil {
			return nil, errors.New("managed cluster registrar is not configured")
		}
		if strings.TrimSpace(operationToken) == "" {
			return nil, errors.New("managed cluster registration operation token is required")
		}
		result.Result, err = e.Installer.RegisterManagedCluster(ctx, canonical, strings.TrimSpace(operationToken))
		if err != nil {
			return nil, fmt.Errorf("managed cluster registration: %w", err)
		}
	case StepComplete:
		result.Result = map[string]any{"completed": true}
	default:
		return nil, fmt.Errorf("unknown managed install step %q", step)
	}
	return json.Marshal(result)
}
