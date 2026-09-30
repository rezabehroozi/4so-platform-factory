package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const ApplicationDeploymentPlanAuthority = "APPLICATION_DEPLOYMENT_PLAN_V1"

var (
	applicationCPUQuantityPattern    = regexp.MustCompile(`^[1-9][0-9]*m$`)
	applicationMemoryQuantityPattern = regexp.MustCompile(`^[1-9][0-9]*(?:Mi|Gi)$`)
)

type ApplicationRuntimeSpec struct {
	Replicas      int    `json:"replicas"`
	ContainerPort int    `json:"containerPort"`
	ServicePort   int    `json:"servicePort,omitempty"`
	CPURequest    string `json:"cpuRequest"`
	CPULimit      string `json:"cpuLimit"`
	MemoryRequest string `json:"memoryRequest"`
	MemoryLimit   string `json:"memoryLimit"`
}

type ApplicationDeploymentPlan struct {
	Authority                string                 `json:"authority"`
	ProjectID                string                 `json:"projectId"`
	ReleaseID                string                 `json:"releaseId"`
	ReleaseDigest            string                 `json:"releaseDigest"`
	WorkloadImageReference   string                 `json:"workloadImageReference"`
	EnvironmentBindingID     string                 `json:"environmentBindingId"`
	EnvironmentBindingRevision int64                `json:"environmentBindingRevision"`
	EnvironmentBindingDigest string                 `json:"environmentBindingDigest"`
	WorkspaceID              string                 `json:"workspaceId"`
	WorkspaceBindingID       string                 `json:"workspaceBindingId"`
	WorkspaceBindingRevision int64                  `json:"workspaceBindingRevision"`
	ClusterID                string                 `json:"clusterId"`
	Namespace                string                 `json:"namespace"`
	Environment              string                 `json:"environment"`
	WorkloadName             string                 `json:"workloadName"`
	RuntimeSpec              ApplicationRuntimeSpec `json:"runtimeSpec"`
	RuntimeSpecDigest        string                 `json:"runtimeSpecDigest"`
	RenderedResources        []map[string]any       `json:"renderedResources"`
	RenderedDigest           string                 `json:"renderedDigest"`
	RuntimeMutationPerformed bool                   `json:"runtimeMutationPerformed"`
	PhysicalCertificationInferred bool              `json:"physicalCertificationInferred"`
}

func normalizeApplicationRuntimeSpec(in ApplicationRuntimeSpec) (ApplicationRuntimeSpec, error) {
	out := in
	out.CPURequest = strings.TrimSpace(out.CPURequest)
	out.CPULimit = strings.TrimSpace(out.CPULimit)
	out.MemoryRequest = strings.TrimSpace(out.MemoryRequest)
	out.MemoryLimit = strings.TrimSpace(out.MemoryLimit)
	if out.Replicas < 1 || out.Replicas > 50 {
		return ApplicationRuntimeSpec{}, fmt.Errorf("%w: replicas must be 1..50", ErrValidation)
	}
	if out.ContainerPort < 1 || out.ContainerPort > 65535 {
		return ApplicationRuntimeSpec{}, fmt.Errorf("%w: containerPort must be 1..65535", ErrValidation)
	}
	if out.ServicePort < 0 || out.ServicePort > 65535 {
		return ApplicationRuntimeSpec{}, fmt.Errorf("%w: servicePort must be 0..65535", ErrValidation)
	}
	if !applicationCPUQuantityPattern.MatchString(out.CPURequest) || !applicationCPUQuantityPattern.MatchString(out.CPULimit) ||
		!applicationMemoryQuantityPattern.MatchString(out.MemoryRequest) || !applicationMemoryQuantityPattern.MatchString(out.MemoryLimit) {
		return ApplicationRuntimeSpec{}, fmt.Errorf("%w: application CPU/memory quantities must use positive m/Mi/Gi values", ErrValidation)
	}
	return out, nil
}

func applicationDeploymentWorkloadName(name string) string {
	name = strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(strings.TrimSpace(name)))
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return strings.Trim(name[:54], "-") + "-" + hex.EncodeToString(sum[:4])
}

func ResolveApplicationDeploymentPlan(release ApplicationRelease, binding EnvironmentBinding, workspaceBinding WorkspaceBinding, runtime ApplicationRuntimeSpec) (ApplicationDeploymentPlan, error) {
	var err error
	release, err = NormalizeApplicationRelease(release)
	if err != nil {
		return ApplicationDeploymentPlan{}, err
	}
	binding, err = NormalizeEnvironmentBinding(binding)
	if err != nil {
		return ApplicationDeploymentPlan{}, err
	}
	workspaceBinding, err = NormalizeWorkspaceBinding(workspaceBinding)
	if err != nil {
		return ApplicationDeploymentPlan{}, err
	}
	runtime, err = normalizeApplicationRuntimeSpec(runtime)
	if err != nil {
		return ApplicationDeploymentPlan{}, err
	}
	if release.WorkloadImageReference == "" {
		return ApplicationDeploymentPlan{}, fmt.Errorf("%w: legacy application release has no exact workload artifact", ErrPrerequisite)
	}
	if binding.ProjectID != release.ProjectID || binding.ReleaseID != release.ID || binding.ReleaseDigest != release.Digest {
		return ApplicationDeploymentPlan{}, fmt.Errorf("%w: environment binding release authority mismatch", ErrPrerequisite)
	}
	if workspaceBinding.ID != binding.WorkspaceBindingID || workspaceBinding.WorkspaceID != binding.WorkspaceID ||
		workspaceBinding.ProjectID != binding.ProjectID || workspaceBinding.ClusterID != binding.ClusterID ||
		workspaceBinding.Namespace != binding.Namespace || workspaceBinding.Revision != binding.WorkspaceBindingRevision ||
		workspaceBinding.State != WorkspaceBindingActive {
		return ApplicationDeploymentPlan{}, fmt.Errorf("%w: environment binding WorkspaceBinding authority changed", ErrPrerequisite)
	}
	workloadName := applicationDeploymentWorkloadName(release.Name)
	if workloadName == "" {
		return ApplicationDeploymentPlan{}, fmt.Errorf("%w: rendered application workload name is empty", ErrValidation)
	}
	runtimeDigest := digestApplicationPlatformMaterial(runtime)
	labels := map[string]any{
		"app.kubernetes.io/name": workloadName,
		"app.kubernetes.io/managed-by": "4so-platform-factory",
		"platform.4so.io/environment-binding": binding.ID,
	}
	annotations := map[string]any{
		"platform.4so.io/application-release-digest": release.Digest,
		"platform.4so.io/environment-binding-digest": binding.Digest,
		"platform.4so.io/runtime-spec-digest": runtimeDigest,
	}
	deployment := map[string]any{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": map[string]any{
			"name": workloadName,
			"namespace": binding.Namespace,
			"labels": labels,
			"annotations": annotations,
		},
		"spec": map[string]any{
			"replicas": runtime.Replicas,
			"revisionHistoryLimit": 3,
			"strategy": map[string]any{
				"type": "RollingUpdate",
				"rollingUpdate": map[string]any{"maxUnavailable": 0, "maxSurge": 1},
			},
			"selector": map[string]any{"matchLabels": map[string]any{
				"app.kubernetes.io/name": workloadName,
				"platform.4so.io/environment-binding": binding.ID,
			}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"containers": []any{map[string]any{
						"name": "app",
						"image": release.WorkloadImageReference,
						"imagePullPolicy": "IfNotPresent",
						"ports": []any{map[string]any{"name": "app", "containerPort": runtime.ContainerPort, "protocol": "TCP"}},
						"resources": map[string]any{
							"requests": map[string]any{"cpu": runtime.CPURequest, "memory": runtime.MemoryRequest},
							"limits": map[string]any{"cpu": runtime.CPULimit, "memory": runtime.MemoryLimit},
						},
					}},
				},
			},
		},
	}
	resources := []map[string]any{deployment}
	if runtime.ServicePort > 0 {
		resources = append(resources, map[string]any{
			"apiVersion": "v1",
			"kind": "Service",
			"metadata": map[string]any{
				"name": workloadName,
				"namespace": binding.Namespace,
				"labels": labels,
				"annotations": annotations,
			},
			"spec": map[string]any{
				"type": "ClusterIP",
				"selector": map[string]any{
					"app.kubernetes.io/name": workloadName,
					"platform.4so.io/environment-binding": binding.ID,
				},
				"ports": []any{map[string]any{"name": "app", "port": runtime.ServicePort, "targetPort": runtime.ContainerPort, "protocol": "TCP"}},
			},
		})
	}
	renderedDigest := digestApplicationPlatformMaterial(resources)
	return ApplicationDeploymentPlan{
		Authority: ApplicationDeploymentPlanAuthority,
		ProjectID: release.ProjectID,
		ReleaseID: release.ID,
		ReleaseDigest: release.Digest,
		WorkloadImageReference: release.WorkloadImageReference,
		EnvironmentBindingID: binding.ID,
		EnvironmentBindingRevision: binding.Revision,
		EnvironmentBindingDigest: binding.Digest,
		WorkspaceID: binding.WorkspaceID,
		WorkspaceBindingID: binding.WorkspaceBindingID,
		WorkspaceBindingRevision: binding.WorkspaceBindingRevision,
		ClusterID: binding.ClusterID,
		Namespace: binding.Namespace,
		Environment: binding.Environment,
		WorkloadName: workloadName,
		RuntimeSpec: runtime,
		RuntimeSpecDigest: runtimeDigest,
		RenderedResources: resources,
		RenderedDigest: renderedDigest,
		RuntimeMutationPerformed: false,
		PhysicalCertificationInferred: false,
	}, nil
}
