package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	ApplicationDeploymentRequestAuthority  = "APPLICATION_DEPLOYMENT_REQUEST_V1"
	ApplicationDeploymentEvidenceAuthority = "APPLICATION_DEPLOYMENT_EVIDENCE_V1"
	ApplicationDeploymentPayloadMediaType  = "application/vnd.4so.application-deployment+json"
	ApplicationDeploymentEvidenceKind      = "application-deployment"
)

type ApplicationDeploymentRequest struct {
	Authority       string                    `json:"authority"`
	InventoryDigest string                    `json:"inventoryDigest"`
	Plan            ApplicationDeploymentPlan `json:"plan"`
}

type ApplicationDeploymentReadback struct {
	DeploymentName       string `json:"deploymentName"`
	DeploymentUID        string `json:"deploymentUid"`
	Generation           int64  `json:"generation"`
	ObservedGeneration   int64  `json:"observedGeneration"`
	DesiredReplicas      int    `json:"desiredReplicas"`
	ReadyReplicas        int    `json:"readyReplicas"`
	WorkloadImage        string `json:"workloadImage"`
	CPURequest           string `json:"cpuRequest"`
	CPULimit             string `json:"cpuLimit"`
	MemoryRequest        string `json:"memoryRequest"`
	MemoryLimit          string `json:"memoryLimit"`
	ServiceObserved      bool   `json:"serviceObserved"`
	ServiceName          string `json:"serviceName,omitempty"`
	ServiceClusterIP     string `json:"serviceClusterIp,omitempty"`
	ServicePort          int    `json:"servicePort,omitempty"`
	ServiceTargetPort    int    `json:"serviceTargetPort,omitempty"`
	AuthorityLabelsMatch bool   `json:"authorityLabelsMatch"`
	AuthorityDigestsMatch bool  `json:"authorityDigestsMatch"`
}

type ApplicationDeploymentEvidence struct {
	Authority                     string                        `json:"authority"`
	OperationID                   string                        `json:"operationId"`
	ProjectID                     string                        `json:"projectId"`
	ClusterID                     string                        `json:"clusterId"`
	Namespace                     string                        `json:"namespace"`
	EnvironmentBindingID          string                        `json:"environmentBindingId"`
	EnvironmentBindingRevision    int64                         `json:"environmentBindingRevision"`
	ReleaseDigest                 string                        `json:"releaseDigest"`
	InventoryDigest               string                        `json:"inventoryDigest"`
	RenderedDigest                string                        `json:"renderedDigest"`
	Readback                      ApplicationDeploymentReadback `json:"readback"`
	ObservedAt                    string                        `json:"observedAt"`
	RuntimeMutationObserved       bool                          `json:"runtimeMutationObserved"`
	PhysicalCertificationInferred bool                          `json:"physicalCertificationInferred"`
}

func normalizeApplicationDeploymentRequest(in ApplicationDeploymentRequest) (ApplicationDeploymentRequest, error) {
	out := in
	out.Authority = strings.TrimSpace(out.Authority)
	out.InventoryDigest = strings.ToLower(strings.TrimSpace(out.InventoryDigest))
	if out.Authority != ApplicationDeploymentRequestAuthority {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment request authority is invalid", ErrValidation)
	}
	if !applicationPlatformDigestPattern.MatchString(out.InventoryDigest) {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment inventory digest is invalid", ErrValidation)
	}
	p := out.Plan
	p.Authority = strings.TrimSpace(p.Authority)
	p.ProjectID = strings.TrimSpace(p.ProjectID)
	p.ReleaseID = strings.TrimSpace(p.ReleaseID)
	p.ReleaseDigest = strings.ToLower(strings.TrimSpace(p.ReleaseDigest))
	p.WorkloadImageReference = strings.TrimSpace(p.WorkloadImageReference)
	p.EnvironmentBindingID = strings.TrimSpace(p.EnvironmentBindingID)
	p.EnvironmentBindingDigest = strings.ToLower(strings.TrimSpace(p.EnvironmentBindingDigest))
	p.WorkspaceID = strings.TrimSpace(p.WorkspaceID)
	p.WorkspaceBindingID = strings.TrimSpace(p.WorkspaceBindingID)
	p.ClusterID = strings.TrimSpace(p.ClusterID)
	p.Namespace = strings.TrimSpace(p.Namespace)
	p.Environment = strings.ToLower(strings.TrimSpace(p.Environment))
	p.WorkloadName = strings.TrimSpace(p.WorkloadName)
	p.RuntimeSpecDigest = strings.ToLower(strings.TrimSpace(p.RuntimeSpecDigest))
	p.RenderedDigest = strings.ToLower(strings.TrimSpace(p.RenderedDigest))
	runtime, err := normalizeApplicationRuntimeSpec(p.RuntimeSpec)
	if err != nil {
		return ApplicationDeploymentRequest{}, err
	}
	p.RuntimeSpec = runtime
	if p.Authority != ApplicationDeploymentPlanAuthority || p.ProjectID == "" || p.ReleaseID == "" ||
		p.EnvironmentBindingID == "" || p.EnvironmentBindingRevision <= 0 || p.WorkspaceID == "" ||
		p.WorkspaceBindingID == "" || p.WorkspaceBindingRevision <= 0 || p.ClusterID == "" ||
		p.Namespace == "" || p.Environment == "" || p.WorkloadName == "" {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment plan scope is incomplete", ErrValidation)
	}
	for _, digest := range []string{p.ReleaseDigest, p.EnvironmentBindingDigest, p.RuntimeSpecDigest, p.RenderedDigest} {
		if !applicationPlatformDigestPattern.MatchString(digest) {
			return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment plan digest is invalid", ErrValidation)
		}
	}
	if !applicationWorkloadImagePattern.MatchString(p.WorkloadImageReference) || strings.Contains(p.WorkloadImageReference, "://") {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment workload image is not exact", ErrValidation)
	}
	if p.RuntimeMutationPerformed || p.PhysicalCertificationInferred {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment plan overclaims runtime evidence", ErrValidation)
	}
	if digestApplicationPlatformMaterial(p.RuntimeSpec) != p.RuntimeSpecDigest ||
		digestApplicationPlatformMaterial(p.RenderedResources) != p.RenderedDigest {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment plan digest mismatch", ErrValidation)
	}
	if err = validateApplicationDeploymentRenderedResources(p); err != nil {
		return ApplicationDeploymentRequest{}, err
	}
	out.Plan = p
	return out, nil
}

func validateApplicationDeploymentRenderedResources(plan ApplicationDeploymentPlan) error {
	expected := 1
	if plan.RuntimeSpec.ServicePort > 0 {
		expected = 2
	}
	if len(plan.RenderedResources) != expected {
		return fmt.Errorf("%w: application deployment rendered resource count mismatch", ErrValidation)
	}
	for index, resource := range plan.RenderedResources {
		kind := strings.TrimSpace(fmt.Sprint(resource["kind"]))
		apiVersion := strings.TrimSpace(fmt.Sprint(resource["apiVersion"]))
		metadata, _ := resource["metadata"].(map[string]any)
		if metadata == nil || strings.TrimSpace(fmt.Sprint(metadata["name"])) != plan.WorkloadName ||
			strings.TrimSpace(fmt.Sprint(metadata["namespace"])) != plan.Namespace {
			return fmt.Errorf("%w: application deployment rendered identity mismatch", ErrValidation)
		}
		labels, _ := metadata["labels"].(map[string]any)
		if labels == nil || strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/environment-binding"])) != plan.EnvironmentBindingID ||
			strings.TrimSpace(fmt.Sprint(labels["app.kubernetes.io/managed-by"])) != "4so-platform-factory" {
			return fmt.Errorf("%w: application deployment ownership labels are invalid", ErrValidation)
		}
		annotations, _ := metadata["annotations"].(map[string]any)
		if annotations == nil ||
			strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/application-release-digest"])) != plan.ReleaseDigest ||
			strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/environment-binding-digest"])) != plan.EnvironmentBindingDigest ||
			strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/runtime-spec-digest"])) != plan.RuntimeSpecDigest {
			return fmt.Errorf("%w: application deployment authority annotations are invalid", ErrValidation)
		}
		if index == 0 {
			if kind != "Deployment" || apiVersion != "apps/v1" {
				return fmt.Errorf("%w: application deployment first rendered resource must be apps/v1 Deployment", ErrValidation)
			}
			spec, _ := resource["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			templateSpec, _ := template["spec"].(map[string]any)
			containers, _ := templateSpec["containers"].([]any)
			if len(containers) != 1 {
				return fmt.Errorf("%w: application deployment must render exactly one app container", ErrValidation)
			}
			container, _ := containers[0].(map[string]any)
			if strings.TrimSpace(fmt.Sprint(container["image"])) != plan.WorkloadImageReference {
				return fmt.Errorf("%w: application deployment rendered workload image mismatch", ErrValidation)
			}
		} else if kind != "Service" || apiVersion != "v1" || plan.RuntimeSpec.ServicePort <= 0 {
			return fmt.Errorf("%w: application deployment rendered Service is invalid", ErrValidation)
		}
	}
	return nil
}

func MarshalApplicationDeploymentRequest(in ApplicationDeploymentRequest) ([]byte, string, error) {
	value, err := normalizeApplicationDeploymentRequest(in)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	return raw, digestApplicationPlatformMaterial(value), nil
}

func ParseApplicationDeploymentRequest(raw []byte, expectedDigest string) (ApplicationDeploymentRequest, error) {
	var value ApplicationDeploymentRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return ApplicationDeploymentRequest{}, fmt.Errorf("decode application deployment request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment request has trailing data", ErrValidation)
	}
	value, err := normalizeApplicationDeploymentRequest(value)
	if err != nil {
		return ApplicationDeploymentRequest{}, err
	}
	_, digest, err := MarshalApplicationDeploymentRequest(value)
	if err != nil {
		return ApplicationDeploymentRequest{}, err
	}
	if strings.TrimSpace(expectedDigest) != "" && !strings.EqualFold(strings.TrimSpace(expectedDigest), digest) {
		return ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment request digest mismatch", ErrConflict)
	}
	return value, nil
}

func ValidateApplicationDeploymentEvidence(value ApplicationDeploymentEvidence, request ApplicationDeploymentRequest, operationID string) error {
	request, err := normalizeApplicationDeploymentRequest(request)
	if err != nil {
		return err
	}
	value.Authority = strings.TrimSpace(value.Authority)
	value.OperationID = strings.TrimSpace(value.OperationID)
	value.ProjectID = strings.TrimSpace(value.ProjectID)
	value.ClusterID = strings.TrimSpace(value.ClusterID)
	value.Namespace = strings.TrimSpace(value.Namespace)
	value.EnvironmentBindingID = strings.TrimSpace(value.EnvironmentBindingID)
	value.ReleaseDigest = strings.ToLower(strings.TrimSpace(value.ReleaseDigest))
	value.InventoryDigest = strings.ToLower(strings.TrimSpace(value.InventoryDigest))
	value.RenderedDigest = strings.ToLower(strings.TrimSpace(value.RenderedDigest))
	r := value.Readback
	r.DeploymentName = strings.TrimSpace(r.DeploymentName)
	r.DeploymentUID = strings.TrimSpace(r.DeploymentUID)
	r.WorkloadImage = strings.TrimSpace(r.WorkloadImage)
	r.CPURequest = strings.TrimSpace(r.CPURequest)
	r.CPULimit = strings.TrimSpace(r.CPULimit)
	r.MemoryRequest = strings.TrimSpace(r.MemoryRequest)
	r.MemoryLimit = strings.TrimSpace(r.MemoryLimit)
	r.ServiceName = strings.TrimSpace(r.ServiceName)
	r.ServiceClusterIP = strings.TrimSpace(r.ServiceClusterIP)
	value.Readback = r
	plan := request.Plan
	if value.Authority != ApplicationDeploymentEvidenceAuthority || value.OperationID != strings.TrimSpace(operationID) ||
		value.ProjectID != plan.ProjectID || value.ClusterID != plan.ClusterID || value.Namespace != plan.Namespace ||
		value.EnvironmentBindingID != plan.EnvironmentBindingID || value.EnvironmentBindingRevision != plan.EnvironmentBindingRevision ||
		value.ReleaseDigest != plan.ReleaseDigest || value.InventoryDigest != request.InventoryDigest ||
		value.RenderedDigest != plan.RenderedDigest || !value.RuntimeMutationObserved || value.PhysicalCertificationInferred {
		return fmt.Errorf("%w: application deployment evidence authority mismatch", ErrValidation)
	}
	if r.DeploymentName != plan.WorkloadName || r.DeploymentUID == "" || r.Generation <= 0 ||
		r.ObservedGeneration < r.Generation || r.DesiredReplicas != plan.RuntimeSpec.Replicas ||
		r.ReadyReplicas != plan.RuntimeSpec.Replicas || r.WorkloadImage != plan.WorkloadImageReference ||
		r.CPURequest != plan.RuntimeSpec.CPURequest || r.CPULimit != plan.RuntimeSpec.CPULimit ||
		r.MemoryRequest != plan.RuntimeSpec.MemoryRequest || r.MemoryLimit != plan.RuntimeSpec.MemoryLimit ||
		!r.AuthorityLabelsMatch || !r.AuthorityDigestsMatch {
		return fmt.Errorf("%w: application deployment workload readback mismatch", ErrValidation)
	}
	if plan.RuntimeSpec.ServicePort > 0 {
		if !r.ServiceObserved || r.ServiceName != plan.WorkloadName || r.ServicePort != plan.RuntimeSpec.ServicePort ||
			r.ServiceTargetPort != plan.RuntimeSpec.ContainerPort || r.ServiceClusterIP == "" {
			return fmt.Errorf("%w: application deployment Service readback mismatch", ErrValidation)
		}
	} else if r.ServiceObserved || r.ServiceName != "" || r.ServicePort != 0 || r.ServiceTargetPort != 0 {
		return fmt.Errorf("%w: application deployment unexpected Service readback", ErrValidation)
	}
	if _, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(value.ObservedAt)); err != nil {
		return fmt.Errorf("%w: application deployment evidence time is invalid", ErrValidation)
	}
	return nil
}

func ApplicationDeploymentEvidenceDigest(value ApplicationDeploymentEvidence, request ApplicationDeploymentRequest, operationID string) (string, error) {
	if err := ValidateApplicationDeploymentEvidence(value, request, operationID); err != nil {
		return "", err
	}
	return digestApplicationPlatformMaterial(value), nil
}
