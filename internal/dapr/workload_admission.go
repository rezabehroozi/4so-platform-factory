package daprruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/targetmodel"
)

const (
	WorkloadAdmissionAuthority        = "DAPR_WORKLOAD_ADMISSION_AUTHORITY_V1"
	WorkloadAdmissionEvidenceAuthority = "DAPR_WORKLOAD_ADMISSION_EVIDENCE_V1"
	WorkloadAdmissionPayloadMediaType = "application/vnd.4so.dapr-workload-admission+json"
)

type WorkloadAdmissionRequest struct {
	Authority         string                             `json:"authority"`
	ProjectID         string                             `json:"projectId"`
	ClusterID         string                             `json:"clusterId"`
	TraitID           string                             `json:"traitId"`
	TraitDigest       string                             `json:"traitDigest"`
	InventoryDigest   string                             `json:"inventoryDigest"`
	RuntimeMode       string                             `json:"runtimeMode"`
	RuntimeLockDigest string                             `json:"runtimeLockDigest,omitempty"`
	ExpectedSidecarImage string                          `json:"expectedSidecarImage,omitempty"`
	ExecutorEvidenceDigest string                        `json:"executorEvidenceDigest"`
	ExecutorImageReference string                        `json:"executorImageReference"`
	WorkloadImage     string                             `json:"workloadImage"`
	Plan              targetmodel.DaprWorkloadRuntimePlan `json:"plan"`
	PlanDigest        string                             `json:"planDigest"`
}

type WorkloadAdmissionEvidence struct {
	Authority                  string   `json:"authority"`
	OperationID                string   `json:"operationId"`
	ProjectID                  string   `json:"projectId"`
	ClusterID                  string   `json:"clusterId"`
	TraitDigest                string   `json:"traitDigest"`
	InventoryDigest            string   `json:"inventoryDigest"`
	RuntimeMode                string   `json:"runtimeMode"`
	RuntimeLockDigest          string   `json:"runtimeLockDigest,omitempty"`
	ExecutorEvidenceDigest     string   `json:"executorEvidenceDigest"`
	PlanDigest                 string   `json:"planDigest"`
	Namespace                  string   `json:"namespace"`
	AppID                      string   `json:"appId"`
	AdmissionObjectKind        string   `json:"admissionObjectKind"`
	AdmissionResource          string   `json:"admissionResource"`
	AdmissionObjectName        string   `json:"admissionObjectName"`
	DryRunHTTPStatus           int      `json:"dryRunHttpStatus"`
	InjectedSidecarObserved    bool     `json:"injectedSidecarObserved"`
	SidecarContainerName       string   `json:"sidecarContainerName"`
	SidecarImageReference      string   `json:"sidecarImageReference"`
	ExpectedSidecarImageMatched bool    `json:"expectedSidecarImageMatched"`
	SidecarCPURequest         string   `json:"sidecarCpuRequest"`
	SidecarCPULimit           string   `json:"sidecarCpuLimit"`
	SidecarMemoryRequest      string   `json:"sidecarMemoryRequest"`
	SidecarMemoryLimit        string   `json:"sidecarMemoryLimit"`
	SidecarResourcesVerified  bool     `json:"sidecarResourcesVerified"`
	RunAsNonRoot              bool     `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem    bool     `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation  bool     `json:"allowPrivilegeEscalation"`
	DroppedCapabilities       []string `json:"droppedCapabilities"`
	DropAllCapabilities       bool     `json:"dropAllCapabilities"`
	AppContainerPreserved     bool     `json:"appContainerPreserved"`
	AnnotationsVerified       bool     `json:"annotationsVerified"`
	ServerSideDryRun          bool     `json:"serverSideDryRun"`
	StrictFieldValidation     bool     `json:"strictFieldValidation"`
	SidecarPullObserved       bool     `json:"sidecarPullObserved"`
	PhysicalCertificationInferred bool `json:"physicalCertificationInferred"`
	ObservedAt                string   `json:"observedAt"`
}

func workloadAdmissionDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func WorkloadPlanDigest(plan targetmodel.DaprWorkloadRuntimePlan) (string, error) {
	if plan.Authority != targetmodel.DaprWorkloadRuntimePlanAuthority || plan.Capability != targetmodel.DaprApplicationRuntimeCapability {
		return "", fmt.Errorf("DAPR_WORKLOAD_PLAN_AUTHORITY_INVALID")
	}
	return workloadAdmissionDigest(plan)
}

func digestPinnedImage(value string) bool {
	value = strings.TrimSpace(value)
	idx := strings.LastIndex(value, "@sha256:")
	if idx <= 0 || len(value[idx+1:]) != 71 {
		return false
	}
	for _, ch := range value[idx+len("@sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return !strings.ContainsAny(value[:idx], " \t\r\n@")
}

func CanonicalWorkloadAdmissionRequest(value WorkloadAdmissionRequest) (WorkloadAdmissionRequest, error) {
	value.Authority = strings.TrimSpace(value.Authority)
	value.ProjectID = strings.TrimSpace(value.ProjectID)
	value.ClusterID = strings.TrimSpace(value.ClusterID)
	value.TraitID = strings.TrimSpace(value.TraitID)
	value.TraitDigest = strings.ToLower(strings.TrimSpace(value.TraitDigest))
	value.InventoryDigest = strings.ToLower(strings.TrimSpace(value.InventoryDigest))
	value.RuntimeMode = strings.ToUpper(strings.TrimSpace(value.RuntimeMode))
	value.RuntimeLockDigest = strings.ToLower(strings.TrimSpace(value.RuntimeLockDigest))
	value.ExpectedSidecarImage = strings.TrimSpace(value.ExpectedSidecarImage)
	value.ExecutorEvidenceDigest = strings.ToLower(strings.TrimSpace(value.ExecutorEvidenceDigest))
	value.ExecutorImageReference = strings.TrimSpace(value.ExecutorImageReference)
	value.WorkloadImage = strings.TrimSpace(value.WorkloadImage)
	value.PlanDigest = strings.ToLower(strings.TrimSpace(value.PlanDigest))
	if value.Authority != WorkloadAdmissionAuthority || value.ProjectID == "" || value.ClusterID == "" || value.TraitID == "" {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_SCOPE_INVALID")
	}
	for _, digest := range []string{value.TraitDigest, value.InventoryDigest, value.PlanDigest, value.ExecutorEvidenceDigest} {
		if !lifecycleDigest(digest) {
			return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_DIGEST_INVALID")
		}
	}
	if value.RuntimeMode != "USE_NATIVE" && value.RuntimeMode != "PRODUCT_MANAGED" {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_RUNTIME_MODE_INVALID")
	}
	if !digestPinnedImage(value.ExecutorImageReference) {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_EXECUTOR_IMAGE_INVALID")
	}
	if value.RuntimeMode == "PRODUCT_MANAGED" {
		if !lifecycleDigest(value.RuntimeLockDigest) || !digestPinnedImage(value.ExpectedSidecarImage) {
			return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_PRODUCT_RUNTIME_INVALID")
		}
	} else if value.RuntimeLockDigest != "" || value.ExpectedSidecarImage != "" {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_NATIVE_RUNTIME_FENCE_INVALID")
	}
	if !digestPinnedImage(value.WorkloadImage) {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_IMAGE_NOT_DIGEST_PINNED")
	}
	if !value.Plan.DeploymentDryRunRequired || value.Plan.SidecarSecurityCompatibilityInferred || value.Plan.PhysicalCertificationInferred ||
		value.Plan.ConfigurationBecomesSoT || value.Plan.SecretMaterialEmbedded {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_PLAN_BOUNDARY_INVALID")
	}
	digest, err := WorkloadPlanDigest(value.Plan)
	if err != nil || digest != value.PlanDigest {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_PLAN_DIGEST_MISMATCH")
	}
	return value, nil
}

func MarshalWorkloadAdmissionRequest(value WorkloadAdmissionRequest) ([]byte, string, error) {
	value, err := CanonicalWorkloadAdmissionRequest(value)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	return raw, OperationDigest(raw), nil
}

func OperationDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ParseWorkloadAdmissionRequest(raw []byte, digest string) (WorkloadAdmissionRequest, error) {
	var value WorkloadAdmissionRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return WorkloadAdmissionRequest{}, fmt.Errorf("decode Dapr workload admission request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_TRAILING_DATA")
	}
	value, err := CanonicalWorkloadAdmissionRequest(value)
	if err != nil {
		return WorkloadAdmissionRequest{}, err
	}
	encoded, got, err := MarshalWorkloadAdmissionRequest(value)
	_ = encoded
	if err != nil {
		return WorkloadAdmissionRequest{}, err
	}
	if strings.TrimSpace(digest) != "" && strings.ToLower(strings.TrimSpace(digest)) != got {
		return WorkloadAdmissionRequest{}, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_REQUEST_DIGEST_MISMATCH")
	}
	return value, nil
}

func ValidateWorkloadAdmissionEvidence(value WorkloadAdmissionEvidence, request WorkloadAdmissionRequest, operationID string) error {
	request, err := CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return err
	}
	value.Authority = strings.TrimSpace(value.Authority)
	value.OperationID = strings.TrimSpace(value.OperationID)
	value.ProjectID = strings.TrimSpace(value.ProjectID)
	value.ClusterID = strings.TrimSpace(value.ClusterID)
	value.TraitDigest = strings.ToLower(strings.TrimSpace(value.TraitDigest))
	value.InventoryDigest = strings.ToLower(strings.TrimSpace(value.InventoryDigest))
	value.RuntimeMode = strings.ToUpper(strings.TrimSpace(value.RuntimeMode))
	value.RuntimeLockDigest = strings.ToLower(strings.TrimSpace(value.RuntimeLockDigest))
	value.ExecutorEvidenceDigest = strings.ToLower(strings.TrimSpace(value.ExecutorEvidenceDigest))
	value.PlanDigest = strings.ToLower(strings.TrimSpace(value.PlanDigest))
	value.Namespace = strings.TrimSpace(value.Namespace)
	value.AppID = strings.TrimSpace(value.AppID)
	value.AdmissionObjectKind = strings.TrimSpace(value.AdmissionObjectKind)
	value.AdmissionResource = strings.TrimSpace(value.AdmissionResource)
	value.AdmissionObjectName = strings.TrimSpace(value.AdmissionObjectName)
	value.SidecarContainerName = strings.TrimSpace(value.SidecarContainerName)
	value.SidecarImageReference = strings.TrimSpace(value.SidecarImageReference)
	value.SidecarCPURequest = strings.TrimSpace(value.SidecarCPURequest)
	value.SidecarCPULimit = strings.TrimSpace(value.SidecarCPULimit)
	value.SidecarMemoryRequest = strings.TrimSpace(value.SidecarMemoryRequest)
	value.SidecarMemoryLimit = strings.TrimSpace(value.SidecarMemoryLimit)
	if value.Authority != WorkloadAdmissionEvidenceAuthority || value.OperationID != strings.TrimSpace(operationID) ||
		value.ProjectID != request.ProjectID || value.ClusterID != request.ClusterID || value.TraitDigest != request.TraitDigest ||
		value.InventoryDigest != request.InventoryDigest || value.RuntimeMode != request.RuntimeMode ||
		value.RuntimeLockDigest != request.RuntimeLockDigest || value.ExecutorEvidenceDigest != request.ExecutorEvidenceDigest || value.PlanDigest != request.PlanDigest ||
		value.Namespace != request.Plan.Namespace || value.AppID != request.Plan.AppID ||
		value.AdmissionObjectKind != "Pod" || value.AdmissionResource != "pods" ||
		value.AdmissionObjectName != AdmissionObjectName(operationID) {
		return fmt.Errorf("DAPR_WORKLOAD_ADMISSION_EVIDENCE_BINDING_INVALID")
	}
	if value.DryRunHTTPStatus < 200 || value.DryRunHTTPStatus >= 300 || !value.ServerSideDryRun || !value.StrictFieldValidation {
		return fmt.Errorf("DAPR_WORKLOAD_ADMISSION_DRY_RUN_INVALID")
	}
	if !value.InjectedSidecarObserved || value.SidecarContainerName != "daprd" || value.SidecarImageReference == "" ||
		!value.RunAsNonRoot || !value.ReadOnlyRootFilesystem || value.AllowPrivilegeEscalation ||
		!value.DropAllCapabilities || !value.AppContainerPreserved || !value.AnnotationsVerified {
		return fmt.Errorf("DAPR_WORKLOAD_SIDECAR_SECURITY_INVALID")
	}
	expectedCPURequest := workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-cpu-request")
	expectedCPULimit := workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-cpu-limit")
	expectedMemoryRequest := workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-memory-request")
	expectedMemoryLimit := workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-memory-limit")
	if !value.SidecarResourcesVerified ||
		value.SidecarCPURequest != expectedCPURequest || value.SidecarCPULimit != expectedCPULimit ||
		value.SidecarMemoryRequest != expectedMemoryRequest || value.SidecarMemoryLimit != expectedMemoryLimit {
		return fmt.Errorf("DAPR_WORKLOAD_SIDECAR_RESOURCE_SIZING_INVALID")
	}
	drops := append([]string(nil), value.DroppedCapabilities...)
	for i := range drops {
		drops[i] = strings.ToUpper(strings.TrimSpace(drops[i]))
	}
	sort.Strings(drops)
	if len(drops) == 0 || drops[0] != "ALL" {
		return fmt.Errorf("DAPR_WORKLOAD_SIDECAR_CAPABILITIES_INVALID")
	}
	if request.RuntimeMode == "PRODUCT_MANAGED" {
		if !value.ExpectedSidecarImageMatched || value.SidecarImageReference != request.ExpectedSidecarImage {
			return fmt.Errorf("DAPR_WORKLOAD_SIDECAR_IMAGE_MISMATCH")
		}
	} else if value.ExpectedSidecarImageMatched {
		return fmt.Errorf("DAPR_WORKLOAD_NATIVE_IMAGE_NOT_PRODUCT_FENCED")
	}
	if value.SidecarPullObserved || value.PhysicalCertificationInferred {
		return fmt.Errorf("DAPR_WORKLOAD_ADMISSION_EVIDENCE_OVERCLAIM")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value.ObservedAt)); err != nil {
		return fmt.Errorf("DAPR_WORKLOAD_ADMISSION_EVIDENCE_TIME_INVALID")
	}
	return nil
}

func WorkloadAdmissionEvidenceDigest(value WorkloadAdmissionEvidence, request WorkloadAdmissionRequest, operationID string) (string, error) {
	if err := ValidateWorkloadAdmissionEvidence(value, request, operationID); err != nil {
		return "", err
	}
	canonical := value
	canonical.DroppedCapabilities = append([]string(nil), value.DroppedCapabilities...)
	for i := range canonical.DroppedCapabilities {
		canonical.DroppedCapabilities[i] = strings.ToUpper(strings.TrimSpace(canonical.DroppedCapabilities[i]))
	}
	sort.Strings(canonical.DroppedCapabilities)
	return workloadAdmissionDigest(canonical)
}


func AdmissionObjectName(operationID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(operationID)))
	return "4so-dapr-admission-" + hex.EncodeToString(sum[:6])
}

func BuildWorkloadAdmissionPod(request WorkloadAdmissionRequest, operationID string) (map[string]any, error) {
	request, err := CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, fmt.Errorf("DAPR_WORKLOAD_ADMISSION_OPERATION_REQUIRED")
	}
	name := AdmissionObjectName(operationID)
	labels := map[string]any{
		"platform.4so.io/dapr-admission": name,
		"platform.4so.io/managed": "true",
		"platform.4so.io/admission-only": "true",
	}
	annotations := map[string]any{}
	for _, item := range request.Plan.Annotations {
		annotations[item.Key] = item.Value
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": request.Plan.Namespace,
			"labels": labels, "annotations": annotations,
		},
		"spec": map[string]any{
			"automountServiceAccountToken": false,
			"restartPolicy": "Never",
			"containers": []any{map[string]any{
				"name": "app", "image": request.WorkloadImage, "imagePullPolicy": "IfNotPresent",
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true,
					"capabilities": map[string]any{"drop": []any{"ALL"}},
				},
			}},
		},
	}, nil
}

func admissionNestedMap(value map[string]any, keys ...string) map[string]any {
	current := value
	for _, key := range keys {
		next, _ := current[key].(map[string]any)
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

func admissionBoolField(value map[string]any, key string) (bool, bool) {
	v, ok := value[key].(bool)
	return v, ok
}

func workloadPlanAnnotation(plan targetmodel.DaprWorkloadRuntimePlan, key string) string {
	for _, item := range plan.Annotations {
		if strings.TrimSpace(item.Key) == key {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func admissionResourceQuantity(value map[string]any, section, resource string) (string, bool) {
	sectionMap, ok := value[section].(map[string]any)
	if !ok {
		return "", false
	}
	quantity, ok := sectionMap[resource]
	if !ok {
		return "", false
	}
	out := strings.TrimSpace(fmt.Sprint(quantity))
	return out, out != ""
}

func WorkloadAdmissionEvidenceFromDryRun(request WorkloadAdmissionRequest, operationID string, response map[string]any, status int, observedAt time.Time) (WorkloadAdmissionEvidence, error) {
	request, err := CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return WorkloadAdmissionEvidence{}, err
	}
	if strings.TrimSpace(fmt.Sprint(response["apiVersion"])) != "v1" || strings.TrimSpace(fmt.Sprint(response["kind"])) != "Pod" {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_POD_SHAPE_INVALID")
	}
	metadata, _ := response["metadata"].(map[string]any)
	podSpec, _ := response["spec"].(map[string]any)
	if metadata == nil || podSpec == nil ||
		strings.TrimSpace(fmt.Sprint(metadata["name"])) != AdmissionObjectName(operationID) ||
		strings.TrimSpace(fmt.Sprint(metadata["namespace"])) != request.Plan.Namespace {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_POD_IDENTITY_INVALID")
	}
	actualAnnotations, _ := metadata["annotations"].(map[string]any)
	annotationsVerified := len(actualAnnotations) >= len(request.Plan.Annotations)
	for _, wanted := range request.Plan.Annotations {
		if strings.TrimSpace(fmt.Sprint(actualAnnotations[wanted.Key])) != wanted.Value {
			annotationsVerified = false
			break
		}
	}
	containers, _ := podSpec["containers"].([]any)
	appPreserved := false
	appCount := 0
	var sidecar map[string]any
	for _, raw := range containers {
		container, _ := raw.(map[string]any)
		name := strings.TrimSpace(fmt.Sprint(container["name"]))
		switch name {
		case "app":
			appCount++
			if appCount > 1 {
				return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_DUPLICATE_APP_CONTAINER")
			}
			appPreserved = strings.TrimSpace(fmt.Sprint(container["image"])) == request.WorkloadImage
		case "daprd":
			if sidecar != nil {
				return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_DUPLICATE_SIDECAR")
			}
			sidecar = container
		}
	}
	if appCount != 1 || !appPreserved {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_APP_CONTAINER_INVALID")
	}
	if sidecar == nil {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_SIDECAR_NOT_INJECTED")
	}
	security, _ := sidecar["securityContext"].(map[string]any)
	runAsNonRoot, runAsNonRootPresent := admissionBoolField(security, "runAsNonRoot")
	readOnlyRootFilesystem, readOnlyRootFilesystemPresent := admissionBoolField(security, "readOnlyRootFilesystem")
	allowPrivilegeEscalation, allowPrivilegeEscalationPresent := admissionBoolField(security, "allowPrivilegeEscalation")
	if !runAsNonRootPresent || !readOnlyRootFilesystemPresent || !allowPrivilegeEscalationPresent {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_SIDECAR_SECURITY_FIELDS_MISSING")
	}
	capabilities, capabilitiesPresent := security["capabilities"].(map[string]any)
	if !capabilitiesPresent {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_SIDECAR_CAPABILITIES_MISSING")
	}
	rawDrops, dropsPresent := capabilities["drop"].([]any)
	if !dropsPresent {
		return WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_SIDECAR_CAPABILITY_DROP_MISSING")
	}
	drops := make([]string, 0, len(rawDrops))
	for _, raw := range rawDrops {
		value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(raw)))
		if value != "" {
			drops = append(drops, value)
		}
	}
	sort.Strings(drops)
	dropAll := false
	for _, value := range drops {
		if value == "ALL" {
			dropAll = true
			break
		}
	}
	resources, resourcesPresent := sidecar["resources"].(map[string]any)
	cpuRequest, cpuRequestPresent := admissionResourceQuantity(resources, "requests", "cpu")
	cpuLimit, cpuLimitPresent := admissionResourceQuantity(resources, "limits", "cpu")
	memoryRequest, memoryRequestPresent := admissionResourceQuantity(resources, "requests", "memory")
	memoryLimit, memoryLimitPresent := admissionResourceQuantity(resources, "limits", "memory")
	resourcesVerified := resourcesPresent && cpuRequestPresent && cpuLimitPresent && memoryRequestPresent && memoryLimitPresent &&
		cpuRequest == workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-cpu-request") &&
		cpuLimit == workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-cpu-limit") &&
		memoryRequest == workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-memory-request") &&
		memoryLimit == workloadPlanAnnotation(request.Plan, "dapr.io/sidecar-memory-limit")
	sidecarImage := strings.TrimSpace(fmt.Sprint(sidecar["image"]))
	expectedMatched := request.RuntimeMode == "PRODUCT_MANAGED" && sidecarImage == request.ExpectedSidecarImage
	evidence := WorkloadAdmissionEvidence{
		Authority: WorkloadAdmissionEvidenceAuthority, OperationID: strings.TrimSpace(operationID),
		ProjectID: request.ProjectID, ClusterID: request.ClusterID, TraitDigest: request.TraitDigest,
		InventoryDigest: request.InventoryDigest, RuntimeMode: request.RuntimeMode, RuntimeLockDigest: request.RuntimeLockDigest,
		ExecutorEvidenceDigest: request.ExecutorEvidenceDigest,
		PlanDigest: request.PlanDigest, Namespace: request.Plan.Namespace, AppID: request.Plan.AppID,
		AdmissionObjectKind: "Pod", AdmissionResource: "pods", AdmissionObjectName: AdmissionObjectName(operationID),
		DryRunHTTPStatus: status, InjectedSidecarObserved: true, SidecarContainerName: "daprd",
		SidecarImageReference: sidecarImage, ExpectedSidecarImageMatched: expectedMatched,
		SidecarCPURequest: cpuRequest, SidecarCPULimit: cpuLimit,
		SidecarMemoryRequest: memoryRequest, SidecarMemoryLimit: memoryLimit,
		SidecarResourcesVerified: resourcesVerified,
		RunAsNonRoot: runAsNonRoot,
		ReadOnlyRootFilesystem: readOnlyRootFilesystem,
		AllowPrivilegeEscalation: allowPrivilegeEscalation,
		DroppedCapabilities: drops, DropAllCapabilities: dropAll,
		AppContainerPreserved: appPreserved, AnnotationsVerified: annotationsVerified,
		ServerSideDryRun: true, StrictFieldValidation: true, SidecarPullObserved: false,
		PhysicalCertificationInferred: false, ObservedAt: observedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := ValidateWorkloadAdmissionEvidence(evidence, request, operationID); err != nil {
		return WorkloadAdmissionEvidence{}, err
	}
	return evidence, nil
}
