package accelerator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	InventoryAuthority          = "ACCELERATOR_INVENTORY_AUTHORITY_V1"
	GPUClassAuthority           = "GPU_CLASS_AUTHORITY_V1"
	QuotaPlacementAuthority     = "ACCELERATOR_QUOTA_PLACEMENT_AUTHORITY_V1"
	PartitionLifecycleAuthority = "ACCELERATOR_PARTITION_LIFECYCLE_AUTHORITY_V1"
	ModelServingAdmission       = "DEFERRED_UNTIL_ACCELERATOR_LIFECYCLE_CERTIFIED"
)

type ObservationSource string

const (
	SourceTargetAgent      ObservationSource = "target-agent"
	SourceDevicePlugin     ObservationSource = "device-plugin"
	SourceDistributionAPI ObservationSource = "distribution-inventory"
)

type Health string

const (
	HealthHealthy   Health = "HEALTHY"
	HealthDegraded  Health = "DEGRADED"
	HealthUnhealthy Health = "UNHEALTHY"
	HealthUnknown   Health = "UNKNOWN"
)

type PartitionMode string

const (
	PartitionMIG  PartitionMode = "MIG"
	PartitionVGPU PartitionMode = "VGPU"
)

type DeviceObservation struct {
	DeviceID       string
	ClusterID      string
	NodeID         string
	Vendor         string
	Model          string
	MemoryMiB      int
	Health         Health
	Source         ObservationSource
	ObservedAt     time.Time
	Observed       bool
	Capabilities   []string
	PartitionModes []PartitionMode
}

type Inventory struct {
	Authority string
	Devices   []DeviceObservation
	Digest    string
}

func BuildInventory(observations []DeviceObservation) (Inventory, error) {
	if len(observations) == 0 {
		return Inventory{}, errors.New("accelerator inventory requires observed devices")
	}
	seen := map[string]bool{}
	devices := make([]DeviceObservation, 0, len(observations))
	for _, raw := range observations {
		device, err := normalizeObservation(raw)
		if err != nil {
			return Inventory{}, err
		}
		if seen[device.DeviceID] {
			return Inventory{}, fmt.Errorf("duplicate accelerator deviceId %q", device.DeviceID)
		}
		seen[device.DeviceID] = true
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].ClusterID != devices[j].ClusterID { return devices[i].ClusterID < devices[j].ClusterID }
		if devices[i].NodeID != devices[j].NodeID { return devices[i].NodeID < devices[j].NodeID }
		return devices[i].DeviceID < devices[j].DeviceID
	})
	digest, err := digestValue([]any{InventoryAuthority, devices})
	if err != nil { return Inventory{}, err }
	return Inventory{Authority: InventoryAuthority, Devices: devices, Digest: digest}, nil
}

func normalizeObservation(v DeviceObservation) (DeviceObservation, error) {
	v.DeviceID = strings.TrimSpace(v.DeviceID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.NodeID = strings.TrimSpace(v.NodeID)
	v.Vendor = strings.ToLower(strings.TrimSpace(v.Vendor))
	v.Model = strings.ToLower(strings.TrimSpace(v.Model))
	if !v.Observed { return DeviceObservation{}, errors.New("accelerator inventory must come from observed target evidence") }
	switch v.Source {
	case SourceTargetAgent, SourceDevicePlugin, SourceDistributionAPI:
	default:
		return DeviceObservation{}, fmt.Errorf("accelerator observation source %q is not admitted", v.Source)
	}
	if v.DeviceID == "" || v.ClusterID == "" || v.NodeID == "" || v.Vendor == "" || v.Model == "" || v.MemoryMiB <= 0 || v.ObservedAt.IsZero() {
		return DeviceObservation{}, errors.New("accelerator observation identity/capacity/timestamp is incomplete")
	}
	switch v.Health {
	case HealthHealthy, HealthDegraded, HealthUnhealthy, HealthUnknown:
	default:
		return DeviceObservation{}, fmt.Errorf("unsupported accelerator health %q", v.Health)
	}
	v.Capabilities = normalizeStrings(v.Capabilities)
	seenModes := map[PartitionMode]bool{}
	v.PartitionModes = append([]PartitionMode(nil), v.PartitionModes...)
	for _, mode := range v.PartitionModes {
		if mode != PartitionMIG && mode != PartitionVGPU { return DeviceObservation{}, fmt.Errorf("unsupported partition mode %q", mode) }
		if seenModes[mode] { return DeviceObservation{}, fmt.Errorf("duplicate partition mode %q", mode) }
		seenModes[mode] = true
	}
	sort.Slice(v.PartitionModes, func(i, j int) bool { return v.PartitionModes[i] < v.PartitionModes[j] })
	return v, nil
}

type GPUClass struct {
	Authority             string
	ID                    string
	Vendor                string
	MinMemoryMiB          int
	RequiredCapabilities  []string
	AllowedPartitionModes []PartitionMode
}

type Quota struct {
	Authority      string
	OrganizationID string
	ProjectID      string
	ClassID        string
	MaxDevices     int
	MaxMemoryMiB   int
}

type Usage struct {
	Devices            int
	MemoryMiB          int
	AllocatedDeviceIDs []string
}

type PlacementRequest struct {
	OrganizationID string
	ProjectID      string
	ClusterID      string
	ClassID        string
	Devices        int
	MemoryMiB      int
	PartitionMode  PartitionMode
}

type PlacementPlan struct {
	Authority          string
	OrganizationID     string
	ProjectID          string
	ClusterID          string
	ClassID            string
	DeviceIDs          []string
	PartitionMode      PartitionMode
	RequestedDevices   int
	RequestedMemoryMiB int
	PlanDigest         string
}

func PlanPlacement(inv Inventory, class GPUClass, quota Quota, usage Usage, request PlacementRequest) (PlacementPlan, error) {
	if inv.Authority != InventoryAuthority || !isDigest(inv.Digest) {
		return PlacementPlan{}, errors.New("accelerator inventory authority is invalid")
	}
	class, err := normalizeClass(class)
	if err != nil { return PlacementPlan{}, err }
	quota, err = normalizeQuota(quota, class.ID)
	if err != nil { return PlacementPlan{}, err }
	request.OrganizationID = strings.TrimSpace(request.OrganizationID)
	request.ProjectID = strings.TrimSpace(request.ProjectID)
	request.ClusterID = strings.TrimSpace(request.ClusterID)
	request.ClassID = strings.TrimSpace(request.ClassID)
	if request.OrganizationID != quota.OrganizationID || request.ProjectID != quota.ProjectID || request.ClassID != quota.ClassID || request.ClassID != class.ID {
		return PlacementPlan{}, errors.New("accelerator placement request is outside quota/class scope")
	}
	if request.ClusterID == "" || request.Devices <= 0 || request.MemoryMiB <= 0 {
		return PlacementPlan{}, errors.New("clusterId, devices and memoryMiB are required")
	}
	if usage.Devices < 0 || usage.MemoryMiB < 0 {
		return PlacementPlan{}, errors.New("accelerator usage cannot be negative")
	}
	allocated, err := exactAllocatedSet(inv, usage)
	if err != nil { return PlacementPlan{}, err }
	if usage.Devices+request.Devices > quota.MaxDevices || usage.MemoryMiB+request.MemoryMiB > quota.MaxMemoryMiB {
		return PlacementPlan{}, errors.New("accelerator quota would be exceeded")
	}
	if !containsMode(class.AllowedPartitionModes, request.PartitionMode) {
		return PlacementPlan{}, fmt.Errorf("partition mode %q is not admitted by GPU class", request.PartitionMode)
	}

	candidates := make([]DeviceObservation, 0)
	for _, device := range inv.Devices {
		if allocated[device.DeviceID] || device.ClusterID != request.ClusterID || device.Health != HealthHealthy || device.Vendor != class.Vendor || device.MemoryMiB < class.MinMemoryMiB {
			continue
		}
		if !containsAll(device.Capabilities, class.RequiredCapabilities) || !containsMode(device.PartitionModes, request.PartitionMode) { continue }
		candidates = append(candidates, device)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].DeviceID < candidates[j].DeviceID })
	if len(candidates) < request.Devices { return PlacementPlan{}, errors.New("insufficient healthy observed unallocated accelerator capacity") }
	selected := candidates[:request.Devices]
	deviceIDs := make([]string, 0, len(selected))
	totalMemory := 0
	for _, device := range selected {
		deviceIDs = append(deviceIDs, device.DeviceID)
		totalMemory += device.MemoryMiB
	}
	if totalMemory < request.MemoryMiB { return PlacementPlan{}, errors.New("selected accelerator capacity cannot satisfy requested memory") }
	plan := PlacementPlan{
		Authority: QuotaPlacementAuthority, OrganizationID: request.OrganizationID, ProjectID: request.ProjectID,
		ClusterID: request.ClusterID, ClassID: class.ID, DeviceIDs: deviceIDs, PartitionMode: request.PartitionMode,
		RequestedDevices: request.Devices, RequestedMemoryMiB: request.MemoryMiB,
	}
	plan.PlanDigest, err = digestValue([]any{plan.Authority, inv.Digest, quota, usage.Devices, usage.MemoryMiB, sortedKeys(allocated), plan.OrganizationID, plan.ProjectID, plan.ClusterID, plan.ClassID, plan.DeviceIDs, plan.PartitionMode, plan.RequestedDevices, plan.RequestedMemoryMiB})
	if err != nil { return PlacementPlan{}, err }
	return plan, nil
}

func exactAllocatedSet(inv Inventory, usage Usage) (map[string]bool, error) {
	allocated := normalizeStrings(usage.AllocatedDeviceIDs)
	if len(allocated) != usage.Devices {
		return nil, errors.New("allocated device identity set must exactly match device usage count")
	}
	known := map[string]bool{}
	for _, device := range inv.Devices { known[device.DeviceID] = true }
	out := map[string]bool{}
	for _, id := range allocated {
		if !known[id] { return nil, fmt.Errorf("allocated accelerator device %q is absent from observed inventory", id) }
		out[id] = true
	}
	return out, nil
}

func normalizeClass(v GPUClass) (GPUClass, error) {
	v.ID = strings.TrimSpace(v.ID)
	v.Vendor = strings.ToLower(strings.TrimSpace(v.Vendor))
	v.RequiredCapabilities = normalizeStrings(v.RequiredCapabilities)
	if v.Authority != GPUClassAuthority || v.ID == "" || v.Vendor == "" || v.MinMemoryMiB <= 0 || len(v.RequiredCapabilities) == 0 || len(v.AllowedPartitionModes) == 0 {
		return GPUClass{}, errors.New("GPU class authority/identity/capacity/capabilities are invalid")
	}
	for _, mode := range v.AllowedPartitionModes {
		if mode != PartitionMIG && mode != PartitionVGPU { return GPUClass{}, fmt.Errorf("unsupported GPU class partition mode %q", mode) }
	}
	return v, nil
}

func normalizeQuota(v Quota, classID string) (Quota, error) {
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClassID = strings.TrimSpace(v.ClassID)
	if v.Authority != QuotaPlacementAuthority || v.OrganizationID == "" || v.ProjectID == "" || v.ClassID != classID || v.MaxDevices <= 0 || v.MaxMemoryMiB <= 0 {
		return Quota{}, errors.New("accelerator quota authority/scope/capacity is invalid")
	}
	return v, nil
}

type PartitionAction string

const (
	PartitionCreate  PartitionAction = "CREATE"
	PartitionAssign  PartitionAction = "ASSIGN"
	PartitionDrain   PartitionAction = "DRAIN"
	PartitionReplace PartitionAction = "REPLACE"
)

type PartitionState string

const (
	PartitionStatePlanned          PartitionState = "PLANNED"
	PartitionStateRunning          PartitionState = "RUNNING"
	PartitionStateReady            PartitionState = "READY"
	PartitionStateDrained          PartitionState = "DRAINED"
	PartitionStateReplaced         PartitionState = "REPLACED"
	PartitionStateRecoveryRequired PartitionState = "RECOVERY_REQUIRED"
	PartitionStateFailed           PartitionState = "FAILED"
)

type Outcome string

const (
	OutcomeApplied Outcome = "APPLIED"
	OutcomePending Outcome = "PENDING"
	OutcomeUnknown Outcome = "UNKNOWN"
	OutcomeFailed  Outcome = "FAILED"
)

type PartitionOperation struct {
	Authority          string
	OperationID        string
	IdempotencyKey     string
	FenceToken         int64
	Action             PartitionAction
	DeviceID           string
	PartitionID        string
	ExpectedGeneration int64
	PlanDigest         string
	OrganizationID     string
	ProjectID          string
	ClusterID          string
}

type PartitionReadback struct {
	Observed       bool
	DeviceID       string
	PartitionID    string
	Generation     int64
	State          PartitionState
	EvidenceDigest string
}

type PartitionResult struct {
	State            PartitionState
	RecoveryRequired bool
	RetryAllowed     bool
	EvidenceDigest   string
	Message          string
}

func NewPartitionOperation(plan PlacementPlan, operationID, idempotencyKey string, fenceToken int64, action PartitionAction, deviceID, partitionID string, expectedGeneration int64) (PartitionOperation, error) {
	operationID = strings.TrimSpace(operationID)
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	deviceID = strings.TrimSpace(deviceID)
	partitionID = strings.TrimSpace(partitionID)
	if plan.Authority != QuotaPlacementAuthority || !isDigest(plan.PlanDigest) || operationID == "" || idempotencyKey == "" || fenceToken <= 0 || expectedGeneration < 0 || deviceID == "" || partitionID == "" {
		return PartitionOperation{}, errors.New("partition operation authority/fence/identity is incomplete")
	}
	if !containsString(plan.DeviceIDs, deviceID) { return PartitionOperation{}, errors.New("partition operation device is outside placement plan") }
	switch action {
	case PartitionCreate, PartitionAssign, PartitionDrain, PartitionReplace:
	default:
		return PartitionOperation{}, fmt.Errorf("unsupported partition action %q", action)
	}
	return PartitionOperation{Authority: PartitionLifecycleAuthority, OperationID: operationID, IdempotencyKey: idempotencyKey, FenceToken: fenceToken, Action: action, DeviceID: deviceID, PartitionID: partitionID, ExpectedGeneration: expectedGeneration, PlanDigest: plan.PlanDigest, OrganizationID: plan.OrganizationID, ProjectID: plan.ProjectID, ClusterID: plan.ClusterID}, nil
}

func ResolvePartitionOutcome(op PartitionOperation, outcome Outcome, readback PartitionReadback) PartitionResult {
	if op.Authority != PartitionLifecycleAuthority || op.FenceToken <= 0 || !isDigest(op.PlanDigest) {
		return PartitionResult{State: PartitionStateFailed, Message: "partition operation authority is invalid"}
	}
	converged := validReadback(op, readback)
	switch outcome {
	case OutcomeUnknown:
		if converged { return PartitionResult{State: readback.State, EvidenceDigest: readback.EvidenceDigest, Message: "ambiguous accelerator mutation resolved by authoritative readback"} }
		return PartitionResult{State: PartitionStateRecoveryRequired, RecoveryRequired: true, Message: "accelerator mutation outcome is ambiguous; authoritative readback is required"}
	case OutcomeApplied:
		if converged { return PartitionResult{State: readback.State, EvidenceDigest: readback.EvidenceDigest} }
		return PartitionResult{State: PartitionStateRunning, Message: "provider accepted mutation; authoritative readback has not converged"}
	case OutcomePending:
		return PartitionResult{State: PartitionStateRunning}
	case OutcomeFailed:
		return PartitionResult{State: PartitionStateFailed, Message: "accelerator partition mutation failed"}
	default:
		return PartitionResult{State: PartitionStateFailed, Message: "unsupported accelerator lifecycle outcome"}
	}
}

func validReadback(op PartitionOperation, readback PartitionReadback) bool {
	if !readback.Observed || strings.TrimSpace(readback.DeviceID) != op.DeviceID || strings.TrimSpace(readback.PartitionID) != op.PartitionID || readback.Generation <= op.ExpectedGeneration || !isDigest(readback.EvidenceDigest) { return false }
	switch op.Action {
	case PartitionCreate, PartitionAssign:
		return readback.State == PartitionStateReady
	case PartitionDrain:
		return readback.State == PartitionStateDrained
	case PartitionReplace:
		return readback.State == PartitionStateReplaced || readback.State == PartitionStateReady
	default:
		return false
	}
}

type HealthDecision struct {
	RepairRequired     bool
	ReplacementAllowed bool
	RequiredAuthority  string
	Reason             string
}

func AssessHealth(observation DeviceObservation) HealthDecision {
	if !observation.Observed || observation.ObservedAt.IsZero() { return HealthDecision{Reason: "health is not backed by observed target evidence"} }
	switch observation.Health {
	case HealthHealthy:
		return HealthDecision{Reason: "device is healthy"}
	case HealthUnknown:
		return HealthDecision{Reason: "device health is unknown; mutation is not authorized"}
	case HealthDegraded:
		return HealthDecision{RepairRequired: true, ReplacementAllowed: true, RequiredAuthority: PartitionLifecycleAuthority, Reason: "degraded device requires durable remediation/readback evidence"}
	case HealthUnhealthy:
		return HealthDecision{RepairRequired: true, ReplacementAllowed: true, RequiredAuthority: PartitionLifecycleAuthority, Reason: "unhealthy device requires durable replacement/readback evidence"}
	default:
		return HealthDecision{Reason: "unsupported health state"}
	}
}

func digestValue(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil { return "", fmt.Errorf("encode accelerator authority: %w", err) }
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func normalizeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] { continue }
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsAll(have, required []string) bool {
	set := map[string]bool{}
	for _, value := range have { set[value] = true }
	for _, value := range required { if !set[value] { return false } }
	return true
}

func containsMode(values []PartitionMode, want PartitionMode) bool {
	for _, value := range values { if value == want { return true } }
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values { if value == want { return true } }
	return false
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values { out = append(out, value) }
	sort.Strings(out)
	return out
}

func isDigest(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") { return false }
	for _, r := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", r) { return false }
	}
	return true
}
