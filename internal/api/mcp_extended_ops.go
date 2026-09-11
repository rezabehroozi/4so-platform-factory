package api

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/managedinstall"
)

func mcpProjectListArguments(arguments map[string]any) (string, bool) {
	if len(arguments) > 1 {
		return "", false
	}
	return mcpString(arguments, "organizationId", false, 200)
}

func mcpProjectCreateArguments(arguments map[string]any) (string, string, string, bool) {
	if len(arguments) != 3 {
		return "", "", "", false
	}
	organizationID, a := mcpString(arguments, "organizationId", true, 200)
	name, b := mcpString(arguments, "name", true, 63)
	displayName, c := mcpString(arguments, "displayName", true, 128)
	return organizationID, name, displayName, a && b && c
}

func mcpWorkspaceCreateArguments(arguments map[string]any) (string, string, string, string, bool) {
	if len(arguments) < 3 || len(arguments) > 4 {
		return "", "", "", "", false
	}
	projectID, a := mcpString(arguments, "projectId", true, 200)
	name, b := mcpString(arguments, "name", true, 63)
	displayName, c := mcpString(arguments, "displayName", true, 128)
	description, d := mcpString(arguments, "description", false, 1024)
	return projectID, name, displayName, description, a && b && c && d
}

func mcpWorkspaceBindingListArguments(arguments map[string]any) (string, bool) {
	if len(arguments) != 1 {
		return "", false
	}
	return mcpString(arguments, "workspaceId", true, 200)
}

func mcpWorkspaceBindingCreateArguments(arguments map[string]any) (string, string, string, bool) {
	if len(arguments) != 3 {
		return "", "", "", false
	}
	workspaceID, a := mcpString(arguments, "workspaceId", true, 200)
	clusterID, b := mcpString(arguments, "clusterId", true, 200)
	namespace, c := mcpString(arguments, "namespace", true, 63)
	return workspaceID, clusterID, namespace, a && b && c
}

func mcpWorkspaceBindingRevokeArguments(arguments map[string]any) (string, int64, bool) {
	if len(arguments) != 2 {
		return "", 0, false
	}
	bindingID, a := mcpString(arguments, "bindingId", true, 200)
	revision, b := mcpPositiveRevision(arguments, "expectedRevision", true)
	return bindingID, revision, a && b
}

type mcpDataProtectionRunArgs struct {
	ProjectID      string
	ClusterID      string
	PolicyID       string
	BackupRunID    string
	IdempotencyKey string
}

func mcpDataProtectionRunArguments(arguments map[string]any, requireBackupRun bool) (mcpDataProtectionRunArgs, bool) {
	allowed := map[string]bool{"projectId": true, "clusterId": true, "policyId": true, "backupRunId": true, "idempotencyKey": true}
	for key := range arguments {
		if !allowed[key] {
			return mcpDataProtectionRunArgs{}, false
		}
	}
	projectID, a := mcpString(arguments, "projectId", true, 200)
	clusterID, b := mcpString(arguments, "clusterId", true, 200)
	policyID, c := mcpString(arguments, "policyId", true, 200)
	backupRunID, d := mcpString(arguments, "backupRunId", requireBackupRun, 200)
	key, e := mcpString(arguments, "idempotencyKey", true, 200)
	if !(a && b && c && d && e) || (!requireBackupRun && backupRunID != "") {
		return mcpDataProtectionRunArgs{}, false
	}
	return mcpDataProtectionRunArgs{ProjectID: projectID, ClusterID: clusterID, PolicyID: policyID, BackupRunID: backupRunID, IdempotencyKey: key}, true
}

func mcpProjectClusterArguments(arguments map[string]any) (string, string, bool) {
	if len(arguments) < 1 || len(arguments) > 2 {
		return "", "", false
	}
	projectID, ok := mcpString(arguments, "projectId", true, 200)
	if !ok {
		return "", "", false
	}
	clusterID, ok := mcpString(arguments, "clusterId", false, 200)
	if !ok {
		return "", "", false
	}
	return projectID, clusterID, true
}

func mcpComplianceScanArguments(arguments map[string]any) (string, string, string, string, bool) {
	if len(arguments) != 4 {
		return "", "", "", "", false
	}
	projectID, a := mcpString(arguments, "projectId", true, 200)
	clusterID, b := mcpString(arguments, "clusterId", true, 200)
	profileID, c := mcpString(arguments, "profileId", true, 200)
	key, d := mcpString(arguments, "idempotencyKey", true, 200)
	return projectID, clusterID, profileID, key, a && b && c && d
}

func mcpComplianceRecheckArguments(arguments map[string]any) (string, string, string, string, bool) {
	if len(arguments) != 4 {
		return "", "", "", "", false
	}
	projectID, a := mcpString(arguments, "projectId", true, 200)
	runID, b := mcpString(arguments, "runId", true, 200)
	fingerprint, c := mcpString(arguments, "fingerprint", true, 256)
	key, d := mcpString(arguments, "idempotencyKey", true, 200)
	return projectID, runID, fingerprint, key, a && b && c && d
}

func mcpUpgradeControlArguments(arguments map[string]any, reasonRequired bool) (string, int64, string, bool) {
	if len(arguments) < 2 || len(arguments) > 3 {
		return "", 0, "", false
	}
	id, a := mcpString(arguments, "id", true, 200)
	revision, b := mcpPositiveRevision(arguments, "expectedRevision", true)
	reason, c := mcpString(arguments, "reason", reasonRequired, 500)
	return id, revision, reason, a && b && c
}

func mcpUpgradeRevalidateArguments(arguments map[string]any) (string, int64, controlplane.UpgradeCampaignRevalidation, bool) {
	allowed := map[string]bool{"id": true, "expectedRevision": true, "recoveryCheckpointIds": true, "maintenanceWindowStart": true, "maintenanceWindowEnd": true}
	for key := range arguments {
		if !allowed[key] {
			return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
		}
	}
	id, a := mcpString(arguments, "id", true, 200)
	revision, b := mcpPositiveRevision(arguments, "expectedRevision", true)
	if !a || !b {
		return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
	}
	result := controlplane.UpgradeCampaignRevalidation{}
	if raw, exists := arguments["recoveryCheckpointIds"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) > 100 {
			return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
		}
		seen := map[string]bool{}
		for _, rawValue := range values {
			value, ok := rawValue.(string)
			value = strings.TrimSpace(value)
			if !ok || value == "" || len(value) > 200 || seen[value] {
				return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
			}
			seen[value] = true
			result.RecoveryCheckpointIDs = append(result.RecoveryCheckpointIDs, value)
		}
	}
	parseTime := func(key string) (time.Time, bool) {
		raw, exists := arguments[key]
		if !exists {
			return time.Time{}, true
		}
		text, ok := raw.(string)
		if !ok {
			return time.Time{}, false
		}
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(text))
		return parsed, err == nil
	}
	start, ok := parseTime("maintenanceWindowStart")
	if !ok {
		return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
	}
	end, ok := parseTime("maintenanceWindowEnd")
	if !ok {
		return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
	}
	if !start.IsZero() && !end.IsZero() && !end.After(start) {
		return "", 0, controlplane.UpgradeCampaignRevalidation{}, false
	}
	result.MaintenanceWindowStart = start
	result.MaintenanceWindowEnd = end
	return id, revision, result, true
}

func mcpIntegerArgument(arguments map[string]any, key string, min, max int) (int, bool) {
	raw, ok := arguments[key]
	if !ok {
		return 0, false
	}
	value, ok := raw.(float64)
	if !ok || math.Trunc(value) != value || value < float64(min) || value > float64(max) {
		return 0, false
	}
	return int(value), true
}

type mcpSupportBundleArgs struct {
	Profile        string
	ProjectID      string
	ClusterID      string
	OperationID    string
	IdempotencyKey string
}

func mcpSupportBundleArguments(arguments map[string]any) (mcpSupportBundleArgs, bool) {
	allowed := map[string]bool{"profile": true, "projectId": true, "clusterId": true, "operationId": true, "idempotencyKey": true}
	for key := range arguments {
		if !allowed[key] {
			return mcpSupportBundleArgs{}, false
		}
	}
	profile, a := mcpString(arguments, "profile", true, 64)
	projectID, b := mcpString(arguments, "projectId", false, 200)
	clusterID, c := mcpString(arguments, "clusterId", false, 200)
	operationID, d := mcpString(arguments, "operationId", false, 200)
	key, e := mcpString(arguments, "idempotencyKey", true, 200)
	if !(a && b && c && d && e) {
		return mcpSupportBundleArgs{}, false
	}
	switch profile {
	case "fleet-diagnostics":
		if projectID == "" || clusterID != "" || operationID != "" {
			return mcpSupportBundleArgs{}, false
		}
	case "cluster-diagnostics":
		if clusterID == "" || projectID != "" || operationID != "" {
			return mcpSupportBundleArgs{}, false
		}
	case "operation-diagnostics":
		if operationID == "" || projectID != "" || clusterID != "" {
			return mcpSupportBundleArgs{}, false
		}
	default:
		return mcpSupportBundleArgs{}, false
	}
	return mcpSupportBundleArgs{Profile: profile, ProjectID: projectID, ClusterID: clusterID, OperationID: operationID, IdempotencyKey: key}, true
}

type mcpManagedOKDInstallArgs struct {
	OrganizationID string                             `json:"organizationId"`
	ProjectID      string                             `json:"projectId"`
	TargetVersion  string                             `json:"targetVersion"`
	ClusterName    string                             `json:"clusterName"`
	BaseDomain     string                             `json:"baseDomain"`
	APIVIP         string                             `json:"apiVip"`
	IngressVIP     string                             `json:"ingressVip"`
	Connectivity   string                             `json:"connectivity,omitempty"`
	Disconnected   *managedinstall.DisconnectedConfig `json:"disconnected,omitempty"`
	Machines       []managedinstall.Machine           `json:"machines"`
	Artifacts      []managedinstall.Artifact          `json:"artifacts"`
	IdempotencyKey string                             `json:"idempotencyKey"`
}

func (a mcpManagedOKDInstallArgs) request() managedinstall.Request {
	return managedinstall.Request{OrganizationID: a.OrganizationID, ProjectID: a.ProjectID, TargetVersion: a.TargetVersion, ClusterName: a.ClusterName, BaseDomain: a.BaseDomain, APIVIP: a.APIVIP, IngressVIP: a.IngressVIP, Connectivity: a.Connectivity, Disconnected: a.Disconnected, Machines: a.Machines, Artifacts: a.Artifacts}
}

func mcpManagedOKDInstallArguments(arguments map[string]any) (mcpManagedOKDInstallArgs, bool) {
	if len(arguments) < 10 || len(arguments) > 12 {
		return mcpManagedOKDInstallArgs{}, false
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		return mcpManagedOKDInstallArgs{}, false
	}
	var out mcpManagedOKDInstallArgs
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&out); err != nil {
		return mcpManagedOKDInstallArgs{}, false
	}
	out.IdempotencyKey = strings.TrimSpace(out.IdempotencyKey)
	if out.IdempotencyKey == "" || len(out.IdempotencyKey) > 200 || managedinstall.ValidateRequest(out.request()) != nil {
		return mcpManagedOKDInstallArgs{}, false
	}
	return out, true
}
