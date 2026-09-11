package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/fleethealth"
	"platform.4so.io/factory/internal/labmodel"
	"platform.4so.io/factory/internal/managedinstall"
	"platform.4so.io/factory/internal/targetmodel"
)

const mcpProtocolVersion = "2026-07-28"

type mcpRequestParams struct {
	Name           string         `json:"name,omitempty"`
	Arguments      map[string]any `json:"arguments,omitempty"`
	Meta           map[string]any `json:"_meta"`
	InputResponses map[string]any `json:"inputResponses,omitempty"`
	RequestState   string         `json:"requestState,omitempty"`
}

type mcpRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  *mcpRequestParams `json:"params"`
}

type mcpTool struct {
	Name               string         `json:"name"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	InputSchema        map[string]any `json:"inputSchema"`
	RequiredPermission string         `json:"requiredPermission"`
	Family             string         `json:"family,omitempty"`
	Risk               string         `json:"risk,omitempty"`
	ApprovalRequired   bool           `json:"approvalRequired,omitempty"`
	AdministrationOnly bool           `json:"administrationOnly,omitempty"`
}

func mcpTools() []mcpTool {
	empty := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}}
	idInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	projectInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	projectListInput := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"organizationId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	projectCreateInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"organizationId", "name", "displayName"}, "properties": map[string]any{"organizationId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "name": map[string]any{"type": "string", "minLength": 1, "maxLength": 63}, "displayName": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}}
	workspaceCreateInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "name", "displayName"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "name": map[string]any{"type": "string", "minLength": 1, "maxLength": 63}, "displayName": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}, "description": map[string]any{"type": "string", "maxLength": 1024}}}
	workspaceBindingListInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspaceId"}, "properties": map[string]any{"workspaceId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	workspaceBindingCreateInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspaceId", "clusterId", "namespace"}, "properties": map[string]any{"workspaceId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "namespace": map[string]any{"type": "string", "minLength": 1, "maxLength": 63}}}
	workspaceBindingRevokeInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"bindingId", "expectedRevision"}, "properties": map[string]any{"bindingId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}}}
	searchInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "query"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "query": map[string]any{"type": "string", "minLength": 1, "maxLength": 500}}}
	notificationPreviewInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "eventType", "severity"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "eventType": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "severity": map[string]any{"type": "string", "enum": []string{"INFO", "WARNING", "CRITICAL"}}}}
	cancelInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "expectedRevision", "reason"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}, "reason": map[string]any{"type": "string", "minLength": 1, "maxLength": 500}}}
	supportBundleInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"profile", "idempotencyKey"}, "properties": map[string]any{"profile": map[string]any{"type": "string", "enum": []string{"fleet-diagnostics", "cluster-diagnostics", "operation-diagnostics"}}, "projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "operationId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	managedInstallMachine := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "credentialRef", "endpoint", "systemResource", "virtualMediaResource"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "credentialRef": map[string]any{"type": "string", "minLength": 1, "maxLength": 500}, "endpoint": map[string]any{"type": "string", "format": "uri"}, "systemResource": map[string]any{"type": "string", "minLength": 1, "maxLength": 1000}, "virtualMediaResource": map[string]any{"type": "string", "minLength": 1, "maxLength": 1000}}}
	managedInstallArtifact := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "url", "sha256"}, "properties": map[string]any{"name": map[string]any{"type": "string", "minLength": 1, "maxLength": 100}, "version": map[string]any{"type": "string", "maxLength": 100}, "url": map[string]any{"type": "string", "format": "uri"}, "sha256": map[string]any{"type": "string", "pattern": "^sha256:[0-9a-fA-F]{64}$"}}}
	disconnectedInstallInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"mirrorRegistry", "imageSetConfigurationSha256", "mirrorInventorySha256"}, "properties": map[string]any{"mirrorRegistry": map[string]any{"type": "string", "minLength": 1, "maxLength": 500}, "imageSetConfigurationSha256": map[string]any{"type": "string", "pattern": "^sha256:[0-9a-fA-F]{64}$"}, "mirrorInventorySha256": map[string]any{"type": "string", "pattern": "^sha256:[0-9a-fA-F]{64}$"}}}
	managedOKDInstallInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"organizationId", "projectId", "targetVersion", "clusterName", "baseDomain", "apiVip", "ingressVip", "machines", "artifacts", "idempotencyKey"}, "properties": map[string]any{"organizationId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "targetVersion": map[string]any{"type": "string", "minLength": 1, "maxLength": 100}, "clusterName": map[string]any{"type": "string", "minLength": 1, "maxLength": 253}, "baseDomain": map[string]any{"type": "string", "minLength": 1, "maxLength": 253}, "apiVip": map[string]any{"type": "string", "minLength": 1, "maxLength": 64}, "ingressVip": map[string]any{"type": "string", "minLength": 1, "maxLength": 64}, "connectivity": map[string]any{"type": "string", "enum": []string{"connected", "disconnected"}}, "disconnected": disconnectedInstallInput, "machines": map[string]any{"type": "array", "minItems": 3, "maxItems": 3, "items": managedInstallMachine}, "artifacts": map[string]any{"type": "array", "minItems": 3, "maxItems": 32, "items": managedInstallArtifact}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	approvalInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "expectedRevision"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}}}
	maintenanceRequestInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"clusterId", "windowId", "nodeNames", "idempotencyKey"}, "properties": map[string]any{"clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "windowId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "action": map[string]any{"type": "string", "enum": []string{"DRAIN", "OS_PATCH"}}, "nodeNames": map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 253}}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	targetNodeLifecyclePlanInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"clusterId", "action"}, "properties": map[string]any{"clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "action": map[string]any{"type": "string", "enum": []string{"ADD", "DRAIN", "REMOVE", "REPLACE", "OS_PATCH", "CERTIFICATE_RENEWAL", "REMEDIATE"}}, "nodeName": map[string]any{"type": "string", "minLength": 1, "maxLength": 253}}}
	driftScanInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "clusterIds", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterIds": map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	runtimeVerificationInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "clusterId", "baselineDeploymentId", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "baselineDeploymentId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	samlBrokerChangeInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"organizationId", "alias", "displayName", "entityId", "singleSignOnServiceUrl", "signingCertificate", "enabled", "idempotencyKey"}, "properties": map[string]any{"brokerId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}, "organizationId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "alias": map[string]any{"type": "string", "minLength": 1, "maxLength": 120}, "displayName": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "entityId": map[string]any{"type": "string", "minLength": 1, "maxLength": 1000}, "singleSignOnServiceUrl": map[string]any{"type": "string", "minLength": 1, "maxLength": 2000}, "singleLogoutServiceUrl": map[string]any{"type": "string", "maxLength": 2000}, "signingCertificate": map[string]any{"type": "string", "minLength": 1, "maxLength": 32768}, "nameIdPolicyFormat": map[string]any{"type": "string", "maxLength": 500}, "wantAuthnRequestsSigned": map[string]any{"type": "boolean"}, "enabled": map[string]any{"type": "boolean"}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	samlBrokerDeleteInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "expectedRevision", "idempotencyKey"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	upgradeCampaignInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "fleetGroupId", "targetVersion", "maintenanceWindowStart", "maintenanceWindowEnd", "recoveryCheckpointIds", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "fleetGroupId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "baselineId": map[string]any{"type": "string", "maxLength": 200}, "targetVersion": map[string]any{"type": "string", "minLength": 1, "maxLength": 100}, "canaryCount": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}, "waveSize": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}, "haltAfterFailures": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}, "maintenanceWindowStart": map[string]any{"type": "string", "format": "date-time"}, "maintenanceWindowEnd": map[string]any{"type": "string", "format": "date-time"}, "recoveryCheckpointIds": map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	dataProtectionRunInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "clusterId", "policyId", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "policyId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "backupRunId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	projectClusterInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	complianceScanInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "clusterId", "profileId", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "clusterId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "profileId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	complianceRecheckInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"projectId", "runId", "fingerprint", "idempotencyKey"}, "properties": map[string]any{"projectId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "runId": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "fingerprint": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}, "idempotencyKey": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}}
	upgradeControlInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "expectedRevision"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}, "reason": map[string]any{"type": "string", "maxLength": 500}}}
	upgradeRevalidateInput := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "expectedRevision"}, "properties": map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}, "expectedRevision": map[string]any{"type": "integer", "minimum": 1}, "recoveryCheckpointIds": map[string]any{"type": "array", "maxItems": 100, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 200}}, "maintenanceWindowStart": map[string]any{"type": "string", "format": "date-time"}, "maintenanceWindowEnd": map[string]any{"type": "string", "format": "date-time"}}}
	base := []mcpTool{
		{Name: "lab_guide", Title: "Lab certification guide", Description: "Read the canonical server tiers, deterministic test matrix, AI failure-only policy and MCP contract.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "target_architecture_model", Title: "Target architecture model", Description: "Read the canonical target-distribution architecture and product phase roadmap.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "mcp_delegation_architecture", Title: "MCP delegated access architecture", Description: "Read the canonical Keycloak/OAuth, revocable grant, user journey, tool-family and durable-write architecture for remote human MCP clients. C7R is source-implemented; C7W parity remains explicit and fail-closed.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "identity", Risk: "low"},
		{Name: "mcp_action_registry", Title: "MCP product action registry", Description: "Read the machine-readable API-family to MCP disposition registry. Pending parity remains explicit; generic raw mutation authority is forbidden.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "identity", Risk: "low"},
		{Name: "ai_runtime_policy", Title: "AI runtime policy", Description: "Read provider-neutral AI budgets, redaction requirements and authority boundaries without exposing credentials.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "platform_version", Title: "Platform version", Description: "Read the product identity and exact running Platform Factory version.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "version", Risk: "low"},
		{Name: "baselines", Title: "Baseline catalog", Description: "Read the immutable built-in baseline catalog and supported baseline upgrade edges.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "baselines", Risk: "low"},
		{Name: "tenancy_plans", Title: "Tenancy plans", Description: "Read the product-owned tenancy plan catalog used by the same REST and Console workflows.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "tenancy", Risk: "low"},
		{Name: "day2_campaign_engine", Title: "Day-2 campaign engine", Description: "Read the canonical machine-readable disruptive lifecycle campaign contract shared by maintenance and fleet upgrade workflows.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "day2-campaign-engine", Risk: "low"},
		{Name: "catalog_signing_identity", Title: "Catalog signing identity", Description: "Read the public catalog signing identity and fingerprint without exposing signing private material.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "catalog-governance", Risk: "low"},
		{Name: "projects", Title: "Projects", Description: "List authoritative projects visible to the current principal, optionally limited to one authorized organization.", InputSchema: projectListInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "projects", Risk: "low"},
		{Name: "project_create", Title: "Create project", Description: "Create one project in an organization where the current principal has organization administration access; project-scoped tokens cannot widen their scope.", InputSchema: projectCreateInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "projects", Risk: "medium", AdministrationOnly: true},
		{Name: "project_clusters", Title: "Project managed clusters", Description: "Discover up to 100 authoritative managed clusters inside one authorized project before drilling into a cluster.", InputSchema: projectInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "project_operations", Title: "Project durable operations", Description: "Discover up to 100 durable operations inside one authorized project before drilling into operation evidence.", InputSchema: projectInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "workspaces", Title: "Project workspaces", Description: "List authoritative application workspaces in one authorized project.", InputSchema: projectInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "workspaces", Risk: "low"},
		{Name: "workspace", Title: "Workspace", Description: "Read one project-scoped workspace and its immutable desired digest.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "workspaces", Risk: "low"},
		{Name: "workspace_create", Title: "Create workspace", Description: "Create one project-scoped application workspace using the same authoritative workspace store as the Operator Console.", InputSchema: workspaceCreateInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "workspaces", Risk: "medium"},
		{Name: "workspace_bindings", Title: "Workspace bindings", Description: "List cluster/namespace bindings for one authorized workspace.", InputSchema: workspaceBindingListInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "workspaces", Risk: "low"},
		{Name: "workspace_binding_create", Title: "Bind workspace to cluster namespace", Description: "Create a project-scoped workspace binding after validating that the managed cluster belongs to the same project.", InputSchema: workspaceBindingCreateInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "workspaces", Risk: "medium"},
		{Name: "workspace_binding_revoke", Title: "Revoke workspace binding", Description: "Revoke one active workspace binding using its exact expected revision; the historical binding remains auditable.", InputSchema: workspaceBindingRevokeInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "workspaces", Risk: "medium"},
		{Name: "ops_search", Title: "Project operational search", Description: "Search the 4SO-owned, rebuildable project projection across clusters, durable operations, evidence metadata and scoped audit records. The tool never exposes direct OpenSearch administration or treats the projection as source of truth.", InputSchema: searchInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "search", Risk: "low"},
		{Name: "notification_routing_preview", Title: "Notification routing preview", Description: "Preview which project/organization notification rules and active destinations would match an event without creating an event or delivery.", InputSchema: notificationPreviewInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "cluster_summary", Title: "Managed cluster summary", Description: "Read authoritative project-scoped cluster identity, health and inventory freshness metadata.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "cluster_maintenance_context", Title: "Cluster maintenance context", Description: "Read a project-scoped cluster maintenance profile, windows and recent runs before proposing maintenance.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "target_node_lifecycle_authority", Title: "Target node lifecycle authority", Description: "Read the inventory-pinned Add/Drain/Remove/Replace/OS Patch/Certificate Renewal/Remediation capability and executor matrix. Unsupported actions remain explicitly blocked.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "target_node_lifecycle_plan", Title: "Target node lifecycle impact plan", Description: "Build a read-only inventory/UID-pinned impact and recovery plan for one target-node lifecycle action. This tool never creates a mutation or approval request.", InputSchema: targetNodeLifecyclePlanInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "operation_status", Title: "Durable operation status", Description: "Read authoritative project-scoped operation state, retry and recovery metadata.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "ai_run", Title: "AI advisory run", Description: "Read a durable project-scoped advisory AI run and its digests/usage without raw prompts or credentials.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead},
		{Name: "operation_cancel", Title: "Request durable operation cancellation", Description: "Request cancellation of an existing project-scoped durable operation using its exact expected revision. This never bypasses safe-boundary cancellation semantics.", InputSchema: cancelInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "operation-control", Risk: "medium"},
		{Name: "identity_admin_job_approve", Title: "Approve identity administration job", Description: "Approve a pending organization identity administration job as a distinct ADMINISTRATION principal. Self-approval is rejected and Keycloak credentials remain server-side.", InputSchema: approvalInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "identity-admin", Risk: "high", AdministrationOnly: true},
		{Name: "cluster_maintenance_approve", Title: "Approve cluster maintenance request", Description: "Approve one pending cluster maintenance request as a distinct ADMINISTRATION principal. The original requester cannot approve the same change.", InputSchema: approvalInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "day2-maintenance", Risk: "high", AdministrationOnly: true},
		{Name: "upgrade_campaign_approve", Title: "Approve fleet upgrade campaign", Description: "Approve one pending fleet upgrade campaign as a distinct ADMINISTRATION principal. The original requester cannot approve the same campaign.", InputSchema: approvalInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "high", AdministrationOnly: true},
		{Name: "drift_scan_request", Title: "Request live drift scan", Description: "Create an idempotent project-scoped drift scan over explicit managed clusters. The scan is observational and cannot remediate findings.", InputSchema: driftScanInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "assurance", Risk: "low"},
		{Name: "runtime_verification_request", Title: "Request runtime verification", Description: "Create an idempotent runtime verification using the digest-pinned product probe for one successful baseline deployment.", InputSchema: runtimeVerificationInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "assurance", Risk: "low"},
		{Name: "saml_broker_change_request", Title: "Request organization SAML broker change", Description: "Create an organization-scoped durable SAML broker identity-admin job. The tool never receives Keycloak credentials and always stops at independent approval before reconciliation.", InputSchema: samlBrokerChangeInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "identity-admin", Risk: "high", ApprovalRequired: true, AdministrationOnly: true},
		{Name: "saml_broker_delete_request", Title: "Request organization SAML broker removal", Description: "Create an organization-scoped durable SAML broker deletion job. The tool never calls Keycloak directly and always stops at independent approval.", InputSchema: samlBrokerDeleteInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "identity-admin", Risk: "high", ApprovalRequired: true, AdministrationOnly: true},
		{Name: "identity_admin_job", Title: "Identity administration job", Description: "Read one organization-scoped durable identity administration job without exposing Keycloak credentials.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "identity-admin", Risk: "low", AdministrationOnly: true},
		{Name: "cluster_maintenance_request", Title: "Request cluster maintenance", Description: "Create an idempotent high-impact cluster maintenance request that stops at independent AWAITING_APPROVAL authority; the requesting AI cannot approve its own request through MCP.", InputSchema: maintenanceRequestInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "day2-maintenance", Risk: "high", ApprovalRequired: true},
		{Name: "upgrade_campaign_request", Title: "Request fleet upgrade campaign", Description: "Create an idempotent high-impact fleet upgrade campaign with explicit maintenance window and recovery checkpoints. It always stops at independent approval.", InputSchema: upgradeCampaignInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "high", ApprovalRequired: true},
		{Name: "support_bundle_request", Title: "Request support bundle", Description: "Create an idempotent durable support-bundle job for a project, cluster or operation. The bundle is generated by the sealed evidence worker and is never returned inline through MCP.", InputSchema: supportBundleInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "support-bundle", Risk: "low"},
		{Name: "managed_okd_install_runtime", Title: "Managed OKD runtime readiness", Description: "Read whether this control plane has a validated production Managed OKD executor. This never implies connected or Physical certification.", InputSchema: empty, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "managed-okd-installs", Risk: "low"},
		{Name: "managed_okd_install", Title: "Managed OKD install", Description: "Read one project-scoped durable managed OKD install without exposing BMC credential references or raw installer secrets.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "managed-okd-installs", Risk: "low"},
		{Name: "managed_okd_install_request", Title: "Request managed OKD install", Description: "Create a Compact-3 managed OKD installation from exact artifacts. BMC credentials remain server-side references and execution always stops at independent approval.", InputSchema: managedOKDInstallInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "managed-okd-installs", Risk: "critical", ApprovalRequired: true},
		{Name: "managed_okd_install_approve", Title: "Approve managed OKD install", Description: "Approve one pending managed OKD install as a distinct ADMINISTRATION principal. The original requester cannot approve the installation.", InputSchema: approvalInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "managed-okd-installs", Risk: "critical", AdministrationOnly: true},
		{Name: "backup_policies", Title: "Backup policies", Description: "Read authoritative backup policies for one project and optional cluster without exposing referenced credentials.", InputSchema: projectClusterInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "data-protection", Risk: "low"},
		{Name: "data_protection_runs", Title: "Data protection runs", Description: "Read bounded backup, restore and restore-drill run authority for one project and optional cluster.", InputSchema: projectClusterInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "data-protection", Risk: "low"},
		{Name: "backup_run_request", Title: "Request backup run", Description: "Create an idempotent project-scoped durable backup run using an existing active backup policy. Credentials remain server/agent-side references.", InputSchema: dataProtectionRunInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "data-protection", Risk: "medium"},
		{Name: "restore_run_request", Title: "Request restore run", Description: "Create an idempotent high-impact restore request from a successful backup checkpoint. It remains AWAITING_APPROVAL until a distinct administrator approves it.", InputSchema: dataProtectionRunInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "data-protection", Risk: "high", ApprovalRequired: true},
		{Name: "restore_drill_request", Title: "Request restore drill", Description: "Create an idempotent isolated restore-drill run from a successful backup checkpoint without treating the drill as production recovery.", InputSchema: dataProtectionRunInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "data-protection", Risk: "medium"},
		{Name: "restore_run_approve", Title: "Approve restore run", Description: "Approve one pending restore run as a distinct ADMINISTRATION principal. Self-approval is rejected by the durable data-protection authority.", InputSchema: approvalInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "data-protection", Risk: "high", AdministrationOnly: true},
		{Name: "compliance_scan_request", Title: "Request compliance scan", Description: "Create an idempotent project-scoped compliance scan against an admitted profile and connected cluster. Raw Kubernetes manifests never become MCP output.", InputSchema: complianceScanInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "compliance", Risk: "low"},
		{Name: "compliance_recheck_request", Title: "Recheck compliance finding", Description: "Create a fresh durable compliance scan to re-evaluate one known finding fingerprint under the same profile and cluster context.", InputSchema: complianceRecheckInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "compliance", Risk: "low"},
		{Name: "upgrade_campaigns", Title: "Fleet upgrade campaigns", Description: "Read authoritative fleet upgrade campaigns for one project.", InputSchema: projectInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "fleet-upgrade", Risk: "low"},
		{Name: "upgrade_campaign", Title: "Fleet upgrade campaign", Description: "Read one authoritative fleet upgrade campaign including its state, wave and recovery metadata.", InputSchema: idInput, RequiredPermission: controlplane.APITokenPermissionMCPRead, Family: "fleet-upgrade", Risk: "low"},
		{Name: "upgrade_campaign_pause", Title: "Pause fleet upgrade campaign", Description: "Persist a pause request for an approved/running fleet upgrade campaign using optimistic concurrency.", InputSchema: upgradeControlInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "medium"},
		{Name: "upgrade_campaign_resume", Title: "Resume fleet upgrade campaign", Description: "Resume a paused fleet upgrade campaign using its exact expected revision.", InputSchema: upgradeControlInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "medium"},
		{Name: "upgrade_campaign_cancel", Title: "Cancel fleet upgrade campaign", Description: "Persist a cancellation request for a fleet upgrade campaign; cancellation still follows the campaign safe-boundary semantics.", InputSchema: upgradeControlInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "high"},
		{Name: "upgrade_campaign_revalidate", Title: "Revalidate fleet upgrade campaign", Description: "Revalidate recovery checkpoints and maintenance-window context on a non-running campaign using optimistic concurrency.", InputSchema: upgradeRevalidateInput, RequiredPermission: controlplane.APITokenPermissionMCPOperate, Family: "fleet-upgrade", Risk: "medium"},
	}
	return append(base, mcpRouteTools()...)
}

func mcpToolAuthorizedForRequest(r *http.Request, tool mcpTool) bool {
	principal, ok := requestPrincipal(r)
	// Explicit loopback development authentication is intentionally read-only
	// on the MCP surface. Development mode may grant platform-admin authority
	// to the local REST/UI session, but it must never silently turn an
	// unauthenticated MCP client into an operate/administration principal.
	if ok && principal.Subject == "local-development" && principal.Authentication == "local" {
		return tool.RequiredPermission == controlplane.APITokenPermissionMCPRead && !tool.AdministrationOnly
	}
	if tool.AdministrationOnly {
		if !ok {
			return false
		}
		if principal.Authentication == "api-token" {
			return false
		}
		if principal.Authentication == "mcp-human" {
			return strings.EqualFold(strings.TrimSpace(principal.DelegationAccessProfile), "ADMINISTRATION")
		}
		return auth.HasAnyRole(principal, "platform-admin")
	}
	if tool.RequiredPermission != controlplane.APITokenPermissionMCPOperate {
		return true
	}
	if !ok {
		// The production /mcp route is always behind RequireAPI. Keeping the
		// inner handler read-only without a principal prevents test/dev callers
		// from turning X-Actor-ID into a mutation authority.
		return false
	}
	if principal.Authentication == "api-token" {
		return principalHasPermission(principal, controlplane.APITokenPermissionMCPOperate)
	}
	if principal.Authentication == "mcp-human" {
		profile := strings.ToUpper(strings.TrimSpace(principal.DelegationAccessProfile))
		return profile == "OPERATE" || profile == "ADMINISTRATION"
	}
	return auth.HasAnyRole(principal, "platform-admin", "platform-operator")
}

func mcpToolByName(name string) (mcpTool, bool) {
	name = strings.TrimSpace(name)
	for _, tool := range mcpTools() {
		if tool.Name == name {
			return tool, true
		}
	}
	return mcpTool{}, false
}

func (s *Server) mcpVisibleTools(r *http.Request) []mcpTool {
	all := mcpTools()
	out := make([]mcpTool, 0, len(all))
	for _, tool := range all {
		if mcpToolAuthorizedForRequest(r, tool) {
			out = append(out, tool)
		}
	}
	return out
}

func mcpExactIDArgument(arguments map[string]any) (string, bool) {
	if len(arguments) != 1 {
		return "", false
	}
	raw, ok := arguments["id"].(string)
	id := strings.TrimSpace(raw)
	return id, ok && id != "" && len(id) <= 200
}

func mcpApprovalArguments(arguments map[string]any) (string, int64, bool) {
	if len(arguments) != 2 {
		return "", 0, false
	}
	id, idOK := mcpString(arguments, "id", true, 200)
	revision, revisionOK := mcpPositiveRevision(arguments, "expectedRevision", true)
	return id, revision, idOK && revisionOK
}

func mcpTargetNodeLifecyclePlanArguments(arguments map[string]any) (string, controlplane.TargetNodeLifecyclePlanRequest, bool) {
	if len(arguments) < 2 || len(arguments) > 3 {
		return "", controlplane.TargetNodeLifecyclePlanRequest{}, false
	}
	rawCluster, clusterOK := arguments["clusterId"].(string)
	rawAction, actionOK := arguments["action"].(string)
	clusterID := strings.TrimSpace(rawCluster)
	action := controlplane.TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(rawAction)))
	if !clusterOK || !actionOK || clusterID == "" || len(clusterID) > 200 {
		return "", controlplane.TargetNodeLifecyclePlanRequest{}, false
	}
	switch action {
	case controlplane.TargetNodeActionAdd, controlplane.TargetNodeActionDrain, controlplane.TargetNodeActionRemove, controlplane.TargetNodeActionReplace, controlplane.TargetNodeActionOSPatch, controlplane.TargetNodeActionCertificateRenewal, controlplane.TargetNodeActionRemediate:
	default:
		return "", controlplane.TargetNodeLifecyclePlanRequest{}, false
	}
	nodeName := ""
	if raw, exists := arguments["nodeName"]; exists {
		name, ok := raw.(string)
		nodeName = strings.TrimSpace(name)
		if !ok || nodeName == "" || len(nodeName) > 253 {
			return "", controlplane.TargetNodeLifecyclePlanRequest{}, false
		}
	}
	return clusterID, controlplane.TargetNodeLifecyclePlanRequest{Action: action, NodeName: nodeName}, true
}

func mcpExactProjectArgument(arguments map[string]any) (string, bool) {
	if len(arguments) != 1 {
		return "", false
	}
	raw, ok := arguments["projectId"].(string)
	projectID := strings.TrimSpace(raw)
	return projectID, ok && projectID != "" && len(projectID) <= 200
}

func mcpSearchArguments(arguments map[string]any) (string, string, bool) {
	if len(arguments) != 2 {
		return "", "", false
	}
	rawProject, projectOK := arguments["projectId"].(string)
	rawQuery, queryOK := arguments["query"].(string)
	projectID, query := strings.TrimSpace(rawProject), strings.TrimSpace(rawQuery)
	if !projectOK || !queryOK || projectID == "" || query == "" || len(projectID) > 200 || len(query) > 500 {
		return "", "", false
	}
	return projectID, query, true
}

func mcpNotificationPreviewArguments(arguments map[string]any) (string, string, controlplane.NotificationSeverity, bool) {
	if len(arguments) != 3 {
		return "", "", "", false
	}
	rawProject, projectOK := arguments["projectId"].(string)
	rawEvent, eventOK := arguments["eventType"].(string)
	rawSeverity, severityOK := arguments["severity"].(string)
	projectID := strings.TrimSpace(rawProject)
	eventType, validEvent := normalizeNotificationPreviewEventType(rawEvent)
	severity := controlplane.NotificationSeverity(strings.ToUpper(strings.TrimSpace(rawSeverity)))
	if !projectOK || !eventOK || !severityOK || projectID == "" || len(projectID) > 200 || !validEvent || !validNotificationPreviewSeverity(severity) {
		return "", "", "", false
	}
	return projectID, eventType, severity, true
}

func mcpOperationCancelArguments(arguments map[string]any) (string, int64, string, bool) {
	if len(arguments) != 3 {
		return "", 0, "", false
	}
	rawID, idOK := arguments["id"].(string)
	rawRevision, revOK := arguments["expectedRevision"].(float64)
	rawReason, reasonOK := arguments["reason"].(string)
	id := strings.TrimSpace(rawID)
	reason := strings.TrimSpace(rawReason)
	if !idOK || !revOK || !reasonOK || id == "" || len(id) > 200 || reason == "" || len(reason) > 500 || rawRevision < 1 || math.Trunc(rawRevision) != rawRevision || rawRevision > math.MaxInt64 {
		return "", 0, "", false
	}
	return id, int64(rawRevision), reason, true
}

func mcpMaintenanceRequestArguments(arguments map[string]any) (string, string, controlplane.TargetNodeLifecycleAction, []string, string, bool) {
	if len(arguments) < 4 || len(arguments) > 5 {
		return "", "", "", nil, "", false
	}
	rawCluster, clusterOK := arguments["clusterId"].(string)
	rawWindow, windowOK := arguments["windowId"].(string)
	rawKey, keyOK := arguments["idempotencyKey"].(string)
	rawNodes, nodesOK := arguments["nodeNames"].([]any)
	clusterID, windowID, key := strings.TrimSpace(rawCluster), strings.TrimSpace(rawWindow), strings.TrimSpace(rawKey)
	action := controlplane.TargetNodeActionDrain
	if raw, exists := arguments["action"]; exists {
		value, ok := raw.(string)
		if !ok {
			return "", "", "", nil, "", false
		}
		action = controlplane.TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(value)))
		if action != controlplane.TargetNodeActionDrain && action != controlplane.TargetNodeActionOSPatch {
			return "", "", "", nil, "", false
		}
	}
	if !clusterOK || !windowOK || !keyOK || !nodesOK || clusterID == "" || windowID == "" || key == "" || len(clusterID) > 200 || len(windowID) > 200 || len(key) > 200 || len(rawNodes) < 1 || len(rawNodes) > 100 {
		return "", "", "", nil, "", false
	}
	nodes := make([]string, 0, len(rawNodes))
	seen := map[string]bool{}
	for _, raw := range rawNodes {
		name, ok := raw.(string)
		name = strings.TrimSpace(name)
		if !ok || name == "" || len(name) > 253 || seen[name] {
			return "", "", "", nil, "", false
		}
		seen[name] = true
		nodes = append(nodes, name)
	}
	return clusterID, windowID, action, nodes, key, true
}

func mcpProjectClustersRequestArguments(arguments map[string]any) (string, []string, string, bool) {
	if len(arguments) != 3 {
		return "", nil, "", false
	}
	projectID, pOK := arguments["projectId"].(string)
	key, kOK := arguments["idempotencyKey"].(string)
	rawIDs, idsOK := arguments["clusterIds"].([]any)
	projectID, key = strings.TrimSpace(projectID), strings.TrimSpace(key)
	if !pOK || !kOK || !idsOK || projectID == "" || key == "" || len(projectID) > 200 || len(key) > 200 || len(rawIDs) < 1 || len(rawIDs) > 100 {
		return "", nil, "", false
	}
	ids := make([]string, 0, len(rawIDs))
	seen := map[string]bool{}
	for _, raw := range rawIDs {
		id, ok := raw.(string)
		id = strings.TrimSpace(id)
		if !ok || id == "" || len(id) > 200 || seen[id] {
			return "", nil, "", false
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return projectID, ids, key, true
}

func mcpRuntimeVerificationRequestArguments(arguments map[string]any) (string, string, string, string, bool) {
	if len(arguments) != 4 {
		return "", "", "", "", false
	}
	projectID, pOK := arguments["projectId"].(string)
	clusterID, cOK := arguments["clusterId"].(string)
	baselineID, bOK := arguments["baselineDeploymentId"].(string)
	key, kOK := arguments["idempotencyKey"].(string)
	projectID, clusterID, baselineID, key = strings.TrimSpace(projectID), strings.TrimSpace(clusterID), strings.TrimSpace(baselineID), strings.TrimSpace(key)
	if !pOK || !cOK || !bOK || !kOK || projectID == "" || clusterID == "" || baselineID == "" || key == "" || len(projectID) > 200 || len(clusterID) > 200 || len(baselineID) > 200 || len(key) > 200 {
		return "", "", "", "", false
	}
	return projectID, clusterID, baselineID, key, true
}

func mcpOptionalPositiveInt(arguments map[string]any, key string, def int) (int, bool) {
	raw, ok := arguments[key]
	if !ok {
		return def, true
	}
	n, ok := raw.(float64)
	if !ok || n < 1 || n > 100 || math.Trunc(n) != n {
		return 0, false
	}
	return int(n), true
}

func mcpUpgradeCampaignRequestArguments(arguments map[string]any) (createUpgradeCampaignInput, string, bool) {
	if len(arguments) < 7 || len(arguments) > 11 {
		return createUpgradeCampaignInput{}, "", false
	}
	get := func(k string) (string, bool) {
		v, ok := arguments[k].(string)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	projectID, pOK := get("projectId")
	fleetGroupID, fOK := get("fleetGroupId")
	targetVersion, tOK := get("targetVersion")
	startRaw, sOK := get("maintenanceWindowStart")
	endRaw, eOK := get("maintenanceWindowEnd")
	key, kOK := get("idempotencyKey")
	baselineID, _ := arguments["baselineId"].(string)
	baselineID = strings.TrimSpace(baselineID)
	rawCP, cpOK := arguments["recoveryCheckpointIds"].([]any)
	if !pOK || !fOK || !tOK || !sOK || !eOK || !kOK || !cpOK || len(rawCP) < 1 || len(rawCP) > 100 || len(projectID) > 200 || len(fleetGroupID) > 200 || len(targetVersion) > 100 || len(key) > 200 || len(baselineID) > 200 {
		return createUpgradeCampaignInput{}, "", false
	}
	start, err := time.Parse(time.RFC3339, startRaw)
	if err != nil {
		return createUpgradeCampaignInput{}, "", false
	}
	end, err := time.Parse(time.RFC3339, endRaw)
	if err != nil || !end.After(start) {
		return createUpgradeCampaignInput{}, "", false
	}
	checkpoints := make([]string, 0, len(rawCP))
	seen := map[string]bool{}
	for _, raw := range rawCP {
		id, ok := raw.(string)
		id = strings.TrimSpace(id)
		if !ok || id == "" || len(id) > 200 || seen[id] {
			return createUpgradeCampaignInput{}, "", false
		}
		seen[id] = true
		checkpoints = append(checkpoints, id)
	}
	canary, ok := mcpOptionalPositiveInt(arguments, "canaryCount", 1)
	if !ok {
		return createUpgradeCampaignInput{}, "", false
	}
	wave, ok := mcpOptionalPositiveInt(arguments, "waveSize", 2)
	if !ok {
		return createUpgradeCampaignInput{}, "", false
	}
	halt, ok := mcpOptionalPositiveInt(arguments, "haltAfterFailures", 1)
	if !ok {
		return createUpgradeCampaignInput{}, "", false
	}
	return createUpgradeCampaignInput{ProjectID: projectID, FleetGroupID: fleetGroupID, BaselineID: baselineID, TargetVersion: targetVersion, CanaryCount: canary, WaveSize: wave, HaltAfterFailures: halt, MaintenanceWindowStart: start, MaintenanceWindowEnd: end, RecoveryCheckpointIDs: checkpoints}, key, true
}

func mcpRequestIDValid(id json.RawMessage) bool {
	if len(id) == 0 || string(id) == "null" {
		return false
	}
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func decodeMCPHeaderValue(value string) (string, bool) {
	if strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=") {
		raw := strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?=")
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", false
		}
		return string(decoded), true
	}
	if strings.TrimSpace(value) != value || value == "" {
		return "", false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return "", false
		}
	}
	return value, true
}

func mcpServerMeta(version string) map[string]any {
	return map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "4so-platform-factory", "version": version}}
}

func (s *Server) writeMCPResult(w http.ResponseWriter, id json.RawMessage, result map[string]any) {
	result["resultType"] = "complete"
	if _, ok := result["_meta"]; !ok {
		result["_meta"] = mcpServerMeta(s.version)
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeMCPErrorData(w http.ResponseWriter, id json.RawMessage, status, code int, message string, data any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	err := map[string]any{"code": code, "message": message}
	if data != nil {
		err["data"] = data
	}
	writeJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": err})
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, status, code int, message string) {
	writeMCPErrorData(w, id, status, code, message, nil)
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	var delegationErr error
	r, delegationErr = s.applyMCPHumanDelegation(r)
	if delegationErr != nil {
		writeMCPError(w, nil, http.StatusForbidden, -32003, delegationErr.Error())
		return
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		writeMCPError(w, nil, http.StatusUnsupportedMediaType, -32600, "Content-Type must be application/json")
		return
	}
	if strings.TrimSpace(r.Header.Get("Origin")) != "" {
		writeMCPError(w, nil, http.StatusForbidden, -32600, "browser Origin requests are not admitted on the MCP agent endpoint")
		return
	}
	if err := s.requireCapabilityAuthorization(r, "mcp.read", true); err != nil {
		if errors.Is(err, errCapabilityAccessDenied) {
			writeMCPError(w, nil, http.StatusForbidden, -32001, "mcp.read capability permission is required")
		} else {
			writeMCPError(w, nil, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
		}
		return
	}
	var req mcpRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeMCPError(w, nil, http.StatusBadRequest, -32700, "invalid JSON-RPC request")
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32700, "request body must contain exactly one JSON-RPC object")
		return
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" || !mcpRequestIDValid(req.ID) || req.Params == nil {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32600, "invalid JSON-RPC request")
		return
	}
	bodyVersion, ok := req.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string)
	if !ok || strings.TrimSpace(bodyVersion) == "" {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "request params._meta must include io.modelcontextprotocol/protocolVersion")
		return
	}
	if _, ok := req.Params.Meta["io.modelcontextprotocol/clientCapabilities"].(map[string]any); !ok {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "request params._meta must include io.modelcontextprotocol/clientCapabilities as an object")
		return
	}
	headerVersion := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if headerVersion == "" || headerVersion != bodyVersion {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32020, "MCP-Protocol-Version header must match params._meta protocolVersion")
		return
	}
	if bodyVersion != mcpProtocolVersion {
		writeMCPErrorData(w, req.ID, http.StatusBadRequest, -32022, "unsupported MCP protocol version", map[string]any{"requested": bodyVersion, "supported": []string{mcpProtocolVersion}})
		return
	}
	headerMethod := strings.TrimSpace(r.Header.Get("Mcp-Method"))
	if headerMethod == "" || headerMethod != req.Method {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32020, "Mcp-Method header must match the JSON-RPC method")
		return
	}
	if req.Method == "tools/call" {
		headerName, valid := decodeMCPHeaderValue(r.Header.Get("Mcp-Name"))
		if !valid || headerName != req.Params.Name {
			writeMCPError(w, req.ID, http.StatusBadRequest, -32020, "Mcp-Name header must match params.name")
			return
		}
	} else if strings.TrimSpace(r.Header.Get("Mcp-Name")) != "" {
		writeMCPError(w, req.ID, http.StatusBadRequest, -32020, "Mcp-Name is not valid for this MCP method")
		return
	}

	switch req.Method {
	case "server/discover":
		s.writeMCPResult(w, req.ID, map[string]any{
			"supportedVersions": []string{mcpProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"instructions":      "4SO Platform Factory MCP is read-only by default. Explicit mcp.operate grants expose only allow-listed product operations through normal RBAC, project scope, revision, durable-operation and audit authority. Test PASS and Physical PASS are never decided by MCP or AI.",
			"ttlMs":             60000,
			"cacheScope":        "private",
		})
	case "tools/list":
		s.writeMCPResult(w, req.ID, map[string]any{"tools": s.mcpVisibleTools(r), "ttlMs": 60000, "cacheScope": "private"})
	case "tools/call":
		tool, exists := mcpToolByName(req.Params.Name)
		if !exists {
			writeMCPError(w, req.ID, http.StatusNotFound, -32602, fmt.Sprintf("unknown tool %q", req.Params.Name))
			return
		}
		if !mcpToolAuthorizedForRequest(r, tool) {
			writeMCPError(w, req.ID, http.StatusForbidden, -32001, "MCP tool is not authorized for the current principal or delegation profile")
			return
		}
		var value any
		if route, ok := mcpRouteByTool(req.Params.Name); ok {
			bridgeValue, err := s.callMCPRouteTool(r.Context(), r, route, req.Params.Arguments)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32030, "MCP fixed-route action was not completed", map[string]any{"detail": err.Error(), "authority": mcpRouteParityAuthority})
				return
			}
			s.writeMCPResult(w, req.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": mustJSON(bridgeValue)}}, "structuredContent": bridgeValue})
			return
		}
		switch strings.TrimSpace(req.Params.Name) {
		case "lab_guide":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "lab_guide accepts no arguments")
				return
			}
			value = labmodel.Model()
		case "target_architecture_model":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "target_architecture_model accepts no arguments")
				return
			}
			value = targetmodel.ArchitectureModel()
		case "mcp_delegation_architecture":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "mcp_delegation_architecture accepts no arguments")
				return
			}
			value = targetmodel.MCPRemoteOAuthModel()
		case "mcp_action_registry":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "mcp_action_registry accepts no arguments")
				return
			}
			value = mcpProductActionRegistryModel()
		case "ai_runtime_policy":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "ai_runtime_policy accepts no arguments")
				return
			}
			if s.aiRuntime == nil {
				value = map[string]any{"enabled": false, "provider": "none", "redactionRequired": true, "advisoryOnly": true, "canDecidePass": false, "canDecidePhysicalPass": false}
			} else {
				value = s.aiRuntime.Policy()
			}
		case "platform_version":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "platform_version accepts no arguments")
				return
			}
			value = map[string]string{"product": "4SO Platform Factory", "version": s.version}
		case "baselines":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "baselines accepts no arguments")
				return
			}
			value = baseline.Catalog()
		case "tenancy_plans":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "tenancy_plans accepts no arguments")
				return
			}
			plans, err := catalog.LoadTenantPlans()
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "tenant plan catalog is unavailable")
				return
			}
			value = plans
		case "day2_campaign_engine":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "day2_campaign_engine accepts no arguments")
				return
			}
			value = controlplane.Day2CampaignEngineModel()
		case "catalog_signing_identity":
			if len(req.Params.Arguments) != 0 {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "catalog_signing_identity accepts no arguments")
				return
			}
			value = s.catalogSigningIdentityModel()
		case "projects":
			organizationID, ok := mcpProjectListArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "projects accepts only optional organizationId")
				return
			}
			if organizationID != "" {
				if err := s.requireOrganizationAccess(r, organizationID, organizationRead); err != nil {
					writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization read access is required")
					return
				}
			}
			items, err := s.store.ListProjects(r.Context(), organizationID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list projects")
				return
			}
			allowedProjects, allProjects, err := s.accessibleProjectSet(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "resolve project scope")
				return
			}
			if !allProjects {
				filtered := make([]controlplane.Project, 0, len(items))
				for _, project := range items {
					if allowedProjects[project.ID] {
						filtered = append(filtered, project)
					}
				}
				items = filtered
			}
			if len(items) > 100 {
				items = items[:100]
			}
			value = map[string]any{"authority": "CONTROL_PLANE_PROJECT_AUTHORITY_V1", "organizationId": organizationID, "items": items, "bounded": true, "limit": 100}

		case "project_create":
			organizationID, name, displayName, ok := mcpProjectCreateArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "project_create requires organizationId, name and displayName")
				return
			}
			if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization administration access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			project, err := s.store.CreateProject(r.Context(), controlplane.Project{OrganizationID: organizationID, Name: name, DisplayName: displayName}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "project creation was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "CONTROL_PLANE_PROJECT_AUTHORITY_V1", "project": project}

		case "project_clusters":
			projectID, ok := mcpExactProjectArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "project_clusters requires exactly one projectId argument")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			clusters, err := s.store.ListManagedClusters(r.Context(), projectID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list managed clusters")
				return
			}
			total := len(clusters)
			if len(clusters) > 100 {
				clusters = clusters[:100]
			}
			items := make([]map[string]any, 0, len(clusters))
			for _, cluster := range clusters {
				items = append(items, map[string]any{"id": cluster.ID, "projectId": cluster.ProjectID, "revision": cluster.Revision, "name": cluster.Name, "distribution": cluster.Distribution, "connectionState": cluster.ConnectionState, "lastSeenAt": cluster.LastSeenAt, "inventoryObservedAt": cluster.InventoryObservedAt})
			}
			value = map[string]any{"projectId": projectID, "items": items, "returned": len(items), "total": total, "truncated": total > len(items)}
		case "project_operations":
			projectID, ok := mcpExactProjectArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "project_operations requires exactly one projectId argument")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			operations, err := s.store.ListOperations(r.Context(), projectID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list durable operations")
				return
			}
			total := len(operations)
			if len(operations) > 100 {
				operations = operations[:100]
			}
			items := make([]map[string]any, 0, len(operations))
			for _, op := range operations {
				items = append(items, map[string]any{"id": op.ID, "projectId": op.ProjectID, "revision": op.Revision, "kind": op.Kind, "targetRef": op.TargetRef, "state": op.State, "risk": op.Risk, "class": op.Class, "updatedAt": op.UpdatedAt})
			}
			value = map[string]any{"projectId": projectID, "items": items, "returned": len(items), "total": total, "truncated": total > len(items)}
		case "workspaces":
			projectID, ok := mcpExactProjectArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspaces requires exactly one projectId argument")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			items, err := s.store.ListWorkspaces(r.Context(), projectID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list workspaces")
				return
			}
			if len(items) > 100 {
				items = items[:100]
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "projectId": projectID, "items": items, "bounded": true, "limit": 100}

		case "workspace":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspace requires exactly one id argument")
				return
			}
			item, err := s.store.GetWorkspace(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "workspace not found")
				return
			}
			if _, err = s.requireProjectAccess(r, item.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "workspace": item}

		case "workspace_create":
			projectID, name, displayName, description, ok := mcpWorkspaceCreateArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspace_create requires projectId, name, displayName and optional description")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			item, err := s.store.CreateWorkspace(r.Context(), controlplane.Workspace{ProjectID: projectID, Name: name, DisplayName: displayName, Description: description}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "workspace create was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "workspace": item}

		case "workspace_bindings":
			workspaceID, ok := mcpWorkspaceBindingListArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspace_bindings requires exactly one workspaceId")
				return
			}
			workspace, err := s.store.GetWorkspace(r.Context(), workspaceID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "workspace not found")
				return
			}
			if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			bindings, err := s.store.ListWorkspaceBindings(r.Context(), workspaceID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list workspace bindings")
				return
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "workspaceId": workspaceID, "projectId": workspace.ProjectID, "items": bindings}

		case "workspace_binding_create":
			workspaceID, clusterID, namespace, ok := mcpWorkspaceBindingCreateArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspace_binding_create requires workspaceId, clusterId and namespace")
				return
			}
			workspace, err := s.store.GetWorkspace(r.Context(), workspaceID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "workspace not found")
				return
			}
			if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			binding, err := s.store.CreateWorkspaceBinding(r.Context(), controlplane.WorkspaceBinding{WorkspaceID: workspaceID, ClusterID: clusterID, Namespace: namespace}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "workspace binding was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "binding": binding}

		case "workspace_binding_revoke":
			bindingID, expected, ok := mcpWorkspaceBindingRevokeArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "workspace_binding_revoke requires bindingId and positive expectedRevision")
				return
			}
			binding, err := s.store.GetWorkspaceBinding(r.Context(), bindingID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "workspace binding not found")
				return
			}
			if _, err = s.requireProjectAccess(r, binding.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			binding, err = s.store.RevokeWorkspaceBinding(r.Context(), bindingID, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "workspace binding revoke was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.WorkspaceAuthority, "binding": binding}

		case "ops_search":
			projectID, query, ok := mcpSearchArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "ops_search requires exactly projectId and non-empty query")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			docs, err := s.buildSearchProjectionDocuments(r, projectID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "build operational search projection")
				return
			}
			results := filterSearchProjectionDocuments(docs, query, 100)
			value = map[string]any{"authority": searchProjectionAuthority, "rebuildAuthority": searchRebuildAuthority, "backend": "postgresql-bounded", "optionalScaleBackend": "opensearch", "projectId": projectID, "query": query, "results": results, "resultCount": len(results), "bounded": true, "limit": 100, "sourceOfTruth": false}
		case "notification_routing_preview":
			projectID, eventType, severity, ok := mcpNotificationPreviewArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "notification_routing_preview requires projectId, eventType and severity INFO/WARNING/CRITICAL")
				return
			}
			project, err := s.requireProjectAccess(r, projectID, organizationRead)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			preview, err := s.notificationRoutingPreviewResult(r.Context(), project.OrganizationID, projectID, eventType, severity)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "preview notification routing")
				return
			}
			value = preview
		case "cluster_summary":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "cluster_summary requires exactly one id argument")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = map[string]any{"id": cluster.ID, "projectId": cluster.ProjectID, "revision": cluster.Revision, "name": cluster.Name, "distribution": cluster.Distribution, "kubernetesVersion": cluster.KubernetesVersion, "agentVersion": cluster.AgentVersion, "connectionState": cluster.ConnectionState, "lastSeenAt": cluster.LastSeenAt, "inventoryObservedAt": cluster.InventoryObservedAt, "inventoryDigest": cluster.InventoryDigest, "capabilities": cluster.Capabilities}

		case "cluster_maintenance_context":
			clusterID, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "cluster_maintenance_context requires exactly one id argument")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			profile, profileErr := s.store.GetClusterMaintenanceProfile(r.Context(), clusterID)
			windows, windowsErr := s.store.ListClusterMaintenanceWindows(r.Context(), clusterID)
			runs, runsErr := s.store.ListClusterMaintenanceRuns(r.Context(), clusterID)
			if windowsErr != nil || runsErr != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "read cluster maintenance authority")
				return
			}
			result := map[string]any{"authority": controlplane.ClusterMaintenanceAuthorityMethod, "clusterId": clusterID, "projectId": cluster.ProjectID, "windows": windows, "runs": runs}
			if profileErr == nil {
				result["profile"] = profile
			} else if errors.Is(profileErr, controlplane.ErrNotFound) {
				result["profile"] = nil
				result["profileStatus"] = "NOT_CONFIGURED"
			} else {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "read cluster maintenance profile")
				return
			}
			value = result
		case "target_node_lifecycle_authority":
			clusterID, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "target_node_lifecycle_authority requires exactly one id argument")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "current cluster inventory is required")
				return
			}
			value = controlplane.BuildTargetNodeLifecycleAuthority(cluster, inventory, s.targetNodeProviderBindingReady(r, cluster), s.targetNodeProviderMachineLifecycleReady(r, cluster))
		case "target_node_lifecycle_plan":
			clusterID, planRequest, ok := mcpTargetNodeLifecyclePlanArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "target_node_lifecycle_plan requires clusterId, a supported action, and nodeName when the action targets an existing node")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "current cluster inventory is required")
				return
			}
			plan, err := controlplane.BuildTargetNodeLifecyclePlan(cluster, inventory, planRequest, s.targetNodeProviderBindingReady(r, cluster), s.targetNodeProviderMachineLifecycleReady(r, cluster))
			if err != nil {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, err.Error())
				return
			}
			value = plan
		case "operation_status":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "operation_status requires exactly one id argument")
				return
			}
			op, err := s.store.GetOperation(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "operation not found")
				return
			}
			if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = map[string]any{"id": op.ID, "projectId": op.ProjectID, "revision": op.Revision, "kind": op.Kind, "targetRef": op.TargetRef, "desiredRevision": op.DesiredRevision, "state": op.State, "risk": op.Risk, "class": op.Class, "attempt": op.Attempt, "retryExhausted": op.RetryExhausted, "lastFailureClass": op.LastFailureClass, "lastError": op.LastError, "recoveryEvidenceDigest": op.RecoveryEvidenceDigest, "updatedAt": op.UpdatedAt}
		case "ai_run":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "ai_run requires exactly one id argument")
				return
			}
			run, err := s.store.GetAIRun(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "AI run not found")
				return
			}
			if _, err = s.requireProjectAccess(r, run.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = run
		case "operation_cancel":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			id, expectedRevision, reason, ok := mcpOperationCancelArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "operation_cancel requires id, positive integer expectedRevision and non-empty reason")
				return
			}
			op, err := s.store.GetOperation(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "operation not found")
				return
			}
			if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			updated, err := s.store.RequestOperationCancellation(r.Context(), id, expectedRevision, actor, reason)
			if errors.Is(err, controlplane.ErrConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "operation revision is stale")
				return
			}
			if errors.Is(err, controlplane.ErrInvalidTransition) || errors.Is(err, controlplane.ErrValidation) {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "operation cannot be cancelled in its current state")
				return
			}
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "request operation cancellation")
				return
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "operation": updated, "requestedBy": actor}

		case "drift_scan_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			projectID, ids, key, ok := mcpProjectClustersRequestArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "drift_scan_request requires projectId, unique clusterIds and idempotencyKey")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			priorScans, err := s.store.ListDriftScans(r.Context(), projectID, "")
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list prior drift scans")
				return
			}
			now := time.Now().UTC()
			targets := make([]controlplane.DriftScanTarget, 0, len(ids))
			for _, clusterID := range ids {
				cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
				if err != nil || cluster.ProjectID != projectID {
					writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found in project")
					return
				}
				deployment, err := s.latestSuccessfulBaseline(r, projectID, clusterID, baseline.SecureNamespaceID)
				if err != nil {
					writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "managed baseline is required before drift scan", map[string]any{"clusterId": clusterID})
					return
				}
				inventory, err := optionalClusterInventory(s.store, r.Context(), clusterID)
				if err != nil {
					writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "read cluster inventory")
					return
				}
				certs, err := s.store.ListAgentCertificates(r.Context(), clusterID)
				if err != nil {
					writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "read agent certificates")
					return
				}
				targets = append(targets, controlplane.DriftScanTarget{ClusterID: clusterID, BaselineDeploymentID: deployment.ID, BaselineID: deployment.BaselineID, BaselineVersion: deployment.BaselineVersion, DesiredDigest: deployment.DesiredDigest, Findings: controlplane.MergeDriftFindingHistory(clusterID, priorScans, healthDriftFindings(fleethealth.Evaluate(cluster, inventory, certs, now)), now)})
			}
			scan, replay, err := s.store.CreateDriftScan(r.Context(), controlplane.DriftScan{ProjectID: projectID, Targets: targets, IdempotencyKey: key, RequestDigest: jsonDigest(struct {
				ProjectID  string
				ClusterIDs []string
			}{projectID, ids})}, actor)
			if errors.Is(err, controlplane.ErrIdempotencyConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "drift scan idempotency key conflicts with different input")
				return
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "drift scan request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "family": "assurance", "risk": "low", "driftScan": scan, "idempotentReplay": replay, "requestedBy": actor}
		case "runtime_verification_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			projectID, clusterID, baselineDeploymentID, key, ok := mcpRuntimeVerificationRequestArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "runtime_verification_request requires projectId, clusterId, baselineDeploymentId and idempotencyKey")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			if !strings.Contains(s.runtimeProbeImage, "@sha256:") {
				writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "digest-pinned runtime probe image is unavailable")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil || cluster.ProjectID != projectID {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found in project")
				return
			}
			dep, err := s.store.GetBaselineDeployment(r.Context(), baselineDeploymentID)
			if err != nil || dep.ProjectID != projectID || dep.ClusterID != clusterID || dep.State != controlplane.BaselineDeploymentSucceeded {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "successful baseline deployment for the same project/cluster is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			input := createRuntimeVerificationInput{ProjectID: projectID, ClusterID: clusterID, BaselineDeploymentID: baselineDeploymentID}
			verification, replay, err := s.store.CreateRuntimeVerification(r.Context(), controlplane.RuntimeVerification{ProjectID: projectID, ClusterID: clusterID, BaselineDeploymentID: baselineDeploymentID, ProbeImage: s.runtimeProbeImage, RequestDigest: jsonDigest(input), IdempotencyKey: key}, actor)
			if errors.Is(err, controlplane.ErrIdempotencyConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "runtime verification idempotency key conflicts with different input")
				return
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "runtime verification request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "family": "assurance", "risk": "low", "verification": verification, "idempotentReplay": replay, "requestedBy": actor}
		case "upgrade_campaign_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			in, key, ok := mcpUpgradeCampaignRequestArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade_campaign_request requires project/fleet/target version, RFC3339 maintenance window, recovery checkpoints and idempotencyKey")
				return
			}
			if _, err := s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if in.BaselineID == "" {
				in.BaselineID = baseline.SecureNamespaceID
			}
			def, ok := baseline.GetVersion(in.BaselineID, in.TargetVersion)
			if !ok {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "target baseline version is unavailable")
				return
			}
			group, err := s.store.GetFleetGroup(r.Context(), in.FleetGroupID)
			if err != nil || group.ProjectID != in.ProjectID {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "fleet group not found in project")
				return
			}
			ids := append([]string(nil), group.ClusterIDs...)
			sort.Strings(ids)
			canary, waveSize, haltAfterFailures, err := controlplane.NormalizeDay2RolloutBounds(len(ids), in.CanaryCount, in.WaveSize, in.HaltAfterFailures)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "fleet group has no upgrade targets")
				return
			}
			in.CanaryCount, in.WaveSize, in.HaltAfterFailures = canary, waveSize, haltAfterFailures
			targets := make([]controlplane.UpgradeCampaignTarget, 0, len(ids))
			for i, clusterID := range ids {
				current, err := s.latestSuccessfulBaseline(r, in.ProjectID, clusterID, in.BaselineID)
				if err != nil {
					writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "managed baseline required before upgrade", map[string]any{"clusterId": clusterID})
					return
				}
				allowed := false
				for _, from := range def.UpgradeFrom {
					if from == current.BaselineVersion {
						allowed = true
						break
					}
				}
				if !allowed {
					writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "upgrade path unavailable", map[string]any{"clusterId": clusterID, "from": current.BaselineVersion, "to": def.Version})
					return
				}
				wave := 1
				if i >= canary {
					wave = 2 + (i-canary)/in.WaveSize
				}
				targets = append(targets, controlplane.UpgradeCampaignTarget{ClusterID: clusterID, Wave: wave, State: controlplane.UpgradeTargetPending, PreviousBaselineDeploymentID: current.ID, PreviousVersion: current.BaselineVersion, PreviousDigest: current.DesiredDigest})
			}
			campaign, replay, err := s.store.CreateUpgradeCampaign(r.Context(), controlplane.UpgradeCampaign{ProjectID: in.ProjectID, FleetGroupID: in.FleetGroupID, BaselineID: def.ID, TargetVersion: def.Version, CanaryCount: canary, WaveSize: in.WaveSize, HaltAfterFailures: in.HaltAfterFailures, Targets: targets, IdempotencyKey: key, RequestDigest: jsonDigest(in), MaintenanceWindowStart: in.MaintenanceWindowStart, MaintenanceWindowEnd: in.MaintenanceWindowEnd, RecoveryCheckpointIDs: append([]string(nil), in.RecoveryCheckpointIDs...)}, actor)
			if errors.Is(err, controlplane.ErrIdempotencyConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "upgrade campaign idempotency key conflicts with different input")
				return
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "upgrade campaign request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			if campaign.State != controlplane.UpgradeCampaignAwaitingApproval {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "high-impact upgrade request did not stop at independent approval")
				return
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "family": "fleet-upgrade", "risk": "high", "campaign": campaign, "idempotentReplay": replay, "approvalRequired": true, "requesterMayApprove": false, "requestedBy": actor}

		case "identity_admin_job_approve":
			id, expected, ok := mcpApprovalArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "identity_admin_job_approve requires id and positive expectedRevision")
				return
			}
			job, err := s.store.GetIdentityAdminJob(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "identity administration job not found")
				return
			}
			if err = s.requireOrganizationAccess(r, job.OrganizationID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization administration access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if strings.TrimSpace(job.RequestedBy) == actor {
				writeMCPError(w, req.ID, http.StatusForbidden, -32011, "separation of duties requires a different approver")
				return
			}
			job, err = s.store.ApproveIdentityAdminJob(r.Context(), id, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "identity administration approval was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.IdentityAdminJobAuthority, "job": job, "approvedBy": actor, "requesterMayApprove": false}

		case "cluster_maintenance_approve":
			id, expected, ok := mcpApprovalArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "cluster_maintenance_approve requires id and positive expectedRevision")
				return
			}
			run, err := s.store.GetClusterMaintenanceRun(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "cluster maintenance request not found")
				return
			}
			if _, err = s.requireProjectAccess(r, run.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if strings.TrimSpace(run.RequestedBy) == actor {
				writeMCPError(w, req.ID, http.StatusForbidden, -32011, "separation of duties requires a different approver")
				return
			}
			run, err = s.store.ApproveClusterMaintenanceRun(r.Context(), id, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "cluster maintenance approval was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			op, err := s.store.GetOperation(r.Context(), run.OperationID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "load approved maintenance operation")
				return
			}
			value = map[string]any{"authority": controlplane.ClusterMaintenanceAuthorityMethod, "run": run, "operation": op, "approvedBy": actor, "requesterMayApprove": false}

		case "upgrade_campaign_approve":
			id, expected, ok := mcpApprovalArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade_campaign_approve requires id and positive expectedRevision")
				return
			}
			campaign, err := s.store.GetUpgradeCampaign(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "upgrade campaign not found")
				return
			}
			if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if strings.TrimSpace(campaign.RequestedBy) == actor {
				writeMCPError(w, req.ID, http.StatusForbidden, -32011, "separation of duties requires a different approver")
				return
			}
			campaign, err = s.store.ApproveUpgradeCampaign(r.Context(), id, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "upgrade campaign approval was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "FLEET_UPGRADE_CAMPAIGN_AUTHORITY_V1", "campaign": campaign, "approvedBy": actor, "requesterMayApprove": false}

		case "managed_okd_install_runtime":
			configured := s.managedOKDInstallExecutor != nil
			disconnectedConfigured := configured && s.managedOKDInstallExecutor.DisconnectedInstaller != nil
			value = map[string]any{"authority": managedinstall.ExecutorAuthority, "configured": configured, "requestCreationAllowed": configured, "connectedRequestAllowed": configured, "disconnectedRequestAllowed": disconnectedConfigured, "requiresExactWorkspace": true, "requiresIndependentApproval": true, "physicalCertificationImplied": false}

		case "managed_okd_install":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "managed_okd_install requires id")
				return
			}
			op, err := s.store.GetOperation(r.Context(), id)
			if err != nil || op.Kind != managedOKDInstallOperationKind {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed OKD install not found")
				return
			}
			if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
			if err != nil || sealed.MediaType != managedinstall.PayloadMediaType {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "managed OKD install request payload is unavailable")
				return
			}
			installReq, err := managedinstall.ParseCanonicalRequest(sealed.Payload, op.DesiredRevision)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "managed OKD install request integrity failed")
				return
			}
			value = map[string]any{"authority": managedinstall.Authority, "install": redactedManagedOKDInstallView(op, installReq), "credentialReferencesExposed": false}

		case "managed_okd_install_request":
			if s.managedOKDInstallExecutor == nil {
				writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32012, "managed OKD production runtime is not configured")
				return
			}
			args, ok := mcpManagedOKDInstallArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "managed_okd_install_request requires an exact Compact-3 request and idempotencyKey")
				return
			}
			installReq, err := managedinstall.CanonicalRequest(args.request())
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusBadRequest, -32602, "managed OKD install request is invalid", map[string]any{"detail": err.Error()})
				return
			}
			if managedinstall.IsDisconnected(installReq) && s.managedOKDInstallExecutor.DisconnectedInstaller == nil {
				writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32012, "disconnected OKD runtime requires exact oc-mirror v2 and managed mirror registry configuration")
				return
			}
			project, err := s.requireProjectAccess(r, installReq.ProjectID, organizationWrite)
			if err != nil || project.OrganizationID != installReq.OrganizationID {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required in the requested organization")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			payload, desired, err := managedinstall.MarshalCanonicalRequest(installReq)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "managed OKD install request cannot be sealed")
				return
			}
			op, replay, err := s.store.CreateOperationAwaitingApprovalWithPayload(r.Context(), controlplane.OperationRequest{ProjectID: installReq.ProjectID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/" + installReq.ClusterName, DesiredRevision: desired, Risk: "critical", Class: controlplane.OperationClassMutating}, args.IdempotencyKey, actor, r.Header.Get("X-Request-ID"), managedinstall.PayloadMediaType, payload)
			if errors.Is(err, controlplane.ErrIdempotencyConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "managed OKD install idempotency key conflicts with different input")
				return
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "managed OKD install request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			if op.State != controlplane.OperationAwaitingApproval {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "managed OKD install did not stop at independent approval")
				return
			}
			value = map[string]any{"authority": managedinstall.Authority, "install": redactedManagedOKDInstallView(op, installReq), "idempotentReplay": replay, "approvalRequired": true, "requesterMayApprove": false, "credentialReferencesExposed": false}

		case "managed_okd_install_approve":
			id, expected, ok := mcpApprovalArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "managed_okd_install_approve requires id and positive expectedRevision")
				return
			}
			op, err := s.store.GetOperation(r.Context(), id)
			if err != nil || op.Kind != managedOKDInstallOperationKind {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed OKD install not found")
				return
			}
			if _, err = s.requireProjectAccess(r, op.ProjectID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project administration access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if strings.TrimSpace(op.ActorID) == actor {
				writeMCPError(w, req.ID, http.StatusForbidden, -32011, "separation of duties requires a different approver")
				return
			}
			op, err = s.store.ApproveOperationAndQueue(r.Context(), op.ID, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "managed OKD install approval was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": managedinstall.Authority, "operation": op, "approvedBy": actor, "requesterMayApprove": false}

		case "support_bundle_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			args, ok := mcpSupportBundleArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "support_bundle_request requires one profile-specific target and idempotencyKey")
				return
			}
			input := supportBundleRequest{Profile: args.Profile, ProjectID: args.ProjectID, ClusterID: args.ClusterID, OperationID: args.OperationID}
			projectID, err := s.authorizeSupportBundleRequest(r, input)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "support bundle target is not accessible")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			target, err := supportBundleTarget(input)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "invalid support bundle target")
				return
			}
			op, replay, err := s.store.CreateOperation(r.Context(), controlplane.OperationRequest{ProjectID: projectID, Kind: supportBundleOperationKind, TargetRef: target, DesiredRevision: supportBundleRequestDigest(input), Risk: "low", Class: controlplane.OperationClassReadOnly}, args.IdempotencyKey, actor, r.Header.Get("X-Request-ID"))
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "create support bundle operation")
				return
			}
			if !replay && op.State == controlplane.OperationDraft {
				op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationPlanning, "", actor)
				if err == nil {
					op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationQueued, "", actor)
				}
				if err != nil {
					writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "queue support bundle operation")
					return
				}
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "operation": op, "replay": replay, "statusTool": "operation_status"}
		case "backup_policies":
			projectID, clusterID, ok := mcpProjectClusterArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "backup_policies requires projectId and optional clusterId")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			policies, err := s.store.ListBackupPolicies(r.Context(), projectID, clusterID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list backup policies")
				return
			}
			items := make([]map[string]any, 0, len(policies))
			for _, policy := range policies {
				items = append(items, map[string]any{"id": policy.ID, "revision": policy.Revision, "projectId": policy.ProjectID, "clusterId": policy.ClusterID, "name": policy.Name, "provider": policy.Provider, "schedule": policy.Schedule, "retention": policy.Retention, "state": policy.State, "desiredDigest": policy.DesiredDigest, "includedNamespaces": policy.IncludedNamespaces})
			}
			value = map[string]any{"authority": "TARGET_DATA_PROTECTION_AUTHORITY_V1", "projectId": projectID, "clusterId": clusterID, "items": items, "credentialValuesExposed": false}

		case "data_protection_runs":
			projectID, clusterID, ok := mcpProjectClusterArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "data_protection_runs requires projectId and optional clusterId")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			runs, err := s.store.ListDataProtectionRuns(r.Context(), projectID, clusterID, "")
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list data protection runs")
				return
			}
			if len(runs) > 100 {
				runs = runs[len(runs)-100:]
			}
			value = map[string]any{"authority": "TARGET_DATA_PROTECTION_AUTHORITY_V1", "projectId": projectID, "clusterId": clusterID, "items": runs, "bounded": true, "limit": 100}

		case "backup_run_request", "restore_run_request", "restore_drill_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				return
			}
			requireBackup := req.Params.Name != "backup_run_request"
			in, ok := mcpDataProtectionRunArguments(req.Params.Arguments, requireBackup)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "data protection request requires projectId, clusterId, policyId, idempotencyKey and backupRunId for restore/drill")
				return
			}
			if _, err := s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			kind := controlplane.DataProtectionBackup
			if req.Params.Name == "restore_run_request" {
				kind = controlplane.DataProtectionRestore
			} else if req.Params.Name == "restore_drill_request" {
				kind = controlplane.DataProtectionRestoreDrill
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			requestDigest := digestValue(map[string]any{"authority": "TARGET_DATA_PROTECTION_AUTHORITY_V1", "kind": kind, "projectId": in.ProjectID, "clusterId": in.ClusterID, "policyId": in.PolicyID, "backupRunId": in.BackupRunID, "idempotencyKey": in.IdempotencyKey})
			run, replay, err := s.store.CreateDataProtectionRun(r.Context(), controlplane.DataProtectionRun{Kind: kind, ProjectID: in.ProjectID, ClusterID: in.ClusterID, PolicyID: in.PolicyID, BackupRunID: in.BackupRunID, IdempotencyKey: in.IdempotencyKey, RequestDigest: requestDigest}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "data protection request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "TARGET_DATA_PROTECTION_AUTHORITY_V1", "run": run, "idempotentReplay": replay, "requestedBy": actor, "approvalRequired": run.State == controlplane.DataProtectionAwaitingApproval, "requesterMayApprove": false}

		case "restore_run_approve":
			id, expected, ok := mcpApprovalArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "restore_run_approve requires id and positive expectedRevision")
				return
			}
			run, err := s.store.GetDataProtectionRun(r.Context(), id)
			if err != nil || run.Kind != controlplane.DataProtectionRestore {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "restore run not found")
				return
			}
			if _, err = s.requireProjectAccess(r, run.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			if strings.TrimSpace(run.RequestedBy) == actor {
				writeMCPError(w, req.ID, http.StatusForbidden, -32011, "separation of duties requires a different approver")
				return
			}
			run, err = s.store.ApproveDataProtectionRun(r.Context(), id, expected, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "restore approval was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "TARGET_DATA_PROTECTION_AUTHORITY_V1", "run": run, "approvedBy": actor, "requesterMayApprove": false}

		case "compliance_scan_request":
			projectID, clusterID, profileID, key, ok := mcpComplianceScanArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "compliance_scan_request requires projectId, clusterId, profileId and idempotencyKey")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil || cluster.ProjectID != projectID {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found in project")
				return
			}
			profile, err := s.store.GetComplianceProfile(r.Context(), profileID)
			if err != nil || profile.ProjectID != projectID {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "compliance profile not found in project")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			digest := complianceRequestDigest(map[string]any{"projectId": projectID, "clusterId": clusterID, "profileId": profileID, "inventoryDigest": cluster.InventoryDigest})
			scan, replay, err := s.store.CreateComplianceScanRun(r.Context(), controlplane.ComplianceScanRun{ProjectID: projectID, ClusterID: clusterID, ProfileID: profileID, IdempotencyKey: key, RequestDigest: digest}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "compliance scan request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.ComplianceScanCenterAuthority, "scan": scan, "idempotentReplay": replay, "requestedBy": actor, "rawManifestExposed": false}

		case "compliance_recheck_request":
			projectID, runID, fingerprint, key, ok := mcpComplianceRecheckArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "compliance_recheck_request requires projectId, runId, fingerprint and idempotencyKey")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			prior, err := s.store.GetComplianceScanRun(r.Context(), runID)
			if err != nil || prior.ProjectID != projectID {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "compliance scan not found in project")
				return
			}
			findings, err := s.store.ListComplianceFindings(r.Context(), projectID, runID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "read compliance findings")
				return
			}
			matched := false
			for _, finding := range findings {
				if finding.Fingerprint == fingerprint {
					matched = true
					break
				}
			}
			if !matched {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "compliance finding not found in scan")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			digest := complianceRequestDigest(map[string]any{"recheckRunId": runID, "fingerprint": fingerprint, "profileId": prior.ProfileID, "clusterId": prior.ClusterID})
			scan, replay, err := s.store.CreateComplianceScanRun(r.Context(), controlplane.ComplianceScanRun{ProjectID: prior.ProjectID, ClusterID: prior.ClusterID, ProfileID: prior.ProfileID, IdempotencyKey: key, RequestDigest: digest}, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "compliance recheck was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": controlplane.ComplianceScanCenterAuthority, "scan": scan, "idempotentReplay": replay, "recheckOf": map[string]any{"runId": runID, "fingerprint": fingerprint}, "rawManifestExposed": false}

		case "upgrade_campaigns":
			projectID, ok := mcpExactProjectArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade_campaigns requires exactly projectId")
				return
			}
			if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			campaigns, err := s.store.ListUpgradeCampaigns(r.Context(), projectID, "")
			if err != nil {
				writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "list upgrade campaigns")
				return
			}
			if len(campaigns) > 100 {
				campaigns = campaigns[len(campaigns)-100:]
			}
			value = map[string]any{"authority": "FLEET_UPGRADE_CAMPAIGN_AUTHORITY_V1", "projectId": projectID, "items": campaigns, "bounded": true, "limit": 100}

		case "upgrade_campaign":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade_campaign requires exactly id")
				return
			}
			campaign, err := s.store.GetUpgradeCampaign(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "upgrade campaign not found")
				return
			}
			if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationRead); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project read access is required")
				return
			}
			value = campaign

		case "upgrade_campaign_pause", "upgrade_campaign_resume", "upgrade_campaign_cancel":
			reasonRequired := req.Params.Name == "upgrade_campaign_cancel"
			id, expected, reason, ok := mcpUpgradeControlArguments(req.Params.Arguments, reasonRequired)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade campaign control requires id, expectedRevision and a reason when cancelling")
				return
			}
			campaign, err := s.store.GetUpgradeCampaign(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "upgrade campaign not found")
				return
			}
			if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			switch req.Params.Name {
			case "upgrade_campaign_pause":
				campaign, err = s.store.PauseUpgradeCampaign(r.Context(), id, expected, actor, reason)
			case "upgrade_campaign_resume":
				campaign, err = s.store.ResumeUpgradeCampaign(r.Context(), id, expected, actor)
			case "upgrade_campaign_cancel":
				campaign, err = s.store.CancelUpgradeCampaign(r.Context(), id, expected, actor, reason)
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "upgrade campaign control was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "FLEET_UPGRADE_CAMPAIGN_AUTHORITY_V1", "campaign": campaign, "actor": actor}

		case "upgrade_campaign_revalidate":
			id, expected, revalidation, ok := mcpUpgradeRevalidateArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "upgrade_campaign_revalidate requires id, expectedRevision and valid optional recovery/window fields")
				return
			}
			campaign, err := s.store.GetUpgradeCampaign(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "upgrade campaign not found")
				return
			}
			if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			campaign, err = s.store.RevalidateUpgradeCampaign(r.Context(), id, expected, revalidation, actor)
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "upgrade campaign revalidation was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			value = map[string]any{"authority": "FLEET_UPGRADE_CAMPAIGN_AUTHORITY_V1", "campaign": campaign, "actor": actor}

		case "identity_admin_job":
			id, ok := mcpExactIDArgument(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "identity_admin_job requires exactly one id argument")
				return
			}
			job, err := s.store.GetIdentityAdminJob(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "identity administration job not found")
				return
			}
			if err = s.requireOrganizationAccess(r, job.OrganizationID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization administration access is required")
				return
			}
			value = job

		case "saml_broker_change_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				return
			}
			brokerInput, expectedRevision, key, ok := mcpSAMLBrokerChangeArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "saml_broker_change_request requires a valid organization-scoped SAML broker, idempotencyKey, and expectedRevision for updates")
				return
			}
			if err := s.requireOrganizationAccess(r, brokerInput.OrganizationID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization administration access is required")
				return
			}
			if brokerInput.ID != "" {
				current, err := s.store.GetSAMLBroker(r.Context(), brokerInput.ID)
				if err != nil || current.OrganizationID != brokerInput.OrganizationID {
					writeMCPError(w, req.ID, http.StatusNotFound, -32602, "SAML broker not found in organization")
					return
				}
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			requestDigest := jsonDigest(map[string]any{"authority": controlplane.KeycloakSAMLBrokerAuthority, "action": "UPSERT_SAML", "expectedRevision": expectedRevision, "broker": brokerInput})
			broker, job, replay, err := s.store.RequestSAMLBrokerUpsert(r.Context(), brokerInput, expectedRevision, key, requestDigest, actor)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "SAML broker change request was not admitted")
				return
			}
			if job.State != controlplane.IdentityAdminAwaitingApproval {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "identity administration request did not stop at independent approval")
				return
			}
			value = map[string]any{"authority": controlplane.IdentityAdminJobAuthority, "brokerAuthority": controlplane.KeycloakSAMLBrokerAuthority, "broker": broker, "job": job, "idempotentReplay": replay, "approvalRequired": true, "requesterMayApprove": false, "requestedBy": actor}

		case "saml_broker_delete_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				return
			}
			id, expectedRevision, key, ok := mcpSAMLBrokerDeleteArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "saml_broker_delete_request requires id, positive expectedRevision and idempotencyKey")
				return
			}
			current, err := s.store.GetSAMLBroker(r.Context(), id)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "SAML broker not found")
				return
			}
			if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "organization administration access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			requestDigest := jsonDigest(map[string]any{"authority": controlplane.KeycloakSAMLBrokerAuthority, "action": "DELETE_SAML", "brokerId": current.ID, "expectedRevision": expectedRevision, "desiredDigest": current.DesiredDigest})
			broker, job, replay, err := s.store.RequestSAMLBrokerDelete(r.Context(), current.ID, expectedRevision, key, requestDigest, actor)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "SAML broker deletion request was not admitted")
				return
			}
			if job.State != controlplane.IdentityAdminAwaitingApproval {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "identity administration deletion did not stop at independent approval")
				return
			}
			value = map[string]any{"authority": controlplane.IdentityAdminJobAuthority, "brokerAuthority": controlplane.KeycloakSAMLBrokerAuthority, "broker": broker, "job": job, "idempotentReplay": replay, "approvalRequired": true, "requesterMayApprove": false, "requestedBy": actor}

		case "cluster_maintenance_request":
			if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionMCPOperate, false); err != nil {
				if errors.Is(err, errCapabilityAccessDenied) {
					writeMCPError(w, req.ID, http.StatusForbidden, -32001, "mcp.operate capability permission is required")
				} else {
					writeMCPError(w, req.ID, http.StatusServiceUnavailable, -32002, "MCP authorization audit unavailable")
				}
				return
			}
			clusterID, windowID, action, nodeNames, key, ok := mcpMaintenanceRequestArguments(req.Params.Arguments)
			if !ok {
				writeMCPError(w, req.ID, http.StatusBadRequest, -32602, "cluster_maintenance_request requires clusterId, windowId, unique nodeNames and idempotencyKey")
				return
			}
			cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusNotFound, -32602, "managed cluster not found")
				return
			}
			if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
				writeMCPError(w, req.ID, http.StatusForbidden, -32003, "project write access is required")
				return
			}
			actor, err := actorID(r)
			if err != nil {
				writeMCPError(w, req.ID, http.StatusUnauthorized, -32004, "authenticated actor is required")
				return
			}
			request := maintenanceRunInput{WindowID: windowID, Action: action, NodeNames: nodeNames}
			requestDigest := digestValue(request)
			opRequest := controlplane.OperationRequest{ProjectID: cluster.ProjectID, Kind: "CLUSTER_MAINTENANCE", TargetRef: "cluster/" + cluster.ID, DesiredRevision: requestDigest, Risk: "high", Class: controlplane.OperationClassMutating}
			run, op, replay, err := s.store.CreateClusterMaintenanceRunRequest(r.Context(), controlplane.ClusterMaintenanceRun{ProjectID: cluster.ProjectID, ClusterID: cluster.ID, WindowID: windowID, Action: action, NodeNames: nodeNames, IdempotencyKey: key, RequestDigest: requestDigest}, opRequest, "cluster-maintenance-operation:"+key, actor, "mcp:"+key)
			if errors.Is(err, controlplane.ErrIdempotencyConflict) {
				writeMCPError(w, req.ID, http.StatusConflict, -32009, "maintenance idempotency key conflicts with different input")
				return
			}
			if err != nil {
				writeMCPErrorData(w, req.ID, http.StatusConflict, -32010, "cluster maintenance request was not admitted", map[string]any{"detail": err.Error()})
				return
			}
			if op.State != controlplane.OperationAwaitingApproval || run.State != controlplane.ClusterMaintenanceAwaitingApproval {
				writeMCPError(w, req.ID, http.StatusConflict, -32010, "high-impact maintenance request did not stop at independent approval")
				return
			}
			value = map[string]any{"authority": "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "maintenanceAuthority": controlplane.ClusterMaintenanceAuthorityMethod, "run": run, "operation": op, "idempotentReplay": replay, "approvalRequired": true, "requesterMayApprove": false, "requestedBy": actor}
		default:
			writeMCPError(w, req.ID, http.StatusNotFound, -32602, fmt.Sprintf("unknown tool %q", req.Params.Name))
			return
		}
		raw, err := json.Marshal(value)
		if err != nil {
			writeMCPError(w, req.ID, http.StatusInternalServerError, -32603, "encode tool result")
			return
		}
		s.writeMCPResult(w, req.ID, map[string]any{
			"content":           []map[string]string{{"type": "text", "text": string(raw)}},
			"structuredContent": value,
			"isError":           false,
		})
	default:
		writeMCPError(w, req.ID, http.StatusNotFound, -32601, "method not found")
	}
}
