package migrations

import (
	"regexp"
	"strings"
	"testing"
)

func TestPostgresAuthorityMigrationContract(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no embedded migrations")
	}
	var builder strings.Builder
	for _, migration := range all {
		builder.WriteString(migration.SQL)
		builder.WriteByte('\n')
	}
	combined := builder.String()
	required := []string{
		"CREATE TABLE organizations", "CREATE TABLE projects", "CREATE TABLE blueprint_revisions",
		"CREATE TABLE assignments", "CREATE TABLE operations", "CREATE TABLE operation_steps",
		"CREATE TABLE outbox_events", "CREATE TABLE audit_events", "CREATE TABLE evidence_metadata",
		"operations_idempotency_key", "fence_token", "audit_events_no_update",
		"blueprint_revisions_immutable", "evidence_metadata_immutable",
		"validate_revision_increment", "validate_operation_update",
		"audit_events_no_truncate", "outbox_published_not_claimed",
		"CREATE TABLE cluster_imports", "CREATE TABLE managed_clusters", "CREATE TABLE cluster_inventory_snapshots",
		"CREATE TABLE baseline_deployments", "baseline_deployments_project_idempotency_key",
		"CREATE TABLE runtime_verifications", "runtime_verifications_project_idempotency",
		"CREATE TABLE fleet_groups", "CREATE TABLE drift_scans", "CREATE TABLE upgrade_campaigns",
		"CREATE TABLE IF NOT EXISTS entitlements", "CREATE TABLE IF NOT EXISTS oem_profiles", "CREATE TABLE IF NOT EXISTS tenant_environments",
		"CREATE TABLE IF NOT EXISTS provider_profiles", "CREATE TABLE IF NOT EXISTS provider_clusters", "cluster-api-topology-v1beta2",
		"CREATE TABLE marketplace_recommendations", "marketplace_recommendations_project_idempotency", "pending_action", "source_type",
		"CREATE TABLE runtime_closure_campaigns", "runtime_closure_project_idempotency", "validate_runtime_closure_campaign_update",
		"CREATE TABLE organization_memberships", "organization_membership_subject_unique", "organization_memberships_subject_state_idx",
		"CREATE TABLE service_accounts", "CREATE TABLE api_tokens", "service_accounts_scope_name_unique", "api_tokens_service_account_state_idx",
		"CREATE TABLE agent_certificates", "serial_number text NOT NULL UNIQUE", "agent_certificates_cluster_state_idx",
		"ADD COLUMN storage_classes jsonb", "ADD COLUMN capacity jsonb", "ADD COLUMN certificates jsonb", "ADD COLUMN networking jsonb",
		"CREATE TABLE blueprint_releases", "blueprint_releases_project_name_version_unique", "validate_blueprint_release_update", "published blueprint release content is immutable",
		"CREATE TABLE catalog_trust_keys", "CREATE TABLE catalog_revisions", "CREATE TABLE catalog_releases", "catalog_revisions_reject_update", "validate_catalog_release_update", "ADD COLUMN catalog_release_id", "catalog binding are immutable",
		"CREATE TABLE recovery_checkpoints", "recovery_checkpoints_active_evidence_idx", "ADD COLUMN maintenance_window_start", "ADD COLUMN plan_context_digest", "baseline_deployments_plan_expiry_idx", "upgrade_campaigns_plan_expiry_idx",
		"CREATE TABLE runtime_certification_runs", "runtime_certification_project_idempotency", "runtime_certification_success_shape",
		"PAUSE_REQUESTED", "CANCEL_REQUESTED", "paused_by", "cancel_requested_by", "upgrade_campaigns_control_state_idx",
		"CREATE TABLE notification_destinations", "CREATE TABLE notification_routes", "CREATE TABLE notification_events", "CREATE TABLE notification_deliveries", "CREATE TABLE notification_delivery_attempts", "notification_event_source_uq", "notification_delivery_route_destination_uq",
		"CREATE TABLE blueprint_overlays", "blueprint_overlay_identity_unique", "blueprint_overlays_immutable", "ADD COLUMN base_blueprint_digest", "ADD COLUMN overlay_digest", "ADD COLUMN ownership_digest", "blueprint_revision_resolution_unique", "validate_blueprint_revision_overlay_scope", "blueprint_revisions_overlay_scope_guard",
		"ADD COLUMN api_resources jsonb", "ADD COLUMN crds jsonb", "api_discovery_complete boolean", "ADD COLUMN plan_impact jsonb", "ADD COLUMN plan_impact_digest text", "baseline_deployments_plan_impact_digest_check",
		"operation_class text", "retry_policy jsonb", "next_attempt_at timestamptz", "recovery_checkpoint_id text", "CANCEL_REQUESTED", "operation_steps_operation_attempt_key",
		"CREATE TABLE IF NOT EXISTS managed_git_revisions", "managed_git_revisions_repo_idx",
		"OBSERVABILITY_V1", "runtime_certification_runs_profile_check",
		"schema_discovery_version", "schema_discovery_digest", "cluster_inventory_schema_discovery_consistency_check",
		"destructive_operation_id", "idx_baseline_deployments_destructive_operation", "idx_tenant_environments_destructive_operation", "idx_provider_clusters_destructive_operation",
		"ADD COLUMN IF NOT EXISTS evidence jsonb", "evidence_digest", "idx_baseline_deployments_evidence_digest",
		"CREATE TABLE IF NOT EXISTS operation_compensation_steps", "compensation_plan_digest", "ROLLBACK_FAILED", "NEEDS_OPERATOR", "operation_compensation_steps_next_idx",
		"CREATE TABLE IF NOT EXISTS operation_step_traces", "CREATE TABLE IF NOT EXISTS operation_evidence_payloads", "operation_step_trace_idempotency", "operation_step_trace_sequence",
		"CREATE TABLE IF NOT EXISTS git_credentials", "CREATE TABLE IF NOT EXISTS git_providers", "git_credentials_active_name_idx", "git_providers_single_default_idx",
		"CREATE TABLE IF NOT EXISTS git_pull_requests", "git_pull_requests_repo_state_idx", "delivery_mode text", "managed_git_revisions_single_lkg_idx",
		"pending_plan_name text", "pending_quota jsonb", "pending_desired_digest text", "recovery_checkpoint_id text", "approved_by text", "RESIZE_AWAITING_APPROVAL", "DELETE_AWAITING_APPROVAL", "idx_tenant_environments_approval_state",
		"CREATE TABLE IF NOT EXISTS cluster_maintenance_profiles", "CREATE TABLE IF NOT EXISTS cluster_maintenance_windows", "CREATE TABLE IF NOT EXISTS cluster_maintenance_runs", "DEVELOPMENT", "STAGING", "PRODUCTION", "max_unavailable = 1", "AWAITING_APPROVAL", "NEEDS_OPERATOR", "idx_cluster_maintenance_runs_claim",
		"CREATE TABLE IF NOT EXISTS oidc_group_mappings", "oidc_group_mappings_active_identity_idx", "CREATE TABLE IF NOT EXISTS security_audit_events", "IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1", "security_audit_events_no_update", "security_audit_events_no_truncate", "security_audit_events_request_idx",
		"storage_policy jsonb", "backup_policy jsonb", "security_policy jsonb", "evidence_sealed_at", "idx_tenant_environments_evidence_digest",
		"ADD COLUMN IF NOT EXISTS architectures jsonb", "ADD COLUMN IF NOT EXISTS distribution_profiles jsonb", "ADD COLUMN IF NOT EXISTS compatibility_decision jsonb", "idx_provider_profiles_compatibility", "idx_provider_clusters_compatibility_status",
		"task_fence_token bigint", "task_lease_expires_at timestamptz", "tenant_agent_task_lease_idx", "provider_profile_agent_task_lease_idx", "provider_cluster_agent_task_lease_idx",
		"baseline_agent_task_lease_idx", "runtime_verification_agent_task_lease_idx", "runtime_certification_agent_task_lease_idx",
		"runtime_contract_version", "idx_tenant_runtime_contract_reconcile",
		"ADD COLUMN IF NOT EXISTS node_uids jsonb", "Immutable node-name to Kubernetes UID identity",
		"cleanup_generations jsonb", "Persist attempt-scoped cleanup ownership",
		"CREATE TABLE IF NOT EXISTS notification_health_scan_leases", "notification_health_scan_leases_until_idx",
		"TARGET_ARCHITECTURE_MODEL_V1", "ALTER COLUMN distribution_profiles SET DEFAULT",
		"DROP CONSTRAINT IF EXISTS managed_clusters_external_uid_key", "managed_clusters_active_external_uid_key", "WHERE connection_state <> 'REVOKED'",
		"ADD COLUMN IF NOT EXISTS agent_service_account text NOT NULL DEFAULT ''",
		"mutation_rbac_basis_digest text NOT NULL DEFAULT ''", "mutation_rbac_issued_for_digest text NOT NULL DEFAULT ''",
		"target_rbac_revocation_ack_digest text NOT NULL DEFAULT ''", "cluster.mutation_rbac_activation.authorized", "target-mutation-rbac-ever-issued",
		"target-read-only-admission", "target_rbac_revocation_acknowledged_at IS NULL", "successor.created_at <= predecessor.target_rbac_revocation_acknowledged_at",
		"CREATE TABLE IF NOT EXISTS ai_runs", "ai_runs_project_idempotency", "advisory_only boolean",
		"CREATE TABLE IF NOT EXISTS ai_execution_claims", "ai_execution_claim_project_idempotency", "DISPATCHED",
		"CREATE TABLE IF NOT EXISTS variable_schemas", "variable_schema_identity_unique", "variable_schemas_immutable",
		"CREATE TABLE IF NOT EXISTS platform_policy_sets", "platform_policy_set_identity_unique", "platform_policy_sets_immutable",
		"CREATE TABLE IF NOT EXISTS platform_templates", "platform_template_identity_unique", "validate_platform_template_binding", "platform_templates_binding_guard", "platform_templates_immutable",
		"CREATE TABLE IF NOT EXISTS workspaces", "workspace_identity_unique", "workspaces_immutable",
		"CREATE TABLE IF NOT EXISTS workspace_bindings", "workspace_bindings_active_scope_unique", "validate_workspace_binding_authority", "workspace_bindings_authority_guard",
		"component_name text NOT NULL DEFAULT ''", "component_release text NOT NULL DEFAULT ''", "COMPONENT_RUNTIME_V1", "runtime_certification_component_identity_check",
		"CREATE TABLE operation_request_payloads", "operation_request_payloads_no_update", "operation request payloads are immutable",
	}
	for _, term := range required {
		if !strings.Contains(combined, term) {
			t.Fatalf("migration missing %q", term)
		}
	}
	for i, migration := range all {
		if migration.Version != int64(i+1) {
			t.Fatalf("unexpected migration version at %d: %#v", i, all)
		}
	}
	for _, migration := range all {
		if !strings.HasPrefix(migration.Checksum, "sha256:") {
			t.Fatalf("bad checksum %s", migration.Checksum)
		}
	}
}

func TestInitialOrganizationNameUniquenessUsesValidExpressionIndex(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("missing initial migration")
	}
	sql := all[0].SQL
	if strings.Contains(sql, "CONSTRAINT organizations_name_key UNIQUE (lower(name))") {
		t.Fatal("PostgreSQL does not allow expression keys in UNIQUE table constraints")
	}
	if !strings.Contains(sql, "CREATE UNIQUE INDEX organizations_name_key ON organizations(lower(name));") {
		t.Fatal("initial migration must enforce case-insensitive organization names with an expression index")
	}
}

func TestNoMigrationUsesExpressionsInsideUniqueTableConstraints(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	invalid := regexp.MustCompile(`(?i)\bUNIQUE\s*\([^\n;]*\blower\s*\(`)
	for _, migration := range all {
		if invalid.MatchString(migration.SQL) {
			t.Fatalf("migration %d uses an expression inside a UNIQUE table constraint; use a unique expression index", migration.Version)
		}
	}
}

func TestMigrationMixedVersionCompatibilityIsExplicit(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	unsafe := map[int64]bool{}
	for _, migration := range all {
		switch migration.Compatibility {
		case CompatibilityRollingSafe:
			if migration.CompatibilityReason == "" {
				t.Fatalf("migration %d rolling classification has no reason", migration.Version)
			}
		case CompatibilityQuiescedRequired:
			if migration.CompatibilityReason == "" {
				t.Fatalf("migration %d quiesced classification has no reason", migration.Version)
			}
			unsafe[migration.Version] = true
		default:
			t.Fatalf("migration %d has invalid compatibility class %q", migration.Version, migration.Compatibility)
		}
	}
	for _, version := range []int64{21, 27, 47, 50, 60, 61, 64} {
		if !unsafe[version] {
			t.Fatalf("migration %d mixed-version hazard was not classified as quiesced-required", version)
		}
	}
	if _, _, err := compatibilityForVersion(int64(len(all) + 1)); err == nil {
		t.Fatal("future migration without explicit compatibility review was accepted")
	}
}

func TestTargetRBACReadOnlyUpgradeParityMigrationIsNarrowAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 51 {
		t.Fatalf("expected migration 51, got %d migrations", len(all))
	}
	m := all[50]
	if m.Version != 51 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 51 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{
		`successor.inventory_digest <> ''`,
		`target-read-only-admission`,
		`NOT (successor.capabilities @> '["target-mutation-rbac-active"]'::jsonb)`,
		`NOT (successor.capabilities @> '["target-mutation-rbac-activation-issued"]'::jsonb)`,
		`predecessor.target_rbac_revocation_acknowledged_at IS NULL`,
		`successor.created_at <= predecessor.target_rbac_revocation_acknowledged_at`,
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 51 missing narrow parity guard %q", term)
		}
	}
}

func TestInventoryObservationEpochMigrationIsNullableAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 52 {
		t.Fatalf("expected migration 52, got %d migrations", len(all))
	}
	m := all[51]
	if m.Version != 52 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 52 compatibility mismatch: %#v", m)
	}
	if !strings.Contains(m.SQL, "inventory_observed_at timestamptz") {
		t.Fatal("migration 52 does not add target observation epoch authority")
	}
	if strings.Contains(strings.ToUpper(m.SQL), "NOT NULL") || strings.Contains(strings.ToUpper(m.SQL), "DEFAULT") {
		t.Fatal("migration 52 must remain nullable/default-free for rolling compatibility")
	}
}

func TestAIRunAuthorityMigrationIsAdditiveAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 53 {
		t.Fatalf("expected migration 53, got %d migrations", len(all))
	}
	m := all[52]
	if m.Version != 53 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 53 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{"CREATE TABLE IF NOT EXISTS ai_runs", "output jsonb NOT NULL", "advisory_only boolean NOT NULL DEFAULT true", "ai_runs_project_idempotency"} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 53 missing %q", term)
		}
	}
}

func TestAIExecutionDispatchMigrationIsAdditiveAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 54 {
		t.Fatalf("expected migration 54, got %d migrations", len(all))
	}
	m := all[53]
	if m.Version != 54 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 54 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{"CREATE TABLE IF NOT EXISTS ai_execution_claims", "ai_execution_claim_project_idempotency", "ai_execution_claim_terminal_shape", "DISPATCHED", "COMPLETED", "FAILED"} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 54 missing %q", term)
		}
	}
}

func TestWorkspaceAuthorityMigrationIsProjectScopedAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 58 {
		t.Fatalf("expected migration 58, got %d migrations", len(all))
	}
	m := all[57]
	if m.Version != 58 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 58 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{
		"CREATE TABLE IF NOT EXISTS workspaces",
		"project_id text NOT NULL REFERENCES projects(id)",
		"workspace_identity_unique",
		"workspaces_immutable",
		"CREATE TABLE IF NOT EXISTS workspace_bindings",
		"cluster_id text NOT NULL REFERENCES managed_clusters(id)",
		"workspace_bindings_active_scope_unique",
		"WHERE state='ACTIVE'",
		"validate_workspace_binding_authority",
		"workspace binding cross-project authority is forbidden",
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 58 missing Workspace authority guard %q", term)
		}
	}
	for _, forbidden := range []string{
		"ALTER TABLE managed_clusters",
		"ALTER TABLE projects",
		"ALTER TABLE tenant_environments",
		"ALTER TABLE baseline_deployments",
	} {
		if strings.Contains(m.SQL, forbidden) {
			t.Fatalf("migration 58 must not mutate existing runtime authority table via %q", forbidden)
		}
	}
}

func TestFinOpsAuthorityMigrationIsAdditiveAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 70 {
		t.Fatalf("expected migration 70, got %d migrations", len(all))
	}
	m := all[69]
	if m.Version != 70 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 70 compatibility mismatch: %#v", m)
	}
	if strings.Contains(m.SQL, "jsonb_object_length(") {
		t.Fatal("migration 70 uses non-existent PostgreSQL jsonb_object_length function")
	}
	if !strings.Contains(m.SQL, "rates <> '{}'::jsonb") {
		t.Fatal("migration 70 must reject an empty rate-card object with PostgreSQL-native jsonb comparison")
	}
	for _, term := range []string{
		"CREATE TABLE finops_rate_cards",
		"CREATE TABLE finops_usage_measurements",
		"CREATE TABLE finops_capacity_observations",
		"finops_usage_source_event_unique",
		"finops_capacity_source_event_unique",
		"finops_rate_cards_immutable",
		"finops_usage_measurements_immutable",
		"finops_capacity_observations_immutable",
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 70 missing %q", term)
		}
	}
}

func TestVMwareProviderAuthorityMigrationIsRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 71 {
		t.Fatalf("expected migration 71, got %d migrations", len(all))
	}
	m := all[70]
	if m.Version != 71 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 71 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{"infrastructure_provider", "infrastructure_endpoint", "credential_ref", "VMWARE_PROVIDER_AUTHORITY_V1"} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 71 missing %q", term)
		}
	}
}

func TestMCPControlJobRecoveryResolutionMigrationIsAdditiveAndRollingSafe(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 72 {
		t.Fatalf("expected migration 72, got %d migrations", len(all))
	}
	m := all[71]
	if m.Version != 72 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 72 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{
		"MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1",
		"recovery_resolution text NOT NULL DEFAULT ''",
		"recovery_readback_digest text NOT NULL DEFAULT ''",
		"recovery_evidence_digest text NOT NULL DEFAULT ''",
		"recovered_by text NOT NULL DEFAULT ''",
		"recovered_at timestamptz",
		"mcp_control_jobs_recovery_resolution_shape",
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 72 missing %q", term)
		}
	}
}

func TestFinOpsBudgetPolicyMigrationMakesOrganizationLevelIdentityUnique(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 73 {
		t.Fatalf("expected migration 73, got %d migrations", len(all))
	}
	m := all[72]
	if m.Version != 73 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 73 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{
		"CREATE TABLE finops_budget_policies",
		"CREATE UNIQUE INDEX finops_budget_identity_scope_unique",
		"COALESCE(project_id,'')",
		"finops_budget_policies_immutable",
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 73 missing %q", term)
		}
	}
}
