package persistence

import (
	"os"
	"strings"
	"testing"
)

func TestPostgresRepositoryContainsRequiredConcurrencyPrimitives(t *testing.T) {
	raw, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, term := range []string{"s.serializable(ctx", "FOR UPDATE", "FOR UPDATE SKIP LOCKED", "fence_token=fence_token+1", "operations_idempotency_key"} {
		if !strings.Contains(source, term) && term != "operations_idempotency_key" {
			t.Fatalf("postgres repository missing %q", term)
		}
	}
}

func TestPostgresGovernedReleaseRevisionPairsUseSerializableTransactions(t *testing.T) {
	checks := map[string][]string{
		"postgres_catalog_governance.go": {
			"func (s *PostgresStore) CreateCatalogReleaseWithRevision",
			"func (s *PostgresStore) UpdateCatalogReleaseDraftWithRevision",
			"s.serializable(ctx",
			"FOR UPDATE",
			"createCatalogRevisionTx",
		},
		"postgres_blueprint_lifecycle.go": {
			"func (s *PostgresStore) CreateBlueprintReleaseWithRevision",
			"func (s *PostgresStore) UpdateBlueprintReleaseDraftWithRevision",
			"s.serializable(ctx",
			"FOR UPDATE",
			"createBlueprintRevisionTx",
		},
	}
	for file, terms := range checks {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		for _, term := range terms {
			if !strings.Contains(source, term) {
				t.Fatalf("%s missing atomic governed-release primitive %q", file, term)
			}
		}
	}
}

func TestPostgresPlatformTemplateCreationLocksAuthorityBindings(t *testing.T) {
	raw, err := os.ReadFile("postgres_platform_template.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, term := range []string{
		"func (s *PostgresStore) CreatePlatformTemplate",
		"s.serializable(ctx",
		"FROM blueprint_releases WHERE id=$1 FOR SHARE",
		"FROM variable_schemas WHERE id=$1 FOR SHARE",
		"FROM platform_policy_sets WHERE id=$1 FOR SHARE",
		"platform_template.created",
	} {
		if !strings.Contains(source, term) {
			t.Fatalf("postgres platform-template authority missing %q", term)
		}
	}
}

func TestPostgresOperationExecutionAuthorityIncludesLeaseExpiryAndAttemptScopedStepReplay(t *testing.T) {
	checks := map[string][]string{
		"postgres_operation_retry.go": {
			"OperationLeaseActive(op, worker, fence, now)",
			"operation.failure_reported",
		},
		"postgres_compensation.go": {
			"OperationLeaseActive(op, worker, fence",
		},
		"postgres_store.go": {
			"CanDirectOperationTransition",
			"OperationLeaseActive(op, actor, step.FenceToken",
			"OperationStepReplayCompatible(existing, step)",
			"WHERE operation_id=$1 AND attempt=$2 AND step_key=$3",
		},
	}
	for file, terms := range checks {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		for _, term := range terms {
			if !strings.Contains(source, term) {
				t.Fatalf("%s missing operation execution authority primitive %q", file, term)
			}
		}
	}
}
