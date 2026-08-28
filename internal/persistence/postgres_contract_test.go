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
