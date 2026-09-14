package migrations

import (
	"strings"
	"testing"
)

func TestSLOClusterTargetMigrationIsRollingSafeAndRekeysIdentity(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 75 {
		t.Fatalf("expected migration 75, got %d migrations", len(all))
	}
	m := all[74]
	if m.Version != 75 || m.Compatibility != CompatibilityRollingSafe {
		t.Fatalf("migration 75 compatibility mismatch: %#v", m)
	}
	for _, term := range []string{
		"ADD COLUMN cluster_id text NOT NULL DEFAULT ''",
		"DROP INDEX slo_policies_project_name_revision_unique",
		"slo_policies_project_cluster_name_revision_unique",
		"ON slo_policies(project_id, cluster_id, lower(name), revision)",
	} {
		if !strings.Contains(m.SQL, term) {
			t.Fatalf("migration 75 missing %q", term)
		}
	}
}
