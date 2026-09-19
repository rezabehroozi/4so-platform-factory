package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type legacyHADatabaseMigrationSystem struct {
	*SimulatedSystem
	databaseOwner   string
	legacyObjects   int
	targetRole      bool
	workloadExists             bool
	workloadReplicas            int
	platformOwnedDatabases      []string
	platformOwnedTablespaces    []string
	scaled                      bool
}

func (s *legacyHADatabaseMigrationSystem) record(name string, args []string) string {
	line := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, line)
	return line
}

func (s *legacyHADatabaseMigrationSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	line := s.record(name, args)
	switch {
	case strings.Contains(line, "get cluster/platform-postgresql") && strings.Contains(line, "currentPrimary"):
		return []byte("platform-postgresql-1\n"), nil
	case strings.Contains(line, "FROM pg_database WHERE datdba="):
		return []byte(strings.Join(s.platformOwnedDatabases, "\n")), nil
	case strings.Contains(line, "FROM pg_tablespace WHERE spcowner="):
		return []byte(strings.Join(s.platformOwnedTablespaces, "\n")), nil
	case strings.Contains(line, "FROM pg_roles"):
		if s.targetRole {
			return []byte("1\n"), nil
		}
		return []byte("0\n"), nil
	case strings.Contains(line, "pg_get_userbyid(datdba)"):
		return []byte(s.databaseOwner + "\n"), nil
	case strings.Contains(line, "pg_shdepend"):
		return []byte(fmt.Sprintf("%d\n", s.legacyObjects)), nil
	case strings.Contains(line, "get statefulset/platform-forgejo"):
		if !s.workloadExists {
			return nil, nil
		}
		return []byte(fmt.Sprintf("platform-forgejo:%d", s.workloadReplicas)), nil
	case strings.Contains(line, "get statefulset/platform-keycloak"):
		if !s.workloadExists {
			return nil, nil
		}
		return []byte(fmt.Sprintf("platform-keycloak:%d", s.workloadReplicas)), nil
	case strings.Contains(line, "get pods -l app="):
		if s.scaled || !s.workloadExists || s.workloadReplicas == 0 {
			return nil, nil
		}
		return []byte("legacy-pod"), nil
	default:
		return nil, nil
	}
}

func (s *legacyHADatabaseMigrationSystem) Run(_ context.Context, name string, args []string, _ map[string]string) error {
	line := s.record(name, args)
	if strings.Contains(line, "scale statefulset/") && strings.Contains(line, "--replicas=0") {
		s.scaled = true
		s.workloadReplicas = 0
	}
	if strings.Contains(line, "REASSIGN OWNED BY platform TO ") {
		s.legacyObjects = 0
	}
	if strings.Contains(line, "ALTER DATABASE forgejo OWNER TO forgejo") {
		s.databaseOwner = "forgejo"
	}
	if strings.Contains(line, "ALTER DATABASE keycloak OWNER TO keycloak") {
		s.databaseOwner = "keycloak"
	}
	return nil
}

func haMigrationRun(profile string) Run {
	run := Run{}
	run.Request.ProfileID = profile
	return run
}

func commandIndex(commands []string, fragment string) int {
	for i, command := range commands {
		if strings.Contains(command, fragment) {
			return i
		}
	}
	return -1
}

func TestLegacyHAServiceDatabaseOwnershipMigrationQuiescesBeforeReassign(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "platform", legacyObjects: 4, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "keycloak", "platform_factory"},
	}
	runner := &Runner{system: system}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo"); err != nil {
		t.Fatal(err)
	}
	if system.databaseOwner != "forgejo" || system.legacyObjects != 0 || !system.scaled {
		t.Fatalf("migration did not converge: owner=%s legacy=%d scaled=%v", system.databaseOwner, system.legacyObjects, system.scaled)
	}
	scale := commandIndex(system.Commands, "scale statefulset/platform-forgejo --replicas=0")
	reassign := commandIndex(system.Commands, "REASSIGN OWNED BY platform TO forgejo")
	if scale < 0 || reassign < 0 || scale >= reassign {
		t.Fatalf("legacy workload was not quiesced before ownership migration: commands=%v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationSkipsConvergedFreshDatabase(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "keycloak", legacyObjects: 0, targetRole: true,
		workloadExists: true, workloadReplicas: 2,
	}
	runner := &Runner{system: system}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "keycloak", "keycloak", "platform-keycloak"); err != nil {
		t.Fatal(err)
	}
	if system.scaled || commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("already-converged database was mutated: commands=%v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationRepairsPartialOwnership(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "keycloak", legacyObjects: 2, targetRole: true,
		workloadExists: true, workloadReplicas: 2,
		platformOwnedDatabases: []string{"forgejo", "platform_factory"},
	}
	runner := &Runner{system: system}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "keycloak", "keycloak", "platform-keycloak"); err != nil {
		t.Fatal(err)
	}
	if !system.scaled || system.legacyObjects != 0 {
		t.Fatalf("partial legacy ownership was not repaired: scaled=%v legacy=%d", system.scaled, system.legacyObjects)
	}
	if commandIndex(system.Commands, "ALTER DATABASE keycloak OWNER TO keycloak") >= 0 {
		t.Fatalf("already-correct database owner was needlessly altered: commands=%v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationFailsClosedOnUnexpectedOwner(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "foreign-owner", targetRole: true,
		workloadExists: true, workloadReplicas: 1,
	}
	runner := &Runner{system: system}
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo")
	if err == nil || !strings.Contains(err.Error(), "unexpected owner") {
		t.Fatalf("unexpected database owner was not rejected: %v", err)
	}
	if system.scaled || commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("mutation occurred before unexpected-owner rejection: commands=%v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationRequiresTargetLoginRole(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "platform", legacyObjects: 1, targetRole: false,
		workloadExists: true, workloadReplicas: 1,
	}
	runner := &Runner{system: system}
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo")
	if err == nil || !strings.Contains(err.Error(), "not present as one login role") {
		t.Fatalf("missing target role was not rejected: %v", err)
	}
	if system.scaled {
		t.Fatal("workload was quiesced before target role admission")
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationIsHANarrow(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("evaluation-single-node"), "forgejo", "forgejo", "platform-forgejo"); err != nil {
		t.Fatal(err)
	}
	if len(system.Commands) != 0 {
		t.Fatalf("single-node path unexpectedly touched HA migration authority: %v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationRejectsUnregisteredTarget(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "other", "other", "platform-other")
	if err == nil || !strings.Contains(err.Error(), "unsupported HA service database migration target") {
		t.Fatalf("unregistered migration target was not rejected: %v", err)
	}
	if len(system.Commands) != 0 {
		t.Fatalf("unregistered target reached runtime authority: %v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationPreservesOtherSharedDatabaseOwners(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "platform", legacyObjects: 3, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "keycloak", "platform_factory"},
	}
	runner := &Runner{system: system}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo"); err != nil {
		t.Fatal(err)
	}
	reassign := commandIndex(system.Commands, "REASSIGN OWNED BY platform TO forgejo")
	if reassign < 0 {
		t.Fatalf("ownership migration command missing: %v", system.Commands)
	}
	command := system.Commands[reassign]
	for _, expected := range []string{
		"BEGIN; REASSIGN OWNED BY platform TO forgejo",
		"ALTER DATABASE forgejo OWNER TO forgejo",
		"ALTER DATABASE keycloak OWNER TO platform",
		"ALTER DATABASE platform_factory OWNER TO platform",
		"COMMIT;",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("shared database ownership was not preserved; missing %q in %s", expected, command)
		}
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationRejectsUnexpectedPlatformOwnedDatabase(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "platform", legacyObjects: 1, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "platform_factory", "foreign_database"},
	}
	runner := &Runner{system: system}
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo")
	if err == nil || !strings.Contains(err.Error(), "unexpected product database") {
		t.Fatalf("unexpected platform-owned database was not rejected: %v", err)
	}
	if system.scaled || commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("mutation occurred before shared-database admission: commands=%v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseOwnershipMigrationRejectsPlatformOwnedTablespace(t *testing.T) {
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		databaseOwner: "platform", legacyObjects: 1, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "platform_factory"},
		platformOwnedTablespaces: []string{"unexpected_tablespace"},
	}
	runner := &Runner{system: system}
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo")
	if err == nil || !strings.Contains(err.Error(), "shared tablespace") {
		t.Fatalf("platform-owned shared tablespace was not rejected: %v", err)
	}
	if system.scaled || commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("mutation occurred before tablespace admission: commands=%v", system.Commands)
	}
}


func TestLegacyHAServiceDatabaseMigrationPersistsDurableOwnershipPhase(t *testing.T) {
	root := t.TempDir()
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		databaseOwner: "platform", legacyObjects: 2, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "platform_factory"},
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Date(2026, 9, 19, 21, 0, 0, 0, time.UTC) }}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo"); err != nil {
		t.Fatal(err)
	}
	status, err := runner.loadHAServiceDatabaseMigrationStatus("forgejo", "forgejo", "platform-forgejo")
	if err != nil || status == nil {
		t.Fatalf("migration status missing: %#v err=%v", status, err)
	}
	if status.Phase != haServiceDatabaseMigrationOwnershipApplied || status.DatabaseOwner != "forgejo" || status.LegacyObjects != 0 {
		t.Fatalf("unexpected migration status after ownership transfer: %#v", status)
	}
}

func TestLegacyHAServiceDatabaseMigrationRecoversOwnershipAppliedFromObservation(t *testing.T) {
	root := t.TempDir()
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		databaseOwner: "keycloak", legacyObjects: 0, targetRole: true,
		workloadExists: true, workloadReplicas: 0,
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Date(2026, 9, 19, 21, 1, 0, 0, time.UTC) }}
	if err := runner.writeHAServiceDatabaseMigrationStatus("keycloak", "keycloak", "platform-keycloak", haServiceDatabaseMigrationQuiesced, "platform", 3); err != nil {
		t.Fatal(err)
	}
	if err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "keycloak", "keycloak", "platform-keycloak"); err != nil {
		t.Fatal(err)
	}
	status, err := runner.loadHAServiceDatabaseMigrationStatus("keycloak", "keycloak", "platform-keycloak")
	if err != nil || status == nil || status.Phase != haServiceDatabaseMigrationOwnershipApplied {
		t.Fatalf("crash recovery did not reconstruct ownership phase: %#v err=%v", status, err)
	}
	if commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("already-applied ownership was replayed instead of observed: %v", system.Commands)
	}
}

func TestLegacyHAServiceDatabaseMigrationMarksReconciledOnlyAfterOwnershipIsProven(t *testing.T) {
	root := t.TempDir()
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		databaseOwner: "forgejo", legacyObjects: 0, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
	}
	runner := &Runner{system: system, now: func() time.Time { return time.Date(2026, 9, 19, 21, 2, 0, 0, time.UTC) }}
	if err := runner.writeHAServiceDatabaseMigrationStatus("forgejo", "forgejo", "platform-forgejo", haServiceDatabaseMigrationOwnershipApplied, "forgejo", 0); err != nil {
		t.Fatal(err)
	}
	if err := runner.finalizeLegacyHAServiceDatabaseMigration(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo"); err != nil {
		t.Fatal(err)
	}
	status, err := runner.loadHAServiceDatabaseMigrationStatus("forgejo", "forgejo", "platform-forgejo")
	if err != nil || status == nil || status.Phase != haServiceDatabaseMigrationReconciled {
		t.Fatalf("migration did not reach RECONCILED: %#v err=%v", status, err)
	}
}

func TestLegacyHAServiceDatabaseMigrationRejectsJournalIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	system := &legacyHADatabaseMigrationSystem{
		SimulatedSystem: &SimulatedSystem{Root: root},
		databaseOwner: "platform", legacyObjects: 1, targetRole: true,
		workloadExists: true, workloadReplicas: 1,
		platformOwnedDatabases: []string{"forgejo", "platform_factory"},
	}
	runner := &Runner{system: system, now: time.Now}
	foreign := HAServiceDatabaseMigrationStatus{
		Authority: haServiceDatabaseMigrationAuthority, Database: "forgejo", Owner: "foreign", Workload: "platform-forgejo",
		Phase: haServiceDatabaseMigrationAdmitted, DatabaseOwner: "platform", LegacyObjects: 1, UpdatedAt: time.Now().UTC(),
	}
	raw, _ := json.Marshal(foreign)
	if err := system.WriteFile(runner.haServiceDatabaseMigrationPath("forgejo"), raw, 0o600); err != nil { t.Fatal(err) }
	err := runner.reconcileLegacyHAServiceDatabaseOwnership(context.Background(), haMigrationRun("production-standard-ha"), "forgejo", "forgejo", "platform-forgejo")
	if err == nil || !strings.Contains(err.Error(), "authority mismatch") {
		t.Fatalf("journal identity mismatch was not rejected: %v", err)
	}
	if system.scaled || commandIndex(system.Commands, "REASSIGN OWNED") >= 0 {
		t.Fatalf("mutation occurred after migration journal identity mismatch: %v", system.Commands)
	}
}
