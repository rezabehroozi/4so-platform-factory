package bootstrap

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type legacyHADatabaseMigrationSystem struct {
	*SimulatedSystem
	databaseOwner   string
	legacyObjects   int
	targetRole      bool
	workloadExists  bool
	workloadReplicas int
	scaled           bool
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
