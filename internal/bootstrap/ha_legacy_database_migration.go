package bootstrap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type haServiceDatabaseMigrationTarget struct {
	owner    string
	workload string
}

var haServiceDatabaseMigrationTargets = map[string]haServiceDatabaseMigrationTarget{
	"forgejo":  {owner: "forgejo", workload: "platform-forgejo"},
	"keycloak": {owner: "keycloak", workload: "platform-keycloak"},
}

func (r *Runner) haServiceDatabasePrimary(ctx context.Context) (string, error) {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	raw, err := r.system.Output(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system",
		"get", "cluster/platform-postgresql", "-o", "jsonpath={.status.currentPrimary}",
	}, nil)
	if err != nil {
		return "", fmt.Errorf("resolve CloudNativePG primary before service database migration: %w", err)
	}
	primary := strings.TrimSpace(string(raw))
	if primary == "" {
		return "", fmt.Errorf("CloudNativePG primary is empty before service database migration")
	}
	return primary, nil
}

func (r *Runner) haServiceDatabaseQuery(ctx context.Context, primary, database, query string) (string, error) {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	raw, err := r.system.Output(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system",
		"exec", primary, "--", "psql", "-U", "postgres", "-d", database, "-Atqc", query,
	}, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (r *Runner) haServiceDatabaseRun(ctx context.Context, primary, database, statement string) error {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	return r.system.Run(ctx, kubectl, []string{
		"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system",
		"exec", primary, "--", "psql", "-U", "postgres", "-d", database,
		"-v", "ON_ERROR_STOP=1", "-c", statement,
	}, nil)
}

func parseHAServiceDatabaseCount(label, raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s returned invalid count %q", label, raw)
	}
	return value, nil
}

func parseHAServiceDatabaseNames(label, raw string) ([]string, error) {
	values := strings.Fields(raw)
	for _, value := range values {
		switch value {
		case "platform_factory", "forgejo", "keycloak":
		default:
			return nil, fmt.Errorf("%s returned unexpected product database %q", label, value)
		}
	}
	return values, nil
}

func (r *Runner) quiesceLegacyHAServiceWorkload(ctx context.Context, workload string) error {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	raw, err := r.system.Output(ctx, kubectl, []string{
		"--kubeconfig", kubeconfig, "-n", "platform-system",
		"get", "statefulset/" + workload, "--ignore-not-found",
		"-o", "jsonpath={.metadata.name}:{.spec.replicas}",
	}, nil)
	if err != nil {
		return fmt.Errorf("inspect legacy HA workload %s before database ownership migration: %w", workload, err)
	}
	observed := strings.TrimSpace(string(raw))
	if observed == "" {
		return nil
	}
	name, replicasRaw, found := strings.Cut(observed, ":")
	if !found || name != workload {
		return fmt.Errorf("legacy HA workload identity is ambiguous: %q", observed)
	}
	replicas := 1
	if strings.TrimSpace(replicasRaw) != "" {
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(replicasRaw))
		if parseErr != nil || parsed < 0 {
			return fmt.Errorf("legacy HA workload %s has invalid replica count %q", workload, replicasRaw)
		}
		replicas = parsed
	}
	if replicas == 0 {
		return nil
	}
	if err = r.system.Run(ctx, kubectl, []string{
		"--kubeconfig", kubeconfig, "-n", "platform-system",
		"scale", "statefulset/" + workload, "--replicas=0",
	}, nil); err != nil {
		return fmt.Errorf("quiesce legacy HA workload %s before database ownership migration: %w", workload, err)
	}
	if err = waitUntil(ctx, time.Second, 5*time.Minute, func() error {
		pods, outputErr := r.system.Output(ctx, kubectl, []string{
			"--kubeconfig", kubeconfig, "-n", "platform-system",
			"get", "pods", "-l", "app=" + workload,
			"-o", "jsonpath={.items[*].metadata.name}",
		}, nil)
		if outputErr != nil {
			return outputErr
		}
		if strings.TrimSpace(string(pods)) != "" {
			return fmt.Errorf("workload pods are still running")
		}
		return nil
	}); err != nil {
		return fmt.Errorf("wait for legacy HA workload %s to quiesce: %w", workload, err)
	}
	return nil
}

// reconcileLegacyHAServiceDatabaseOwnership upgrades the historical HA layout
// where Forgejo and Keycloak used the platform database role. The migration is
// deliberately fenced to the two product-owned service databases, quiesces an
// existing legacy workload before changing ownership, and is replay-safe:
// after REASSIGN/ALTER succeed, a retry observes the target owner and skips
// already-completed mutations before the caller reapplies desired workload state.
func (r *Runner) reconcileLegacyHAServiceDatabaseOwnership(ctx context.Context, run Run, database, owner, workload string) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	target, ok := haServiceDatabaseMigrationTargets[database]
	if !ok || target.owner != owner || target.workload != workload {
		return fmt.Errorf("unsupported HA service database migration target database=%q owner=%q workload=%q", database, owner, workload)
	}
	primary, err := r.haServiceDatabasePrimary(ctx)
	if err != nil {
		return err
	}
	roleCountRaw, err := r.haServiceDatabaseQuery(ctx, primary, "postgres",
		fmt.Sprintf("SELECT count(*) FROM pg_roles WHERE rolname='%s' AND rolcanlogin", owner))
	if err != nil {
		return fmt.Errorf("verify HA service database role %s: %w", owner, err)
	}
	roleCount, err := parseHAServiceDatabaseCount("HA service database role", roleCountRaw)
	if err != nil {
		return err
	}
	if roleCount != 1 {
		return fmt.Errorf("HA service database role %s is not present as one login role", owner)
	}
	databaseOwner, err := r.haServiceDatabaseQuery(ctx, primary, "postgres",
		fmt.Sprintf("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='%s'", database))
	if err != nil {
		return fmt.Errorf("inspect HA service database owner for %s: %w", database, err)
	}
	if databaseOwner != "platform" && databaseOwner != owner {
		return fmt.Errorf("HA service database %s has unexpected owner %q; refusing implicit adoption", database, databaseOwner)
	}
	legacyObjectsRaw, err := r.haServiceDatabaseQuery(ctx, primary, database,
		"SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid=d.refobjid WHERE d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND r.rolname='platform' AND d.deptype='o'")
	if err != nil {
		return fmt.Errorf("inspect legacy platform-owned objects in HA service database %s: %w", database, err)
	}
	legacyObjects, err := parseHAServiceDatabaseCount("legacy HA service database ownership", legacyObjectsRaw)
	if err != nil {
		return err
	}
	if databaseOwner == owner && legacyObjects == 0 {
		return nil
	}
	sharedDatabasesRaw, err := r.haServiceDatabaseQuery(ctx, primary, "postgres",
		"SELECT datname FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='platform') ORDER BY datname")
	if err != nil {
		return fmt.Errorf("inspect platform-owned shared databases before HA service migration for %s: %w", database, err)
	}
	sharedDatabases, err := parseHAServiceDatabaseNames("platform-owned shared database inventory", sharedDatabasesRaw)
	if err != nil {
		return err
	}
	sharedDatabaseSet := make(map[string]struct{}, len(sharedDatabases))
	for _, sharedDatabase := range sharedDatabases {
		sharedDatabaseSet[sharedDatabase] = struct{}{}
	}
	if databaseOwner == "platform" {
		if _, ok := sharedDatabaseSet[database]; !ok {
			return fmt.Errorf("HA service database %s reports owner platform but is absent from the shared database ownership inventory", database)
		}
	}
	platformTablespacesRaw, err := r.haServiceDatabaseQuery(ctx, primary, "postgres",
		"SELECT spcname FROM pg_tablespace WHERE spcowner=(SELECT oid FROM pg_roles WHERE rolname='platform') ORDER BY spcname")
	if err != nil {
		return fmt.Errorf("inspect platform-owned shared tablespaces before HA service migration for %s: %w", database, err)
	}
	if tablespaces := strings.Fields(platformTablespacesRaw); len(tablespaces) != 0 {
		return fmt.Errorf("platform role owns shared tablespace(s) %q; refusing HA service database migration that could transfer shared ownership", strings.Join(tablespaces, ","))
	}
	if err = r.quiesceLegacyHAServiceWorkload(ctx, workload); err != nil {
		return err
	}
	statements := []string{"BEGIN", fmt.Sprintf("REASSIGN OWNED BY platform TO %s", owner)}
	for _, sharedDatabase := range sharedDatabases {
		desiredOwner := "platform"
		if sharedDatabase == database {
			desiredOwner = owner
		}
		statements = append(statements, fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", sharedDatabase, desiredOwner))
	}
	statements = append(statements, "COMMIT")
	if err = r.haServiceDatabaseRun(ctx, primary, database, strings.Join(statements, "; ")+";"); err != nil {
		return fmt.Errorf("reassign legacy HA service database %s objects to %s while preserving shared database ownership: %w", database, owner, err)
	}
	verifiedOwner, err := r.haServiceDatabaseQuery(ctx, primary, "postgres",
		fmt.Sprintf("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='%s'", database))
	if err != nil {
		return fmt.Errorf("verify HA service database owner after migration for %s: %w", database, err)
	}
	if verifiedOwner != owner {
		return fmt.Errorf("HA service database %s owner migration did not converge: got %q want %q", database, verifiedOwner, owner)
	}
	remainingRaw, err := r.haServiceDatabaseQuery(ctx, primary, database,
		"SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid=d.refobjid WHERE d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND r.rolname='platform' AND d.deptype='o'")
	if err != nil {
		return fmt.Errorf("verify legacy ownership cleanup in HA service database %s: %w", database, err)
	}
	remaining, err := parseHAServiceDatabaseCount("remaining legacy HA service database ownership", remainingRaw)
	if err != nil {
		return err
	}
	if remaining != 0 {
		return fmt.Errorf("HA service database %s still has %d platform-owned object(s) after migration", database, remaining)
	}
	return nil
}
