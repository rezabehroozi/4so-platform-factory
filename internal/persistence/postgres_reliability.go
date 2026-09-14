package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const healthObservationColumns = `id,organization_id,project_id,cluster_id,health,observed_at,source_digest`
const incidentColumns = `id,organization_id,project_id,cluster_id,service,severity,state,revision,acknowledged_by,resolved_by,resolution_summary`
const sloPolicyColumns = `id,organization_id,project_id,cluster_id,name,revision,objective_basis_points,window_seconds,observation_interval_seconds`

func scanHealthObservation(row interface{ Scan(...any) error }) (reliability.HealthObservation, error) {
	var v reliability.HealthObservation
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.Health, &v.ObservedAt, &v.SourceDigest)
	return v, err
}

func scanIncident(row interface{ Scan(...any) error }) (reliability.Incident, error) {
	var v reliability.Incident
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.Service, &v.Severity, &v.State, &v.Revision, &v.AcknowledgedBy, &v.ResolvedBy, &v.ResolutionSummary)
	return v, err
}

func scanSLOPolicy(row interface{ Scan(...any) error }) (reliability.SLOPolicy, error) {
	var v reliability.SLOPolicy
	var objective int64
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.Name, &v.Revision, &objective, &v.WindowSeconds, &v.ObservationIntervalSeconds)
	v.ObjectiveBasisPoints = int(objective)
	return v, err
}

func validateReliabilityScope(ctx context.Context, tx *sql.Tx, organizationID, projectID, clusterID string) error {
	var projectOrg string
	if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, projectID).Scan(&projectOrg); err != nil {
		return mapDBError(err)
	}
	if projectOrg != organizationID {
		return fmt.Errorf("%w: reliability project is outside organization authority", controlplane.ErrValidation)
	}
	if strings.TrimSpace(clusterID) != "" {
		var clusterProject string
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, clusterID).Scan(&clusterProject); err != nil {
			return mapDBError(err)
		}
		if clusterProject != projectID {
			return fmt.Errorf("%w: reliability cluster is outside project authority", controlplane.ErrValidation)
		}
	}
	return nil
}

func (s *PostgresStore) CreateHealthObservation(ctx context.Context, in reliability.HealthObservation) (reliability.HealthObservation, bool, error) {
	id, err := reliability.ObservationIdentity(in)
	if err != nil {
		return reliability.HealthObservation{}, false, fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
	}
	in.ID = id
	in.ObservedAt = in.ObservedAt.UTC()
	created := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, id); e != nil {
			return e
		}
		existing, e := scanHealthObservation(tx.QueryRowContext(ctx, `SELECT `+healthObservationColumns+` FROM health_observations WHERE id=$1`, id))
		if e == nil {
			in = existing
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		if e = validateReliabilityScope(ctx, tx, in.OrganizationID, in.ProjectID, in.ClusterID); e != nil {
			return e
		}
		now := utcNow(s.now)
		if _, e = tx.ExecContext(ctx, `INSERT INTO health_observations(id,organization_id,project_id,cluster_id,health,observed_at,source_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, in.ID, in.OrganizationID, in.ProjectID, in.ClusterID, in.Health, in.ObservedAt, in.SourceDigest, now); e != nil {
			return mapDBError(e)
		}
		created = true
		return s.appendAuditTx(ctx, tx, "system:fleet-health-observer", "reliability.health_observation.created", "healthObservation", in.ID, 1, "", map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "sourceDigest": in.SourceDigest})
	})
	return in, created, err
}

func (s *PostgresStore) ListHealthObservations(ctx context.Context, projectID, clusterID string, from, until time.Time, limit int) ([]reliability.HealthObservation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+healthObservationColumns+` FROM health_observations WHERE project_id=$1 AND ($2='' OR cluster_id=$2) AND ($3::timestamptz IS NULL OR observed_at >= $3) AND ($4::timestamptz IS NULL OR observed_at < $4) ORDER BY observed_at ASC,id ASC LIMIT $5`, strings.TrimSpace(projectID), strings.TrimSpace(clusterID), nullableTime(from), nullableTime(until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]reliability.HealthObservation, 0)
	for rows.Next() {
		v, e := scanHealthObservation(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateIncident(ctx context.Context, in reliability.Incident, actor string) (reliability.Incident, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" || strings.TrimSpace(in.OrganizationID) == "" || strings.TrimSpace(in.ProjectID) == "" || strings.TrimSpace(in.Severity) == "" {
		return reliability.Incident{}, fmt.Errorf("%w: incident scope, severity and actor are required", controlplane.ErrValidation)
	}
	if in.State == "" {
		in.State = reliability.IncidentOpen
	}
	if in.State != reliability.IncidentOpen {
		return reliability.Incident{}, fmt.Errorf("%w: new incident must start OPEN", controlplane.ErrValidation)
	}
	in.ID = s.id("inc")
	in.Revision = 1
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if err := validateReliabilityScope(ctx, tx, in.OrganizationID, in.ProjectID, in.ClusterID); err != nil {
			return err
		}
		now := utcNow(s.now)
		_, err := tx.ExecContext(ctx, `INSERT INTO incidents(id,organization_id,project_id,cluster_id,service,severity,state,revision,acknowledged_by,resolved_by,resolution_summary,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,'','','',$8,$8)`, in.ID, in.OrganizationID, in.ProjectID, in.ClusterID, in.Service, in.Severity, in.State, now)
		if err != nil {
			return mapDBError(err)
		}
		return s.appendAuditTx(ctx, tx, actor, "reliability.incident.created", "incident", in.ID, 1, "", map[string]any{"projectId": in.ProjectID, "severity": in.Severity})
	})
	return in, err
}

func (s *PostgresStore) GetIncident(ctx context.Context, id string) (reliability.Incident, error) {
	v, err := scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListIncidents(ctx context.Context, projectID, state string, limit int) ([]reliability.Incident, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE project_id=$1 AND ($2='' OR state=$2) ORDER BY updated_at DESC,id DESC LIMIT $3`, strings.TrimSpace(projectID), strings.TrimSpace(state), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]reliability.Incident, 0)
	for rows.Next() {
		v, e := scanIncident(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) TransitionIncident(ctx context.Context, id string, expected int64, action, actor, summary string) (reliability.Incident, error) {
	var next reliability.Incident
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanIncident(tx.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		next, err = reliability.TransitionIncident(current, action, actor, summary)
		if err != nil {
			return fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
		}
		result, err := tx.ExecContext(ctx, `UPDATE incidents SET state=$3,revision=$4,acknowledged_by=$5,resolved_by=$6,resolution_summary=$7,updated_at=$8 WHERE id=$1 AND revision=$2`, id, expected, next.State, next.Revision, next.AcknowledgedBy, next.ResolvedBy, next.ResolutionSummary, utcNow(s.now))
		if err != nil {
			return mapDBError(err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return controlplane.ErrConflict
		}
		return s.appendAuditTx(ctx, tx, actor, "reliability.incident.transitioned", "incident", id, next.Revision, "", map[string]any{"projectId": next.ProjectID, "state": next.State})
	})
	return next, err
}

func (s *PostgresStore) CreateSLOPolicy(ctx context.Context, in reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: actor is required", controlplane.ErrValidation)
	}
	if err := reliability.ValidateSLOPolicy(in); err != nil {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
	}
	in.ID = s.id("slo")
	in.Revision = 1
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if err := validateReliabilityScope(ctx, tx, in.OrganizationID, in.ProjectID, in.ClusterID); err != nil {
			return err
		}
		now := utcNow(s.now)
		_, err := tx.ExecContext(ctx, `INSERT INTO slo_policies(id,organization_id,project_id,cluster_id,name,revision,objective_basis_points,window_seconds,observation_interval_seconds,created_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9)`, in.ID, in.OrganizationID, in.ProjectID, in.ClusterID, in.Name, in.ObjectiveBasisPoints, in.WindowSeconds, in.ObservationIntervalSeconds, now)
		if err != nil {
			return mapDBError(err)
		}
		return s.appendAuditTx(ctx, tx, actor, "reliability.slo_policy.created", "sloPolicy", in.ID, 1, "", map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "name": in.Name})
	})
	return in, err
}

func (s *PostgresStore) CreateSLOPolicyRevision(ctx context.Context, predecessor string, expected int64, next reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: actor is required", controlplane.ErrValidation)
	}
	var out reliability.SLOPolicy
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanSLOPolicy(tx.QueryRowContext(ctx, `SELECT `+sloPolicyColumns+` FROM slo_policies WHERE id=$1 FOR SHARE`, predecessor))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		var latest int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0) FROM slo_policies WHERE project_id=$1 AND cluster_id=$2 AND name=$3`, current.ProjectID, current.ClusterID, current.Name).Scan(&latest); err != nil {
			return err
		}
		if latest != current.Revision {
			return controlplane.ErrConflict
		}
		next.OrganizationID, next.ProjectID, next.ClusterID, next.Name = current.OrganizationID, current.ProjectID, current.ClusterID, current.Name
		next.Revision = current.Revision + 1
		if err = reliability.ValidateSLOPolicy(next); err != nil {
			return fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
		}
		next.ID = s.id("slo")
		if _, err = tx.ExecContext(ctx, `INSERT INTO slo_policies(id,organization_id,project_id,cluster_id,name,revision,objective_basis_points,window_seconds,observation_interval_seconds,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, next.ID, next.OrganizationID, next.ProjectID, next.ClusterID, next.Name, next.Revision, next.ObjectiveBasisPoints, next.WindowSeconds, next.ObservationIntervalSeconds, utcNow(s.now)); err != nil {
			return mapDBError(err)
		}
		out = next
		return s.appendAuditTx(ctx, tx, actor, "reliability.slo_policy.revised", "sloPolicy", out.ID, out.Revision, "", map[string]any{"projectId": out.ProjectID, "clusterId": out.ClusterID, "name": out.Name, "predecessorId": predecessor})
	})
	return out, err
}

func (s *PostgresStore) GetSLOPolicy(ctx context.Context, id string) (reliability.SLOPolicy, error) {
	v, err := scanSLOPolicy(s.db.QueryRowContext(ctx, `SELECT `+sloPolicyColumns+` FROM slo_policies WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListSLOPolicies(ctx context.Context, projectID, name string, limit int) ([]reliability.SLOPolicy, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+sloPolicyColumns+` FROM slo_policies WHERE project_id=$1 AND ($2='' OR name=$2) ORDER BY cluster_id ASC,name ASC,revision ASC,id ASC LIMIT $3`, strings.TrimSpace(projectID), strings.TrimSpace(name), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]reliability.SLOPolicy, 0)
	for rows.Next() {
		v, e := scanSLOPolicy(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

var _ controlplane.ReliabilityStore = (*PostgresStore)(nil)
