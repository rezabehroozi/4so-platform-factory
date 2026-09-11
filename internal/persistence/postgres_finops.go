package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const finOpsRateCardColumns = `id,organization_id,revision,authority,name,version,currency,effective_from,effective_until,rates,digest,created_at,updated_at`
const finOpsUsageColumns = `id,organization_id,project_id,cluster_id,workspace_id,namespace,revision,authority,source,source_event_id,window_start,window_end,metrics,digest,created_at,updated_at`
const finOpsCapacityColumns = `id,organization_id,project_id,cluster_id,revision,authority,source,source_event_id,observed_at,metrics,digest,created_at,updated_at`

func scanFinOpsRateCard(row interface{ Scan(...any) error }) (controlplane.FinOpsRateCard, error) {
	var v controlplane.FinOpsRateCard
	var until sql.NullTime
	var raw []byte
	if err := row.Scan(&v.ID, &v.OrganizationID, &v.Revision, &v.Authority, &v.Name, &v.Version, &v.Currency, &v.EffectiveFrom, &until, &raw, &v.Digest, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if until.Valid {
		t := until.Time
		v.EffectiveUntil = &t
	}
	if err := decodeJSONColumn(raw, &v.Rates, "finops_rate_cards.rates"); err != nil {
		return v, err
	}
	return v, nil
}
func scanFinOpsUsage(row interface{ Scan(...any) error }) (controlplane.FinOpsUsageMeasurement, error) {
	var v controlplane.FinOpsUsageMeasurement
	var raw []byte
	if err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.WorkspaceID, &v.Namespace, &v.Revision, &v.Authority, &v.Source, &v.SourceEventID, &v.WindowStart, &v.WindowEnd, &raw, &v.Digest, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if err := decodeJSONColumn(raw, &v.Metrics, "finops_usage_measurements.metrics"); err != nil {
		return v, err
	}
	return v, nil
}
func scanFinOpsCapacity(row interface{ Scan(...any) error }) (controlplane.FinOpsCapacityObservation, error) {
	var v controlplane.FinOpsCapacityObservation
	var raw []byte
	if err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.Authority, &v.Source, &v.SourceEventID, &v.ObservedAt, &raw, &v.Digest, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if err := decodeJSONColumn(raw, &v.Metrics, "finops_capacity_observations.metrics"); err != nil {
		return v, err
	}
	return v, nil
}

func (s *PostgresStore) CreateFinOpsRateCard(ctx context.Context, in controlplane.FinOpsRateCard, actor string) (controlplane.FinOpsRateCard, error) {
	v, err := controlplane.NormalizeFinOpsRateCard(in)
	if err != nil {
		return v, err
	}
	rates, err := json.Marshal(v.Rates)
	if err != nil {
		return v, err
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("frc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		lockKey := v.OrganizationID + "\x00" + v.Currency
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
			return err
		}
		var conflicts int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM finops_rate_cards WHERE organization_id=$1 AND currency=$2 AND effective_from < COALESCE($4::timestamptz,'infinity'::timestamptz) AND $3::timestamptz < COALESCE(effective_until,'infinity'::timestamptz)`, v.OrganizationID, v.Currency, v.EffectiveFrom, v.EffectiveUntil).Scan(&conflicts); err != nil {
			return err
		}
		if conflicts > 0 {
			return controlplane.ErrConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO finops_rate_cards(id,organization_id,revision,authority,name,version,currency,effective_from,effective_until,rates,digest,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$11)`, v.ID, v.OrganizationID, v.Authority, v.Name, v.Version, v.Currency, v.EffectiveFrom, v.EffectiveUntil, rates, v.Digest, now)
		if err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "finops.rate_card.created", "finOpsRateCard", v.ID, 1, "", map[string]any{"organizationId": v.OrganizationID, "currency": v.Currency, "digest": v.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "finOpsRateCard", v.ID, "finops.rate_card.created", v)
	})
	return v, err
}
func (s *PostgresStore) GetFinOpsRateCard(ctx context.Context, id string) (controlplane.FinOpsRateCard, error) {
	v, err := scanFinOpsRateCard(s.db.QueryRowContext(ctx, `SELECT `+finOpsRateCardColumns+` FROM finops_rate_cards WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListFinOpsRateCards(ctx context.Context, orgID string) ([]controlplane.FinOpsRateCard, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+finOpsRateCardColumns+` FROM finops_rate_cards WHERE ($1='' OR organization_id=$1) ORDER BY effective_from,id`, strings.TrimSpace(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.FinOpsRateCard{}
	for rows.Next() {
		v, e := scanFinOpsRateCard(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func validateFinOpsSQLScope(ctx context.Context, tx *sql.Tx, orgID, projectID, clusterID, workspaceID string) error {
	var actualOrg string
	if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, projectID).Scan(&actualOrg); err != nil {
		return mapDBError(err)
	}
	if actualOrg != orgID {
		return fmt.Errorf("%w: FinOps project is outside organization authority", controlplane.ErrValidation)
	}
	if clusterID != "" {
		var p string
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, clusterID).Scan(&p); err != nil {
			return mapDBError(err)
		}
		if p != projectID {
			return fmt.Errorf("%w: FinOps cluster is outside project authority", controlplane.ErrValidation)
		}
	}
	if workspaceID != "" {
		var p string
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM workspaces WHERE id=$1`, workspaceID).Scan(&p); err != nil {
			return mapDBError(err)
		}
		if p != projectID {
			return fmt.Errorf("%w: FinOps workspace is outside project authority", controlplane.ErrValidation)
		}
	}
	return nil
}

func (s *PostgresStore) CreateFinOpsUsageMeasurement(ctx context.Context, in controlplane.FinOpsUsageMeasurement, actor string) (controlplane.FinOpsUsageMeasurement, bool, error) {
	v, err := controlplane.NormalizeFinOpsUsageMeasurement(in)
	if err != nil {
		return v, false, err
	}
	raw, err := json.Marshal(v.Metrics)
	if err != nil {
		return v, false, err
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("fus"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	replay := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		key := v.ProjectID + "\x00" + v.Source + "\x00" + v.SourceEventID
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return err
		}
		if err := validateFinOpsSQLScope(ctx, tx, v.OrganizationID, v.ProjectID, v.ClusterID, v.WorkspaceID); err != nil {
			return err
		}
		existing, e := scanFinOpsUsage(tx.QueryRowContext(ctx, `SELECT `+finOpsUsageColumns+` FROM finops_usage_measurements WHERE project_id=$1 AND source=$2 AND source_event_id=$3`, v.ProjectID, v.Source, v.SourceEventID))
		if e == nil {
			if existing.Digest != v.Digest {
				return controlplane.ErrIdempotencyConflict
			}
			v = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO finops_usage_measurements(id,organization_id,project_id,cluster_id,workspace_id,namespace,revision,authority,source,source_event_id,window_start,window_end,metrics,digest,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$14)`, v.ID, v.OrganizationID, v.ProjectID, v.ClusterID, v.WorkspaceID, v.Namespace, v.Authority, v.Source, v.SourceEventID, v.WindowStart, v.WindowEnd, raw, v.Digest, now)
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "finops.usage_measurement.created", "finOpsUsageMeasurement", v.ID, 1, "", map[string]any{"organizationId": v.OrganizationID, "projectId": v.ProjectID, "source": v.Source, "digest": v.Digest})
	})
	return v, replay, err
}
func (s *PostgresStore) GetFinOpsUsageMeasurement(ctx context.Context, id string) (controlplane.FinOpsUsageMeasurement, error) {
	v, err := scanFinOpsUsage(s.db.QueryRowContext(ctx, `SELECT `+finOpsUsageColumns+` FROM finops_usage_measurements WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListFinOpsUsageMeasurements(ctx context.Context, orgID, projectID string, from, until time.Time, limit int) ([]controlplane.FinOpsUsageMeasurement, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+finOpsUsageColumns+` FROM finops_usage_measurements WHERE ($1='' OR organization_id=$1) AND ($2='' OR project_id=$2) AND ($3::timestamptz IS NULL OR window_end >= $3) AND ($4::timestamptz IS NULL OR window_start <= $4) ORDER BY window_start DESC,id DESC LIMIT $5`, strings.TrimSpace(orgID), strings.TrimSpace(projectID), nullableTime(from), nullableTime(until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.FinOpsUsageMeasurement{}
	for rows.Next() {
		v, e := scanFinOpsUsage(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateFinOpsCapacityObservation(ctx context.Context, in controlplane.FinOpsCapacityObservation, actor string) (controlplane.FinOpsCapacityObservation, bool, error) {
	v, err := controlplane.NormalizeFinOpsCapacityObservation(in)
	if err != nil {
		return v, false, err
	}
	raw, err := json.Marshal(v.Metrics)
	if err != nil {
		return v, false, err
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("fco"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	replay := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		key := v.ProjectID + "\x00" + v.Source + "\x00" + v.SourceEventID
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return err
		}
		if err := validateFinOpsSQLScope(ctx, tx, v.OrganizationID, v.ProjectID, v.ClusterID, ""); err != nil {
			return err
		}
		existing, e := scanFinOpsCapacity(tx.QueryRowContext(ctx, `SELECT `+finOpsCapacityColumns+` FROM finops_capacity_observations WHERE project_id=$1 AND source=$2 AND source_event_id=$3`, v.ProjectID, v.Source, v.SourceEventID))
		if e == nil {
			if existing.Digest != v.Digest {
				return controlplane.ErrIdempotencyConflict
			}
			v = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO finops_capacity_observations(id,organization_id,project_id,cluster_id,revision,authority,source,source_event_id,observed_at,metrics,digest,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9::jsonb,$10,$11,$11)`, v.ID, v.OrganizationID, v.ProjectID, v.ClusterID, v.Authority, v.Source, v.SourceEventID, v.ObservedAt, raw, v.Digest, now)
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "finops.capacity_observation.created", "finOpsCapacityObservation", v.ID, 1, "", map[string]any{"organizationId": v.OrganizationID, "projectId": v.ProjectID, "source": v.Source, "digest": v.Digest})
	})
	return v, replay, err
}
func (s *PostgresStore) GetFinOpsCapacityObservation(ctx context.Context, id string) (controlplane.FinOpsCapacityObservation, error) {
	v, err := scanFinOpsCapacity(s.db.QueryRowContext(ctx, `SELECT `+finOpsCapacityColumns+` FROM finops_capacity_observations WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListFinOpsCapacityObservations(ctx context.Context, orgID, projectID string, from, until time.Time, limit int) ([]controlplane.FinOpsCapacityObservation, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+finOpsCapacityColumns+` FROM finops_capacity_observations WHERE ($1='' OR organization_id=$1) AND ($2='' OR project_id=$2) AND ($3::timestamptz IS NULL OR observed_at >= $3) AND ($4::timestamptz IS NULL OR observed_at <= $4) ORDER BY observed_at DESC,id DESC LIMIT $5`, strings.TrimSpace(orgID), strings.TrimSpace(projectID), nullableTime(from), nullableTime(until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.FinOpsCapacityObservation{}
	for rows.Next() {
		v, e := scanFinOpsCapacity(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func nullableTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}
