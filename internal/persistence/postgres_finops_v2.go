package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const finOpsBudgetColumns = `id,organization_id,project_id,revision,authority,name,version,currency,effective_from,effective_until,limit_micros,warning_basis_points,critical_basis_points,digest,created_at,updated_at`

func scanFinOpsBudget(row interface{ Scan(...any) error }) (controlplane.FinOpsBudgetPolicy, error) {
	var v controlplane.FinOpsBudgetPolicy
	var project sql.NullString
	var until sql.NullTime
	if err := row.Scan(&v.ID, &v.OrganizationID, &project, &v.Revision, &v.Authority, &v.Name, &v.Version, &v.Currency, &v.EffectiveFrom, &until, &v.LimitMicros, &v.WarningBasisPoints, &v.CriticalBasisPoints, &v.Digest, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if project.Valid {
		v.ProjectID = project.String
	}
	if until.Valid {
		t := until.Time
		v.EffectiveUntil = &t
	}
	return v, nil
}

func (s *PostgresStore) CreateFinOpsBudgetPolicy(ctx context.Context, in controlplane.FinOpsBudgetPolicy, actor string) (controlplane.FinOpsBudgetPolicy, error) {
	v, err := controlplane.NormalizeFinOpsBudgetPolicy(in)
	if err != nil {
		return v, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return v, fmt.Errorf("%w: actor is required", controlplane.ErrValidation)
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("fbp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		lockKey := v.OrganizationID + "\x00" + v.ProjectID + "\x00" + v.Currency
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
			return err
		}
		if v.ProjectID != "" {
			var org string
			if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, v.ProjectID).Scan(&org); err != nil {
				return mapDBError(err)
			}
			if org != v.OrganizationID {
				return fmt.Errorf("%w: FinOps budget project is outside organization authority", controlplane.ErrValidation)
			}
		}
		var duplicates int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM finops_budget_policies WHERE organization_id=$1 AND COALESCE(project_id,'')=$2 AND lower(name)=lower($3) AND version=$4`, v.OrganizationID, v.ProjectID, v.Name, v.Version).Scan(&duplicates); err != nil {
			return err
		}
		if duplicates > 0 {
			return controlplane.ErrDuplicateName
		}
		var conflicts int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM finops_budget_policies WHERE organization_id=$1 AND COALESCE(project_id,'')=$2 AND currency=$3 AND effective_from < COALESCE($5::timestamptz,'infinity'::timestamptz) AND $4::timestamptz < COALESCE(effective_until,'infinity'::timestamptz)`, v.OrganizationID, v.ProjectID, v.Currency, v.EffectiveFrom, v.EffectiveUntil).Scan(&conflicts); err != nil {
			return err
		}
		if conflicts > 0 {
			return controlplane.ErrConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO finops_budget_policies(id,organization_id,project_id,revision,authority,name,version,currency,effective_from,effective_until,limit_micros,warning_basis_points,critical_basis_points,digest,created_at,updated_at) VALUES($1,$2,NULLIF($3,''),1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`, v.ID, v.OrganizationID, v.ProjectID, v.Authority, v.Name, v.Version, v.Currency, v.EffectiveFrom, v.EffectiveUntil, v.LimitMicros, v.WarningBasisPoints, v.CriticalBasisPoints, v.Digest, now)
		if err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "finops.budget_policy.created", "finOpsBudgetPolicy", v.ID, 1, "", map[string]any{"organizationId": v.OrganizationID, "projectId": v.ProjectID, "currency": v.Currency, "digest": v.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "finOpsBudgetPolicy", v.ID, "finops.budget_policy.created", v)
	})
	return v, err
}

func (s *PostgresStore) GetFinOpsBudgetPolicy(ctx context.Context, id string) (controlplane.FinOpsBudgetPolicy, error) {
	v, err := scanFinOpsBudget(s.db.QueryRowContext(ctx, `SELECT `+finOpsBudgetColumns+` FROM finops_budget_policies WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListFinOpsBudgetPolicies(ctx context.Context, orgID, projectID string) ([]controlplane.FinOpsBudgetPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+finOpsBudgetColumns+` FROM finops_budget_policies WHERE ($1='' OR organization_id=$1) AND ($2='' OR COALESCE(project_id,'')=$2) ORDER BY effective_from,id`, strings.TrimSpace(orgID), strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.FinOpsBudgetPolicy{}
	for rows.Next() {
		v, e := scanFinOpsBudget(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
