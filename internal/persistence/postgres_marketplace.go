package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"platform.4so.io/factory/internal/controlplane"
)

const marketplaceRecommendationColumns = `id,project_id,cluster_id,revision,objective,engine,model,context_digest,response_digest,items,requested_by,idempotency_key,request_digest,created_at,updated_at`

func scanMarketplaceRecommendation(row interface{ Scan(...any) error }) (controlplane.MarketplaceRecommendation, error) {
	var v controlplane.MarketplaceRecommendation
	var items []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.Objective, &v.Engine, &v.Model, &v.ContextDigest, &v.ResponseDigest, &items, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.CreatedAt, &v.UpdatedAt)
	if len(items) > 0 {
		if decodeErr := decodeJSONColumn(items, &v.Items, "postgres_marketplace.Items"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func (s *PostgresStore) CreateMarketplaceRecommendation(ctx context.Context, v controlplane.MarketplaceRecommendation, actor string) (controlplane.MarketplaceRecommendation, bool, error) {
	if err := controlplane.ValidateMarketplaceRecommendation(&v); err != nil {
		return controlplane.MarketplaceRecommendation{}, false, err
	}
	var out controlplane.MarketplaceRecommendation
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanMarketplaceRecommendation(tx.QueryRowContext(ctx, `SELECT `+marketplaceRecommendationColumns+` FROM marketplace_recommendations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out, replay = existing, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		var clusterProject string
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, v.ClusterID).Scan(&clusterProject); e != nil {
			return mapDBError(e)
		}
		if clusterProject != v.ProjectID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("mrc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.RequestedBy = actor
		items, _ := json.Marshal(v.Items)
		_, e = tx.ExecContext(ctx, `INSERT INTO marketplace_recommendations(id,project_id,cluster_id,revision,objective,engine,model,context_digest,response_digest,items,requested_by,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$13)`, v.ID, v.ProjectID, v.ClusterID, v.Objective, v.Engine, v.Model, v.ContextDigest, v.ResponseDigest, items, actor, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "marketplace_recommendation.created", "marketplaceRecommendation", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "engine": v.Engine, "itemCount": len(v.Items)}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "marketplaceRecommendation", v.ID, "marketplace_recommendation.created", v)
	})
	return out, replay, err
}

func (s *PostgresStore) GetMarketplaceRecommendation(ctx context.Context, id string) (controlplane.MarketplaceRecommendation, error) {
	v, err := scanMarketplaceRecommendation(s.db.QueryRowContext(ctx, `SELECT `+marketplaceRecommendationColumns+` FROM marketplace_recommendations WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) GetMarketplaceRecommendationByIdempotencyKey(ctx context.Context, projectID, key string) (controlplane.MarketplaceRecommendation, error) {
	v, err := scanMarketplaceRecommendation(s.db.QueryRowContext(ctx, `SELECT `+marketplaceRecommendationColumns+` FROM marketplace_recommendations WHERE project_id=$1 AND idempotency_key=$2`, projectID, key))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListMarketplaceRecommendations(ctx context.Context, projectID, clusterID string) ([]controlplane.MarketplaceRecommendation, error) {
	q := `SELECT ` + marketplaceRecommendationColumns + ` FROM marketplace_recommendations WHERE 1=1`
	args := []any{}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if clusterID != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.MarketplaceRecommendation{}
	for rows.Next() {
		v, err := scanMarketplaceRecommendation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
