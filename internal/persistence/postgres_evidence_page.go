package persistence

import (
	"context"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

// ListEvidencePageByProject scopes evidence inside PostgreSQL before LIMIT so
// the search hot path does not materialize evidence belonging to other tenants.
func (s *PostgresStore) ListEvidencePageByProject(ctx context.Context, projectID string, limit int) ([]controlplane.EvidenceMetadata, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return []controlplane.EvidenceMetadata{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+evidenceColumns+`
FROM evidence_metadata e
JOIN operations o ON o.id=e.operation_id
WHERE o.project_id=$1
ORDER BY e.updated_at DESC,e.created_at DESC,e.id DESC
LIMIT $2`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.EvidenceMetadata{}
	for rows.Next() {
		value, scanErr := scanEvidence(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

// ListEvidencePageByOperation keeps incident detail evidence bounded and operation-owned.
func (s *PostgresStore) ListEvidencePageByOperation(ctx context.Context, operationID string, limit int) ([]controlplane.EvidenceMetadata, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return []controlplane.EvidenceMetadata{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM operations WHERE id=$1`, operationID).Scan(&exists); err != nil {
		return nil, mapDBError(err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+evidenceColumns+`
FROM evidence_metadata
WHERE operation_id=$1
ORDER BY updated_at DESC,created_at DESC,id DESC
LIMIT $2`, operationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.EvidenceMetadata{}
	for rows.Next() {
		value, scanErr := scanEvidence(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, value)
	}
	return out, rows.Err()
}
