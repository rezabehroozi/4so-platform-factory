package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const variableSchemaColumns = `id,project_id,revision,name,version,digest,variables,created_by,created_at,updated_at`

func scanVariableSchema(row interface{ Scan(...any) error }) (controlplane.VariableSchema, error) {
	var v controlplane.VariableSchema
	var raw []byte
	if err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.Version, &v.Digest, &raw, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v.Variables); err != nil {
		return v, fmt.Errorf("decode variable schema variables: %w", err)
	}
	return v, nil
}

func (s *PostgresStore) CreateVariableSchema(ctx context.Context, schema controlplane.VariableSchema, actor string) (controlplane.VariableSchema, error) {
	var err error
	schema, err = controlplane.NormalizeVariableSchema(schema)
	if err != nil {
		return controlplane.VariableSchema{}, err
	}
	variables, err := json.Marshal(schema.Variables)
	if err != nil {
		return controlplane.VariableSchema{}, err
	}
	now := utcNow(s.now)
	schema.ResourceMeta = controlplane.ResourceMeta{ID: s.id("vsc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	schema.CreatedBy = strings.TrimSpace(actor)
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO variable_schemas(id,project_id,revision,name,version,digest,variables,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6::jsonb,$7,$8,$8)`, schema.ID, schema.ProjectID, schema.Name, schema.Version, schema.Digest, variables, schema.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "variable_schema.created", "variableSchema", schema.ID, 1, "", map[string]any{"projectId": schema.ProjectID, "name": schema.Name, "version": schema.Version, "digest": schema.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "variableSchema", schema.ID, "variable_schema.created", schema)
	})
	return schema, err
}

func (s *PostgresStore) GetVariableSchema(ctx context.Context, id string) (controlplane.VariableSchema, error) {
	v, err := scanVariableSchema(s.db.QueryRowContext(ctx, `SELECT `+variableSchemaColumns+` FROM variable_schemas WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListVariableSchemas(ctx context.Context, projectID string) ([]controlplane.VariableSchema, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+variableSchemaColumns+` FROM variable_schemas WHERE ($1='' OR project_id=$1) ORDER BY lower(name),version,id`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.VariableSchema{}
	for rows.Next() {
		v, err := scanVariableSchema(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
