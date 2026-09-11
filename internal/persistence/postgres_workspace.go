package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const workspaceColumns = `id,project_id,revision,name,display_name,description,digest,created_by,created_at,updated_at`
const workspaceBindingColumns = `id,workspace_id,project_id,cluster_id,namespace,state,revision,created_by,revoked_by,revoked_at,created_at,updated_at`

func scanWorkspace(row interface{ Scan(...any) error }) (controlplane.Workspace, error) {
	var v controlplane.Workspace
	err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.DisplayName, &v.Description, &v.Digest, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func scanWorkspaceBinding(row interface{ Scan(...any) error }) (controlplane.WorkspaceBinding, error) {
	var v controlplane.WorkspaceBinding
	var revokedBy sql.NullString
	var revokedAt sql.NullTime
	if err := row.Scan(&v.ID, &v.WorkspaceID, &v.ProjectID, &v.ClusterID, &v.Namespace, &v.State, &v.Revision, &v.CreatedBy, &revokedBy, &revokedAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if revokedBy.Valid {
		v.RevokedBy = revokedBy.String
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		v.RevokedAt = &t
	}
	return v, nil
}

func (s *PostgresStore) CreateWorkspace(ctx context.Context, workspace controlplane.Workspace, actor string) (controlplane.Workspace, error) {
	var err error
	workspace, err = controlplane.NormalizeWorkspace(workspace)
	if err != nil {
		return controlplane.Workspace{}, err
	}
	now := utcNow(s.now)
	workspace.ResourceMeta = controlplane.ResourceMeta{ID: s.id("wsp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	workspace.CreatedBy = strings.TrimSpace(actor)
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, workspace.ProjectID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return controlplane.ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO workspaces(id,project_id,revision,name,display_name,description,digest,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$8)`, workspace.ID, workspace.ProjectID, workspace.Name, workspace.DisplayName, workspace.Description, workspace.Digest, workspace.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "workspace.created", "workspace", workspace.ID, 1, "", map[string]any{"projectId": workspace.ProjectID, "name": workspace.Name, "digest": workspace.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "workspace", workspace.ID, "workspace.created", workspace)
	})
	return workspace, err
}

func (s *PostgresStore) GetWorkspace(ctx context.Context, id string) (controlplane.Workspace, error) {
	v, err := scanWorkspace(s.db.QueryRowContext(ctx, `SELECT `+workspaceColumns+` FROM workspaces WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListWorkspaces(ctx context.Context, projectID string) ([]controlplane.Workspace, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workspaceColumns+` FROM workspaces WHERE ($1='' OR project_id=$1) ORDER BY lower(name),id`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.Workspace{}
	for rows.Next() {
		v, err := scanWorkspace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateWorkspaceBinding(ctx context.Context, binding controlplane.WorkspaceBinding, actor string) (controlplane.WorkspaceBinding, error) {
	now := utcNow(s.now)
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var workspaceProject string
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM workspaces WHERE id=$1 FOR SHARE`, strings.TrimSpace(binding.WorkspaceID)).Scan(&workspaceProject); err != nil {
			return mapDBError(err)
		}
		var clusterProject string
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1 FOR SHARE`, strings.TrimSpace(binding.ClusterID)).Scan(&clusterProject); err != nil {
			return mapDBError(err)
		}
		if workspaceProject != clusterProject {
			return controlplane.ErrNotFound
		}
		binding.ProjectID = workspaceProject
		binding.State = controlplane.WorkspaceBindingActive
		binding.CreatedBy = strings.TrimSpace(actor)
		var err error
		binding, err = controlplane.NormalizeWorkspaceBinding(binding)
		if err != nil {
			return err
		}
		binding.ResourceMeta = controlplane.ResourceMeta{ID: s.id("wsb"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		if _, err := tx.ExecContext(ctx, `INSERT INTO workspace_bindings(id,workspace_id,project_id,cluster_id,namespace,state,revision,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'ACTIVE',1,$6,$7,$7)`, binding.ID, binding.WorkspaceID, binding.ProjectID, binding.ClusterID, binding.Namespace, binding.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "workspace_binding.created", "workspaceBinding", binding.ID, 1, "", map[string]any{"workspaceId": binding.WorkspaceID, "projectId": binding.ProjectID, "clusterId": binding.ClusterID, "namespace": binding.Namespace}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "workspaceBinding", binding.ID, "workspace_binding.created", binding)
	})
	return binding, err
}

func (s *PostgresStore) GetWorkspaceBinding(ctx context.Context, id string) (controlplane.WorkspaceBinding, error) {
	v, err := scanWorkspaceBinding(s.db.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListWorkspaceBindings(ctx context.Context, workspaceID string) ([]controlplane.WorkspaceBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE ($1='' OR workspace_id=$1) ORDER BY cluster_id,lower(namespace),id`, strings.TrimSpace(workspaceID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.WorkspaceBinding{}
	for rows.Next() {
		v, err := scanWorkspaceBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeWorkspaceBinding(ctx context.Context, id string, expectedRevision int64, actor string) (controlplane.WorkspaceBinding, error) {
	var out controlplane.WorkspaceBinding
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanWorkspaceBinding(tx.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expectedRevision {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.WorkspaceBindingActive {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		actor = strings.TrimSpace(actor)
		row := tx.QueryRowContext(ctx, `UPDATE workspace_bindings SET state='REVOKED',revision=revision+1,revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE id=$1 AND revision=$2 RETURNING `+workspaceBindingColumns, current.ID, expectedRevision, actor, now)
		out, err = scanWorkspaceBinding(row)
		if err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "workspace_binding.revoked", "workspaceBinding", out.ID, out.Revision, "", map[string]any{"workspaceId": out.WorkspaceID, "projectId": out.ProjectID, "clusterId": out.ClusterID, "namespace": out.Namespace}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "workspaceBinding", out.ID, "workspace_binding.revoked", out)
	})
	if err != nil {
		return controlplane.WorkspaceBinding{}, fmt.Errorf("revoke workspace binding: %w", err)
	}
	return out, nil
}
