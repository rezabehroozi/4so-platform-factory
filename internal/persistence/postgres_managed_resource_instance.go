package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const managedResourceInstanceColumns = `id,project_id,revision,type_id,type_digest,name,input_digest,plan_digest,dependency_instance_ids,state,outputs_digest,observed_digest,last_evidence_digest,last_error,created_at,updated_at`

type managedResourceInstanceScanner interface{ Scan(...any) error }

func scanManagedResourceInstance(scanner managedResourceInstanceScanner) (controlplane.ManagedResourceInstance, error) {
	var v controlplane.ManagedResourceInstance
	var dependenciesRaw []byte
	if err := scanner.Scan(
		&v.ID, &v.ProjectID, &v.Revision, &v.TypeID, &v.TypeDigest, &v.Name, &v.InputDigest, &v.PlanDigest,
		&dependenciesRaw, &v.State, &v.OutputsDigest, &v.ObservedDigest, &v.LastEvidenceDigest, &v.LastError, &v.CreatedAt, &v.UpdatedAt,
	); err != nil {
		return v, mapDBError(err)
	}
	v.Authority = controlplane.ManagedResourceInstanceAuthority
	if len(dependenciesRaw) > 0 {
		if err := json.Unmarshal(dependenciesRaw, &v.DependencyInstanceIDs); err != nil {
			return controlplane.ManagedResourceInstance{}, fmt.Errorf("decode managed resource dependency ids: %w", err)
		}
	}
	return v, nil
}

func (s *PostgresStore) CreateManagedResourceInstance(ctx context.Context, plan controlplane.ManagedResourcePlan, actor string) (controlplane.ManagedResourceInstance, error) {
	resourceType, err := s.GetManagedResourceType(ctx, strings.TrimSpace(plan.TypeID))
	if err != nil {
		return controlplane.ManagedResourceInstance{}, err
	}
	if resourceType.ProjectID != strings.TrimSpace(plan.ProjectID) || resourceType.Digest != strings.TrimSpace(plan.TypeDigest) {
		return controlplane.ManagedResourceInstance{}, fmt.Errorf("%w: managed resource plan type authority is stale or cross-project", controlplane.ErrValidation)
	}
	dependencies := make([]controlplane.ManagedResourceInstance, 0, len(plan.DependencyInstanceIDs))
	for _, id := range plan.DependencyInstanceIDs {
		dep, err := s.GetManagedResourceInstance(ctx, id)
		if err != nil {
			return controlplane.ManagedResourceInstance{}, err
		}
		dependencies = append(dependencies, dep)
	}
	rebuilt, err := controlplane.BuildManagedResourcePlan(resourceType, controlplane.ManagedResourceRequest{
		ProjectID: plan.ProjectID,
		TypeID: plan.TypeID,
		Name: plan.Name,
		InputDigest: plan.InputDigest,
		DependencyInstanceIDs: append([]string(nil), plan.DependencyInstanceIDs...),
	}, dependencies)
	if err != nil {
		return controlplane.ManagedResourceInstance{}, err
	}
	if rebuilt.PlanDigest != strings.TrimSpace(plan.PlanDigest) {
		return controlplane.ManagedResourceInstance{}, fmt.Errorf("%w: managed resource plan digest is stale", controlplane.ErrValidation)
	}

	now := utcNow(s.now)
	v := controlplane.ManagedResourceInstance{
		ResourceMeta: controlplane.ResourceMeta{ID: s.id("mri"), Revision: 1, CreatedAt: now, UpdatedAt: now},
		Authority: controlplane.ManagedResourceInstanceAuthority,
		ProjectID: rebuilt.ProjectID,
		TypeID: rebuilt.TypeID,
		TypeDigest: rebuilt.TypeDigest,
		Name: rebuilt.Name,
		InputDigest: rebuilt.InputDigest,
		PlanDigest: rebuilt.PlanDigest,
		DependencyInstanceIDs: append([]string(nil), rebuilt.DependencyInstanceIDs...),
		State: controlplane.ManagedResourceRequested,
	}
	dependenciesRaw, err := json.Marshal(v.DependencyInstanceIDs)
	if err != nil {
		return controlplane.ManagedResourceInstance{}, err
	}
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var projectID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM projects WHERE id=$1 FOR SHARE`, v.ProjectID).Scan(&projectID); err != nil {
			return mapDBError(err)
		}
		var kind, typeDigest string
		if err := tx.QueryRowContext(ctx, `SELECT kind,digest FROM application_platform_authorities WHERE id=$1 AND project_id=$2 FOR SHARE`, v.TypeID, v.ProjectID).Scan(&kind, &typeDigest); err != nil {
			return mapDBError(err)
		}
		if kind != "MANAGED_RESOURCE_TYPE" || typeDigest != v.TypeDigest {
			return fmt.Errorf("%w: managed resource type authority changed before persistence", controlplane.ErrConflict)
		}
		for _, snapshot := range rebuilt.DependencySnapshots {
			var revision int64
			var state controlplane.ManagedResourceState
			var observedDigest string
			if err := tx.QueryRowContext(ctx, `SELECT revision,state,observed_digest FROM application_managed_resource_instances WHERE id=$1 AND project_id=$2 FOR SHARE`, snapshot.InstanceID, v.ProjectID).Scan(&revision, &state, &observedDigest); err != nil {
				return mapDBError(err)
			}
			if revision != snapshot.Revision || state != controlplane.ManagedResourceReady || observedDigest != snapshot.ObservedDigest {
				return fmt.Errorf("%w: managed resource dependency changed after planning", controlplane.ErrConflict)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO application_managed_resource_instances(
			id,project_id,revision,type_id,type_digest,name,input_digest,plan_digest,dependency_instance_ids,state,created_by,created_at,updated_at
		) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$11)`,
			v.ID, v.ProjectID, v.TypeID, v.TypeDigest, v.Name, v.InputDigest, v.PlanDigest, dependenciesRaw, v.State, strings.TrimSpace(actor), now,
		); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "managed_resource_instance.requested", "managedResourceInstance", v.ID, v.Revision, "", map[string]any{
			"projectId": v.ProjectID, "typeId": v.TypeID, "typeDigest": v.TypeDigest, "planDigest": v.PlanDigest,
		}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "managedResourceInstance", v.ID, "managed_resource_instance.requested", v)
	})
	if err != nil {
		return controlplane.ManagedResourceInstance{}, err
	}
	return v, nil
}

func (s *PostgresStore) GetManagedResourceInstance(ctx context.Context, id string) (controlplane.ManagedResourceInstance, error) {
	return scanManagedResourceInstance(s.db.QueryRowContext(ctx, `SELECT `+managedResourceInstanceColumns+` FROM application_managed_resource_instances WHERE id=$1`, strings.TrimSpace(id)))
}

func (s *PostgresStore) ListManagedResourceInstances(ctx context.Context, projectID string) ([]controlplane.ManagedResourceInstance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+managedResourceInstanceColumns+` FROM application_managed_resource_instances WHERE ($1='' OR project_id=$1) ORDER BY lower(name),id`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	out := []controlplane.ManagedResourceInstance{}
	for rows.Next() {
		v, err := scanManagedResourceInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, mapDBError(err)
	}
	return out, nil
}
