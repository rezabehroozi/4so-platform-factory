package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const platformPolicySetColumns = `id,project_id,revision,name,version,digest,maintenance,backup,security,created_by,created_at,updated_at`
const platformTemplateColumns = `id,project_id,revision,name,version,digest,blueprint_release_id,blueprint_digest,variable_schema_id,variable_schema_digest,policy_set_id,policy_set_digest,allowed_target_classes,certification_requirements,impact,created_by,created_at,updated_at`

func scanPlatformPolicySet(row interface{ Scan(...any) error }) (controlplane.PlatformPolicySet, error) {
	var v controlplane.PlatformPolicySet
	var maintenance, backup, security []byte
	if err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.Version, &v.Digest, &maintenance, &backup, &security, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if err := json.Unmarshal(maintenance, &v.Maintenance); err != nil {
		return v, fmt.Errorf("decode platform policy maintenance: %w", err)
	}
	if err := json.Unmarshal(backup, &v.Backup); err != nil {
		return v, fmt.Errorf("decode platform policy backup: %w", err)
	}
	if err := json.Unmarshal(security, &v.Security); err != nil {
		return v, fmt.Errorf("decode platform policy security: %w", err)
	}
	return v, nil
}

func scanPlatformTemplate(row interface{ Scan(...any) error }) (controlplane.PlatformTemplate, error) {
	var v controlplane.PlatformTemplate
	var targets, requirements, impact []byte
	if err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.Version, &v.Digest, &v.BlueprintReleaseID, &v.BlueprintDigest, &v.VariableSchemaID, &v.VariableSchemaDigest, &v.PolicySetID, &v.PolicySetDigest, &targets, &requirements, &impact, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	if err := json.Unmarshal(targets, &v.AllowedTargetClasses); err != nil {
		return v, fmt.Errorf("decode platform template targets: %w", err)
	}
	if err := json.Unmarshal(requirements, &v.CertificationRequirements); err != nil {
		return v, fmt.Errorf("decode platform template requirements: %w", err)
	}
	if err := json.Unmarshal(impact, &v.Impact); err != nil {
		return v, fmt.Errorf("decode platform template impact: %w", err)
	}
	return v, nil
}

func (s *PostgresStore) CreatePlatformPolicySet(ctx context.Context, policy controlplane.PlatformPolicySet, actor string) (controlplane.PlatformPolicySet, error) {
	var err error
	policy, err = controlplane.NormalizePlatformPolicySet(policy)
	if err != nil {
		return controlplane.PlatformPolicySet{}, err
	}
	maintenance, _ := json.Marshal(policy.Maintenance)
	backup, _ := json.Marshal(policy.Backup)
	security, _ := json.Marshal(policy.Security)
	now := utcNow(s.now)
	policy.ResourceMeta = controlplane.ResourceMeta{ID: s.id("pps"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	policy.CreatedBy = strings.TrimSpace(actor)
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO platform_policy_sets(id,project_id,revision,name,version,digest,maintenance,backup,security,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$10)`, policy.ID, policy.ProjectID, policy.Name, policy.Version, policy.Digest, maintenance, backup, security, policy.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "platform_policy_set.created", "platformPolicySet", policy.ID, 1, "", map[string]any{"projectId": policy.ProjectID, "name": policy.Name, "version": policy.Version, "digest": policy.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "platformPolicySet", policy.ID, "platform_policy_set.created", policy)
	})
	return policy, err
}

func (s *PostgresStore) GetPlatformPolicySet(ctx context.Context, id string) (controlplane.PlatformPolicySet, error) {
	v, err := scanPlatformPolicySet(s.db.QueryRowContext(ctx, `SELECT `+platformPolicySetColumns+` FROM platform_policy_sets WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListPlatformPolicySets(ctx context.Context, projectID string) ([]controlplane.PlatformPolicySet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+platformPolicySetColumns+` FROM platform_policy_sets WHERE ($1='' OR project_id=$1) ORDER BY lower(name),version,id`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.PlatformPolicySet{}
	for rows.Next() {
		v, err := scanPlatformPolicySet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreatePlatformTemplate(ctx context.Context, template controlplane.PlatformTemplate, actor string) (controlplane.PlatformTemplate, error) {
	projectID := strings.TrimSpace(template.ProjectID)
	now := utcNow(s.now)
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var blueprint controlplane.BlueprintRelease
		if err := tx.QueryRowContext(ctx, `SELECT id,project_id,state,current_blueprint_digest,execution_ready FROM blueprint_releases WHERE id=$1 FOR SHARE`, strings.TrimSpace(template.BlueprintReleaseID)).Scan(&blueprint.ID, &blueprint.ProjectID, &blueprint.State, &blueprint.CurrentBlueprintDigest, &blueprint.ExecutionReady); err != nil {
			return mapDBError(err)
		}
		if blueprint.ProjectID != projectID {
			return controlplane.ErrNotFound
		}
		if blueprint.State != controlplane.BlueprintPublished || !blueprint.ExecutionReady || strings.TrimSpace(blueprint.CurrentBlueprintDigest) == "" {
			return fmt.Errorf("%w: platform template requires a published execution-ready blueprint release", controlplane.ErrValidation)
		}
		var schemaProject, schemaDigest string
		if err := tx.QueryRowContext(ctx, `SELECT project_id,digest FROM variable_schemas WHERE id=$1 FOR SHARE`, strings.TrimSpace(template.VariableSchemaID)).Scan(&schemaProject, &schemaDigest); err != nil {
			return mapDBError(err)
		}
		if schemaProject != projectID {
			return controlplane.ErrNotFound
		}
		var policyProject, policyDigest string
		if err := tx.QueryRowContext(ctx, `SELECT project_id,digest FROM platform_policy_sets WHERE id=$1 FOR SHARE`, strings.TrimSpace(template.PolicySetID)).Scan(&policyProject, &policyDigest); err != nil {
			return mapDBError(err)
		}
		if policyProject != projectID {
			return controlplane.ErrNotFound
		}
		template.BlueprintDigest = blueprint.CurrentBlueprintDigest
		template.VariableSchemaDigest = schemaDigest
		template.PolicySetDigest = policyDigest
		normalized, err := controlplane.NormalizePlatformTemplate(template)
		if err != nil {
			return err
		}
		template = normalized
		template.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ptm"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		template.CreatedBy = strings.TrimSpace(actor)
		targets, _ := json.Marshal(template.AllowedTargetClasses)
		requirements, _ := json.Marshal(template.CertificationRequirements)
		impact, _ := json.Marshal(template.Impact)
		if _, err := tx.ExecContext(ctx, `INSERT INTO platform_templates(id,project_id,revision,name,version,digest,blueprint_release_id,blueprint_digest,variable_schema_id,variable_schema_digest,policy_set_id,policy_set_digest,allowed_target_classes,certification_requirements,impact,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb,$15,$16,$16)`, template.ID, template.ProjectID, template.Name, template.Version, template.Digest, template.BlueprintReleaseID, template.BlueprintDigest, template.VariableSchemaID, template.VariableSchemaDigest, template.PolicySetID, template.PolicySetDigest, targets, requirements, impact, template.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "platform_template.created", "platformTemplate", template.ID, 1, "", map[string]any{"projectId": template.ProjectID, "name": template.Name, "version": template.Version, "digest": template.Digest, "blueprintReleaseId": template.BlueprintReleaseID, "variableSchemaId": template.VariableSchemaID, "policySetId": template.PolicySetID}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "platformTemplate", template.ID, "platform_template.created", template)
	})
	return template, err
}

func (s *PostgresStore) GetPlatformTemplate(ctx context.Context, id string) (controlplane.PlatformTemplate, error) {
	v, err := scanPlatformTemplate(s.db.QueryRowContext(ctx, `SELECT `+platformTemplateColumns+` FROM platform_templates WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListPlatformTemplates(ctx context.Context, projectID string) ([]controlplane.PlatformTemplate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+platformTemplateColumns+` FROM platform_templates WHERE ($1='' OR project_id=$1) ORDER BY lower(name),version,id`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.PlatformTemplate{}
	for rows.Next() {
		v, err := scanPlatformTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
