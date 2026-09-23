BEGIN;
-- FINOPS_VIRTUAL_CLUSTER_ATTRIBUTION_V1
-- ROLLING_SAFE: nullable attribution is ignored by old writers. New writers
-- bind measured usage to an exact existing virtual-cluster runtime scope.

ALTER TABLE finops_usage_measurements
  ADD COLUMN virtual_cluster_id text REFERENCES virtual_clusters(id) ON DELETE RESTRICT;

CREATE INDEX finops_usage_virtual_cluster_window_idx
  ON finops_usage_measurements(virtual_cluster_id,window_start DESC,id)
  WHERE virtual_cluster_id IS NOT NULL;

CREATE FUNCTION validate_finops_virtual_cluster_scope() RETURNS trigger AS $$
DECLARE vc_project text; vc_workspace text; vc_cluster text; vc_namespace text;
BEGIN
  IF NEW.virtual_cluster_id IS NULL OR NEW.virtual_cluster_id = '' THEN
    RETURN NEW;
  END IF;
  SELECT project_id,workspace_id,host_cluster_id,host_namespace
    INTO vc_project,vc_workspace,vc_cluster,vc_namespace
    FROM virtual_clusters WHERE id=NEW.virtual_cluster_id;
  IF vc_project IS NULL
     OR vc_project <> NEW.project_id
     OR vc_workspace <> NEW.workspace_id
     OR vc_cluster <> NEW.cluster_id
     OR vc_namespace <> NEW.namespace THEN
    RAISE EXCEPTION 'FinOps virtual cluster attribution crosses runtime authority';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER finops_usage_virtual_cluster_scope_guard
  BEFORE INSERT ON finops_usage_measurements
  FOR EACH ROW EXECUTE FUNCTION validate_finops_virtual_cluster_scope();

COMMIT;
