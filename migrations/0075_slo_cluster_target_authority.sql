-- Make SLO error-budget authority explicit about the cluster whose health
-- observations it consumes. The default preserves mixed-version schema
-- compatibility for old writers; new binaries fail closed on an empty target.

ALTER TABLE slo_policies
    ADD COLUMN cluster_id text NOT NULL DEFAULT '';

DROP INDEX slo_policies_project_name_revision_unique;
DROP INDEX slo_policies_project_name_idx;

CREATE UNIQUE INDEX slo_policies_project_cluster_name_revision_unique
    ON slo_policies(project_id, cluster_id, lower(name), revision);
CREATE INDEX slo_policies_project_cluster_name_idx
    ON slo_policies(project_id, cluster_id, lower(name), revision DESC);
