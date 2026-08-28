ALTER TABLE baseline_deployments
 ADD COLUMN IF NOT EXISTS pending_action text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS source_type text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS source_id text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS source_version text NOT NULL DEFAULT '';

UPDATE baseline_deployments
SET pending_action = CASE
 WHEN state = 'PLANNING' THEN 'PLAN'
 WHEN state IN ('QUEUED','APPLYING') THEN 'APPLY'
 WHEN state IN ('ROLLBACK_QUEUED','ROLLING_BACK') THEN 'ROLLBACK'
 ELSE pending_action
END
WHERE pending_action = '';

ALTER TABLE baseline_deployments
 ADD CONSTRAINT baseline_deployments_pending_action_check
 CHECK (pending_action IN ('','PLAN','APPLY','ROLLBACK'));

ALTER TABLE baseline_deployments
 ADD CONSTRAINT baseline_deployments_source_identity_check
 CHECK (
   (source_type = '' AND source_id = '' AND source_version = '') OR
   (source_type = 'marketplace' AND source_id <> '' AND source_version <> '')
 );

CREATE TABLE marketplace_recommendations (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 objective text NOT NULL CHECK(length(objective) BETWEEN 1 AND 1000),
 engine text NOT NULL CHECK(engine IN ('policy','model')),
 model text NOT NULL DEFAULT '',
 context_digest text NOT NULL CHECK(context_digest LIKE 'sha256:%'),
 response_digest text NOT NULL CHECK(response_digest LIKE 'sha256:%'),
 items jsonb NOT NULL DEFAULT '[]'::jsonb,
 requested_by text NOT NULL,
 idempotency_key text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT marketplace_recommendations_project_idempotency UNIQUE(project_id,idempotency_key),
 CONSTRAINT marketplace_recommendations_model_check CHECK(engine <> 'model' OR model <> '')
);
CREATE INDEX marketplace_recommendations_project_cluster_idx ON marketplace_recommendations(project_id,cluster_id,created_at);
