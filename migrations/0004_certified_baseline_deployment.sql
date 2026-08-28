CREATE TYPE baseline_deployment_state AS ENUM (
 'PLANNING','AWAITING_APPROVAL','QUEUED','APPLYING','SUCCEEDED','FAILED',
 'ROLLBACK_QUEUED','ROLLING_BACK','ROLLED_BACK'
);

CREATE TABLE baseline_deployments (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 baseline_id text NOT NULL,
 baseline_version text NOT NULL,
 target_namespace text NOT NULL,
 state baseline_deployment_state NOT NULL,
 risk text NOT NULL CHECK(risk IN ('low','medium','high','critical')),
 desired_digest text NOT NULL CHECK(desired_digest LIKE 'sha256:%'),
 observed_digest text NOT NULL DEFAULT '',
 previous_digest text NOT NULL DEFAULT '',
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 idempotency_key text NOT NULL,
 requested_by text NOT NULL,
 approved_by text NOT NULL DEFAULT '',
 approved_at timestamptz,
 started_at timestamptz,
 finished_at timestamptz,
 plan jsonb NOT NULL DEFAULT '[]'::jsonb,
 last_error text NOT NULL DEFAULT '',
 task_attempt integer NOT NULL DEFAULT 0 CHECK(task_attempt >= 0),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT baseline_deployments_project_idempotency_key UNIQUE(project_id,idempotency_key)
);
CREATE INDEX baseline_deployments_cluster_state_idx ON baseline_deployments(cluster_id,state,created_at);
CREATE UNIQUE INDEX baseline_deployments_active_baseline_key
 ON baseline_deployments(cluster_id,baseline_id)
 WHERE state NOT IN ('FAILED','ROLLED_BACK');
