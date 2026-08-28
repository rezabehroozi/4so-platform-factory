CREATE TYPE runtime_verification_state AS ENUM ('QUEUED','RUNNING','SUCCEEDED','FAILED');

CREATE TABLE runtime_verifications (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
 baseline_deployment_id text NOT NULL REFERENCES baseline_deployments(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 state runtime_verification_state NOT NULL,
 desired_digest text NOT NULL CHECK(desired_digest LIKE 'sha256:%'),
 observed_digest text NOT NULL DEFAULT '',
 probe_image text NOT NULL CHECK(probe_image LIKE '%@sha256:%'),
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 idempotency_key text NOT NULL,
 requested_by text NOT NULL,
 started_at timestamptz,
 finished_at timestamptz,
 checks jsonb NOT NULL DEFAULT '[]'::jsonb,
 report_digest text NOT NULL DEFAULT '',
 last_error text NOT NULL DEFAULT '',
 task_attempt integer NOT NULL DEFAULT 0 CHECK(task_attempt >= 0),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT runtime_verifications_project_idempotency UNIQUE(project_id,idempotency_key)
);
CREATE INDEX runtime_verifications_cluster_state_idx ON runtime_verifications(cluster_id,state,created_at);
CREATE INDEX runtime_verifications_baseline_idx ON runtime_verifications(baseline_deployment_id,created_at);
CREATE UNIQUE INDEX runtime_verifications_one_active_per_baseline
 ON runtime_verifications(baseline_deployment_id)
 WHERE state IN ('QUEUED','RUNNING');
