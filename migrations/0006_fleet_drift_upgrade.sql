CREATE TYPE drift_scan_state AS ENUM ('QUEUED','RUNNING','IN_SYNC','DRIFTED','FAILED');
CREATE TYPE upgrade_campaign_state AS ENUM ('AWAITING_APPROVAL','QUEUED','RUNNING','HALTED','SUCCEEDED','FAILED');

CREATE TABLE fleet_groups (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 name text NOT NULL,
 display_name text NOT NULL,
 cluster_ids jsonb NOT NULL,
 requested_by text NOT NULL,
 idempotency_key text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT fleet_groups_project_name UNIQUE(project_id,name),
 CONSTRAINT fleet_groups_project_idempotency UNIQUE(project_id,idempotency_key)
);

CREATE TABLE drift_scans (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 fleet_group_id text REFERENCES fleet_groups(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 state drift_scan_state NOT NULL,
 targets jsonb NOT NULL,
 requested_by text NOT NULL,
 idempotency_key text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 started_at timestamptz,
 finished_at timestamptz,
 summary text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT drift_scans_project_idempotency UNIQUE(project_id,idempotency_key)
);
CREATE INDEX drift_scans_project_state_idx ON drift_scans(project_id,state,created_at);

CREATE TABLE upgrade_campaigns (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 fleet_group_id text NOT NULL REFERENCES fleet_groups(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision > 0),
 baseline_id text NOT NULL,
 target_version text NOT NULL,
 state upgrade_campaign_state NOT NULL,
 canary_count integer NOT NULL CHECK(canary_count > 0),
 wave_size integer NOT NULL CHECK(wave_size > 0),
 halt_after_failures integer NOT NULL CHECK(halt_after_failures > 0),
 current_wave integer NOT NULL DEFAULT 0 CHECK(current_wave >= 0),
 targets jsonb NOT NULL,
 requested_by text NOT NULL,
 approved_by text NOT NULL DEFAULT '',
 approved_at timestamptz,
 started_at timestamptz,
 finished_at timestamptz,
 idempotency_key text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest LIKE 'sha256:%'),
 summary text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CONSTRAINT upgrade_campaigns_project_idempotency UNIQUE(project_id,idempotency_key)
);
CREATE INDEX upgrade_campaigns_group_state_idx ON upgrade_campaigns(fleet_group_id,state,created_at);

DROP INDEX IF EXISTS baseline_deployments_active_baseline_key;
CREATE UNIQUE INDEX baseline_deployments_active_baseline_key
 ON baseline_deployments(cluster_id,baseline_id)
 WHERE state IN ('PLANNING','AWAITING_APPROVAL','QUEUED','APPLYING','ROLLBACK_QUEUED','ROLLING_BACK');
