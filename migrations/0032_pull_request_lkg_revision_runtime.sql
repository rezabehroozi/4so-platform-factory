-- 0.0.65: durable pull-request delivery and last-known-good revision authority.
CREATE TABLE IF NOT EXISTS git_pull_requests (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  organization text NOT NULL,
  repository text NOT NULL,
  base_branch text NOT NULL DEFAULT 'main',
  head_branch text NOT NULL,
  revision_id text NOT NULL,
  digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
  public_key_fingerprint text NOT NULL CHECK (public_key_fingerprint LIKE 'sha256:%'),
  external_number bigint NOT NULL CHECK (external_number > 0),
  external_url text NOT NULL DEFAULT '',
  state text NOT NULL CHECK (state IN ('OPEN','APPROVED','MERGED','CLOSED')),
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  merged_by text NOT NULL DEFAULT '',
  merged_at timestamptz,
  merged_commit_sha text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (organization, repository, external_number),
  UNIQUE (organization, repository, revision_id)
);
CREATE INDEX IF NOT EXISTS git_pull_requests_repo_state_idx
  ON git_pull_requests (organization, repository, state, created_at DESC);

ALTER TABLE managed_git_revisions
  ADD COLUMN IF NOT EXISTS delivery_mode text NOT NULL DEFAULT 'DIRECT_COMMIT'
    CHECK (delivery_mode IN ('DIRECT_COMMIT','PULL_REQUEST')),
  ADD COLUMN IF NOT EXISTS pull_request_id text REFERENCES git_pull_requests(id),
  ADD COLUMN IF NOT EXISTS sync_healthy boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS observed_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS last_known_good boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS last_known_good_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS managed_git_revisions_single_lkg_idx
  ON managed_git_revisions (organization, repository, branch)
  WHERE last_known_good=true;
