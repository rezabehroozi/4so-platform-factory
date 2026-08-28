-- 0.0.49: durable platform-published Git revision authority used as the immutable
-- base for external Git / live-state three-way drift classification.
CREATE TABLE IF NOT EXISTS managed_git_revisions (
    id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    organization text NOT NULL,
    repository text NOT NULL,
    branch text NOT NULL DEFAULT 'main',
    revision_id text NOT NULL,
    digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
    commit_sha text NOT NULL,
    public_key_fingerprint text NOT NULL CHECK (public_key_fingerprint LIKE 'sha256:%'),
    source text NOT NULL,
    recorded_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (organization, repository, branch, commit_sha)
);
CREATE INDEX IF NOT EXISTS managed_git_revisions_repo_idx
    ON managed_git_revisions (organization, repository, branch, created_at DESC, id DESC);
