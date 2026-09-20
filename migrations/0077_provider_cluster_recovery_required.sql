BEGIN;

ALTER TABLE provider_clusters
  DROP CONSTRAINT IF EXISTS provider_clusters_state_check;

ALTER TABLE provider_clusters
  ADD CONSTRAINT provider_clusters_state_check
  CHECK (state IN (
    'AWAITING_APPROVAL','QUEUED','APPLYING','RECONCILING','ACTIVE',
    'DELETE_AWAITING_APPROVAL','DELETE_QUEUED','DELETING','DELETED',
    'RECOVERY_REQUIRED','FAILED'
  )) NOT VALID;

ALTER TABLE provider_clusters
  VALIDATE CONSTRAINT provider_clusters_state_check;

COMMIT;
