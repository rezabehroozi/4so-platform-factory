-- v50 removed unsafe legacy successor mutation authority when a revoked
-- predecessor for the same physical kube-system UID had not yet been fenced,
-- but PostgreSQL did not mirror FileStore's explicit read-only capability
-- marker. Preserve v50 history/checksum and normalize only those already-
-- inventoried successor generations that predate (or still await) the
-- predecessor acknowledgement. Newly re-enrolled generations created after an
-- acknowledgement are left untouched until their first authoritative inventory
-- establishes read-only or mutation admission normally.
UPDATE managed_clusters successor
SET capabilities = CASE
  WHEN successor.capabilities @> '["target-read-only-admission"]'::jsonb THEN successor.capabilities
  ELSE successor.capabilities || '["target-read-only-admission"]'::jsonb
END
WHERE successor.connection_state <> 'REVOKED'
  AND successor.inventory_digest <> ''
  AND NOT (successor.capabilities @> '["target-mutation-rbac-active"]'::jsonb)
  AND NOT (successor.capabilities @> '["target-mutation-rbac-activation-issued"]'::jsonb)
  AND EXISTS (
    SELECT 1 FROM managed_clusters predecessor
    WHERE predecessor.id <> successor.id
      AND predecessor.connection_state = 'REVOKED'
      AND predecessor.external_uid = successor.external_uid
      AND (
        predecessor.target_rbac_revocation_acknowledged_at IS NULL
        OR successor.created_at <= predecessor.target_rbac_revocation_acknowledged_at
      )
  );
