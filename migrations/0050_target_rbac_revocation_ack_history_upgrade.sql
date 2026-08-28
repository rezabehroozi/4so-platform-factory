-- Crossing this migration requires old writers to be quiesced. It introduces
-- digest-bound acknowledgement for target-local RBAC revocation and repairs
-- legacy successor registrations that could have been created before the
-- predecessor fence was acknowledged.
ALTER TABLE managed_clusters
  ADD COLUMN IF NOT EXISTS target_rbac_revocation_ack_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS target_rbac_revocation_acknowledged_at timestamptz,
  ADD COLUMN IF NOT EXISTS target_rbac_revocation_acknowledged_by text NOT NULL DEFAULT '';

ALTER TABLE managed_clusters
  ADD CONSTRAINT managed_clusters_target_rbac_revocation_ack_digest_shape
    CHECK (target_rbac_revocation_ack_digest = '' OR target_rbac_revocation_ack_digest LIKE 'sha256:%');

-- Reconstruct sticky mutation-RBAC history from the immutable authorization
-- audit. Current capability state may have been cleared by later authority
-- drift even though target-local RoleBindings still exist.
UPDATE managed_clusters mc
SET capabilities = CASE
  WHEN mc.capabilities @> '["target-mutation-rbac-ever-issued"]'::jsonb THEN mc.capabilities
  ELSE mc.capabilities || '["target-mutation-rbac-ever-issued"]'::jsonb
END
WHERE EXISTS (
  SELECT 1 FROM audit_events a
  WHERE a.resource_type = 'managedCluster'
    AND a.resource_id = mc.id
    AND a.action = 'cluster.mutation_rbac_activation.authorized'
);

-- Fail closed any legacy successor that reused a physical UID before the
-- predecessor's target-side RBAC fence could be acknowledged. A fresh
-- inventory remains observable, but mutation issuance/proof must be re-done
-- after the predecessor acknowledgement is recorded by the new binary.
UPDATE managed_clusters successor
SET capabilities = (successor.capabilities - 'target-mutation-rbac-active') - 'target-mutation-rbac-activation-issued',
    mutation_rbac_issued_for_digest = ''
WHERE successor.connection_state <> 'REVOKED'
  AND EXISTS (
    SELECT 1 FROM managed_clusters predecessor
    WHERE predecessor.id <> successor.id
      AND predecessor.connection_state = 'REVOKED'
      AND predecessor.external_uid = successor.external_uid
      AND predecessor.target_rbac_revocation_ack_digest = ''
  );
