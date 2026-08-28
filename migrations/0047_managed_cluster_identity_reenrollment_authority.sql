-- A physical Kubernetes cluster may have only one active managed-cluster authority,
-- while a fully revoked historical registration must not permanently block explicit
-- re-enrollment of the same kube-system UID.
ALTER TABLE managed_clusters
  DROP CONSTRAINT IF EXISTS managed_clusters_external_uid_key;

CREATE UNIQUE INDEX managed_clusters_active_external_uid_key
  ON managed_clusters(external_uid)
  WHERE connection_state <> 'REVOKED';
