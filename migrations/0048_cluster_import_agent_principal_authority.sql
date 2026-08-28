-- New enrollment manifests use an import-scoped Kubernetes ServiceAccount so a
-- revoked generation's mutation RoleBindings cannot authorize a later
-- re-enrollment. Existing imports keep the empty value and therefore retain the
-- legacy fixed ServiceAccount until they are explicitly re-enrolled.
ALTER TABLE cluster_imports
  ADD COLUMN IF NOT EXISTS agent_service_account text NOT NULL DEFAULT '';
