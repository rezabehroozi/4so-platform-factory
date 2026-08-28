-- Mutation RBAC activation is valid only for the exact non-mutation semantic
-- inventory basis that the control plane authorized. Additive/defaulted columns
-- keep mixed-version writers valid; new binaries fail closed until inventory is
-- refreshed and activation is explicitly issued for its current basis.
ALTER TABLE managed_clusters
  ADD COLUMN IF NOT EXISTS mutation_rbac_basis_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS mutation_rbac_issued_for_digest text NOT NULL DEFAULT '';

ALTER TABLE managed_clusters
  ADD CONSTRAINT managed_clusters_mutation_rbac_basis_digest_shape
    CHECK (mutation_rbac_basis_digest = '' OR mutation_rbac_basis_digest LIKE 'sha256:%'),
  ADD CONSTRAINT managed_clusters_mutation_rbac_issued_digest_shape
    CHECK (mutation_rbac_issued_for_digest = '' OR mutation_rbac_issued_for_digest LIKE 'sha256:%');
