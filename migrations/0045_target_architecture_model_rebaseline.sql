-- TARGET_ARCHITECTURE_MODEL_V1: distribution identity is independent from
-- provisioning history/adapter. Existing mutable provider profiles are
-- canonicalized without rewriting immutable blueprint/catalog release history.
ALTER TABLE provider_profiles
  ALTER COLUMN distribution_profiles SET DEFAULT '["kubernetes"]'::jsonb;

UPDATE provider_profiles AS p
SET distribution_profiles = (
  SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb)
  FROM (
    SELECT DISTINCT CASE item
      WHEN 'generic-imported' THEN 'kubernetes'
      WHEN 'kubespray' THEN 'kubernetes'
      WHEN 'upstream-kubernetes' THEN 'kubernetes'
      ELSE lower(item)
    END AS value
    FROM jsonb_array_elements_text(p.distribution_profiles) AS item
  ) canonical
)
WHERE p.distribution_profiles ? 'generic-imported'
   OR p.distribution_profiles ? 'kubespray'
   OR p.distribution_profiles ? 'upstream-kubernetes';
