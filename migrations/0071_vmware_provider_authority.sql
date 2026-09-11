-- VMWARE_PROVIDER_AUTHORITY_V1: additive source authority for the first
-- external private-infrastructure provider. Existing provider rows and old
-- writers remain valid as `unspecified`; new binaries admit VMware only with
-- an HTTPS origin and an external-secret reference. Runtime vCenter/CAPV
-- execution remains independently certification-gated.
ALTER TABLE provider_profiles
  ADD COLUMN infrastructure_provider text NOT NULL DEFAULT 'unspecified',
  ADD COLUMN infrastructure_endpoint text NOT NULL DEFAULT '',
  ADD COLUMN credential_ref text NOT NULL DEFAULT '';

ALTER TABLE provider_profiles
  ADD CONSTRAINT provider_profiles_vmware_authority_v1 CHECK (
    (infrastructure_provider = 'unspecified' AND infrastructure_endpoint = '' AND credential_ref = '')
    OR
    (infrastructure_provider = 'vmware'
      AND infrastructure_endpoint ~ '^https://[^/?#@]+/?$'
      AND credential_ref ~ '^external-secret://4so-provider-system/[a-z0-9]([-.a-z0-9]*[a-z0-9])?$')
  );

CREATE INDEX provider_profiles_infrastructure_provider_idx
  ON provider_profiles(infrastructure_provider, state, created_at);
