package main

import (
	"fmt"

	"platform.4so.io/factory/internal/evidence"
	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/releaseartifact"
)

const fieldCampaignPlatformctlBindingAuthority = "FIELD_CAMPAIGN_PLATFORMCTL_CONTINUITY_AUTHORITY_V1"

func bindRunningPlatformctlToExactRelease(release releaseartifact.Inspection) string {
	digest, err := release.RequireRunningExecutable(releaseartifact.PlatformctlBinaryPath)
	if err != nil {
		fatal(fmt.Errorf("bind running platformctl to exact release: %w", err))
	}
	return digest
}

func verifyRunningPlatformctlForFieldCampaign(campaign fieldcampaign.Campaign) (string, error) {
	if campaign.SchemaVersion < fieldcampaign.PlatformctlBindingSchemaVersion {
		return "", nil
	}
	actual, err := releaseartifact.RunningExecutableDigest()
	if err != nil {
		return "", fmt.Errorf("bind running platformctl to field campaign: %w", err)
	}
	if actual != campaign.PlatformctlBinaryDigest {
		return "", fmt.Errorf("bind running platformctl to field campaign: running executable digest %s does not match prepared campaign platformctl digest %s", actual, campaign.PlatformctlBinaryDigest)
	}
	return actual, nil
}

func bindRunningPlatformctlToFieldCampaign(campaign fieldcampaign.Campaign) string {
	digest, err := verifyRunningPlatformctlForFieldCampaign(campaign)
	if err != nil {
		fatal(err)
	}
	return digest
}

func verifyRuntimeClosureExactRelease(result evidence.RuntimeClosureVerification, release releaseartifact.Inspection) error {
	if !result.Valid {
		return fmt.Errorf("runtime closure report is not independently valid")
	}
	if !result.ExactReleaseBound || result.EvidenceSchemaVersion != evidence.RuntimeClosureEvidenceSchema {
		return fmt.Errorf("runtime closure report is legacy and is not exact-release-bound")
	}
	if result.ProductVersion != release.Version {
		return fmt.Errorf("runtime closure product version %s does not match exact release version %s", result.ProductVersion, release.Version)
	}
	if result.ReleaseArtifactDigest != release.Digest {
		return fmt.Errorf("runtime closure release artifact digest %s does not match exact release digest %s", result.ReleaseArtifactDigest, release.Digest)
	}
	expectedProducer, err := release.FileDigest(releaseartifact.PlatformAPIBinaryPath)
	if err != nil {
		return fmt.Errorf("resolve exact release platform-api digest: %w", err)
	}
	if result.ProducerBinaryDigest != expectedProducer {
		return fmt.Errorf("runtime closure producer binary digest %s does not match exact release platform-api digest %s", result.ProducerBinaryDigest, expectedProducer)
	}
	return nil
}
