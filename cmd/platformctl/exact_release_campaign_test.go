package main

import (
	"strings"
	"testing"

	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/releaseartifact"
)

func TestFieldCampaignPlatformctlContinuityBinding(t *testing.T) {
	actual, err := releaseartifact.RunningExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	campaign := fieldcampaign.Campaign{SchemaVersion: fieldcampaign.SchemaVersion, PlatformctlBinaryDigest: actual}
	bound, err := verifyRunningPlatformctlForFieldCampaign(campaign)
	if err != nil {
		t.Fatal(err)
	}
	if bound != actual {
		t.Fatalf("bound digest=%q actual=%q", bound, actual)
	}
	campaign.PlatformctlBinaryDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err = verifyRunningPlatformctlForFieldCampaign(campaign); err == nil || !strings.Contains(err.Error(), "does not match prepared campaign") {
		t.Fatalf("mismatched running binary accepted: %v", err)
	}
}

func TestLegacyFieldCampaignDoesNotRequireCurrentBinaryBinding(t *testing.T) {
	campaign := fieldcampaign.Campaign{SchemaVersion: fieldcampaign.PrePlatformctlBindingSchemaVersion}
	bound, err := verifyRunningPlatformctlForFieldCampaign(campaign)
	if err != nil {
		t.Fatal(err)
	}
	if bound != "" {
		t.Fatalf("legacy campaign unexpectedly bound to %q", bound)
	}
}
