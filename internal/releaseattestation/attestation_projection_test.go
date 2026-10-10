package releaseattestation

import "testing"

func TestProjectAssuranceFailsClosedOnTamperedSourceEvidence(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	set, err := BuildSet(identity,
		EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	set.SBOM.PayloadDigest = digest('9')
	projection := ProjectAssurance(set)
	if projection.SourceBuild.Status != StatusMissingNotInferred || projection.SourceBuild.ClaimedPass || len(projection.SourceBuild.Evidence) != 0 {
		t.Fatalf("tampered source evidence must never project PASS: %#v", projection.SourceBuild)
	}
}

func TestProjectAssuranceFailsClosedOnTamperedRuntimeEvidence(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	runtime := EvidenceDocument{Authority: ExactRuntimeEvidenceAuthority, Kind: KindExactRuntime, Identity: identity, PayloadDigest: digest('f'), Layer: LayerExactSHAPhysical, Present: true, Executed: true}
	set, err := BuildSet(identity,
		EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true},
		&runtime,
	)
	if err != nil {
		t.Fatal(err)
	}
	set.ExactRuntime.PayloadDigest = digest('8')
	projection := ProjectAssurance(set)
	if projection.ExactRuntime.Status != StatusMissingNotInferred || projection.ExactRuntime.ClaimedPass || len(projection.ExactRuntime.Evidence) != 0 {
		t.Fatalf("tampered runtime evidence must never project PASS: %#v", projection.ExactRuntime)
	}
}
