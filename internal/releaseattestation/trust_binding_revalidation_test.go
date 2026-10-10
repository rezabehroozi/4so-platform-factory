package releaseattestation

import "testing"

func TestBindShippedTrustRejectsTamperedAttestationSet(t *testing.T) {
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
	if _, err := BindShippedTrust(set, digest('8')); err == nil {
		t.Fatal("trust binding must not reseal an attestation set whose sealed content was modified")
	}
}
