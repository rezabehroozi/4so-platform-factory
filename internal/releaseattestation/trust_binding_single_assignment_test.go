package releaseattestation

import "testing"

func TestBindShippedTrustIsSingleAssignment(t *testing.T) {
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
	bound, err := BindShippedTrust(set, digest('8'))
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := BindShippedTrust(bound, digest('8'))
	if err != nil {
		t.Fatalf("rebinding the same shipped trust digest must be idempotent: %v", err)
	}
	if idempotent.SetDigest != bound.SetDigest || idempotent.PublicationKey != bound.PublicationKey {
		t.Fatalf("same trust binding must preserve the exact content address: before=%#v after=%#v", bound, idempotent)
	}
	if _, err := BindShippedTrust(bound, digest('9')); err == nil {
		t.Fatal("attestation trust material must not be rebound to a different shipped trust digest")
	}
}
