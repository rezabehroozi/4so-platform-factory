package releaseattestation

import "testing"

func TestBuildSetKeepsRuntimeEvidenceIndependentAndMissingByDefault(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	set, err := BuildSet(identity,
		EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true},
		nil,
	)
	if err != nil { t.Fatal(err) }
	if set.Authority != AttestationSetAuthority || !set.SourceBuildComplete || set.ExactRuntimeEvidencePresent || set.SetDigest == "" || set.PublicationKey == "" {
		t.Fatalf("unexpected source-only attestation set: %#v", set)
	}
	projection := ProjectAssurance(set)
	if projection.ExactRuntime.Status != StatusMissingNotInferred || projection.ExactRuntime.ClaimedPass {
		t.Fatalf("missing runtime evidence must remain explicitly absent: %#v", projection.ExactRuntime)
	}
}

func TestBuildSetRejectsCrossReleaseEvidenceMixing(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	other := identity
	other.ReleaseSHA256 = digest('f')
	_, err := BuildSet(identity,
		EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: other, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true},
		nil,
	)
	if err == nil {
		t.Fatal("cross-release evidence mixing must be rejected")
	}
}

func TestExactRuntimeEvidenceRequiresExecutedExactPhysicalLayer(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	sbom := EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true}
	vex := EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true}
	provenance := EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true}
	bad := EvidenceDocument{Authority: ExactRuntimeEvidenceAuthority, Kind: KindExactRuntime, Identity: identity, PayloadDigest: digest('f'), Layer: LayerExactSHAPhysical, Present: true, Executed: false}
	if _, err := BuildSet(identity, sbom, vex, provenance, &bad); err == nil {
		t.Fatal("runtime evidence must not exist without direct execution")
	}
	good := bad
	good.Executed = true
	set, err := BuildSet(identity, sbom, vex, provenance, &good)
	if err != nil { t.Fatal(err) }
	if !set.ExactRuntimeEvidencePresent {
		t.Fatalf("direct exact-runtime evidence not represented: %#v", set)
	}
	projection := ProjectAssurance(set)
	if projection.ExactRuntime.Status != StatusPresent || !projection.ExactRuntime.ClaimedPass {
		t.Fatalf("executed exact runtime layer must project independently: %#v", projection.ExactRuntime)
	}
}

func TestDisconnectedVerificationUsesContentAddressAndShippedTrustOnly(t *testing.T) {
	identity := ArtifactIdentity{SourceCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSHA256: digest('b'), Version: "0.0.1", ReleaseName: "factory"}
	set, err := BuildSet(identity,
		EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true},
		EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true},
		nil,
	)
	if err != nil { t.Fatal(err) }
	if err := VerifyDisconnected(set, identity, digest('9')); err != nil {
		t.Fatal(err)
	}
	mutated := set
	mutated.PublicationKey = "sha256/" + digest('8')[7:]
	if err := VerifyDisconnected(mutated, identity, digest('9')); err == nil {
		t.Fatal("tampered content-address publication key must be rejected")
	}
	if err := VerifyDisconnected(set, identity, ""); err == nil {
		t.Fatal("shipped trust material digest is required")
	}
}

func digest(ch byte) string {
	buf := make([]byte, 64)
	for i := range buf { buf[i] = ch }
	return "sha256:" + string(buf)
}
