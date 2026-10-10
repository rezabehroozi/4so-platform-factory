package releaseattestation

import (
	"strings"
	"testing"
)

func TestBuildSetCanonicalizesEquivalentEvidenceDocuments(t *testing.T) {
	identity := ArtifactIdentity{
		SourceCommitSHA: "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
		ReleaseSHA256:   digest('b'),
		Version:         "0.0.1",
		ReleaseName:     "factory",
	}
	canonicalSBOM := EvidenceDocument{Authority: SBOMEvidenceAuthority, Kind: KindSBOM, Identity: identity, PayloadDigest: digest('c'), Layer: LayerSourceBuild, Present: true}
	canonicalVEX := EvidenceDocument{Authority: VEXEvidenceAuthority, Kind: KindVEX, Identity: identity, PayloadDigest: digest('d'), Layer: LayerSourceBuild, Present: true}
	canonicalProvenance := EvidenceDocument{Authority: BuildProvenanceAuthority, Kind: KindBuildProvenance, Identity: identity, PayloadDigest: digest('e'), Layer: LayerSourceBuild, Present: true}

	canonical, err := BuildSet(identity, canonicalSBOM, canonicalVEX, canonicalProvenance, nil)
	if err != nil {
		t.Fatal(err)
	}

	messyIdentity := ArtifactIdentity{
		SourceCommitSHA: "  " + strings.ToUpper(identity.SourceCommitSHA) + "  ",
		ReleaseSHA256:   "  " + strings.ToUpper(identity.ReleaseSHA256) + "  ",
		Version:         "  " + identity.Version + "  ",
		ReleaseName:     "  " + identity.ReleaseName + "  ",
	}
	messySBOM := canonicalSBOM
	messySBOM.Identity = messyIdentity
	messySBOM.PayloadDigest = "  " + strings.ToUpper(canonicalSBOM.PayloadDigest) + "  "
	messyVEX := canonicalVEX
	messyVEX.Identity = messyIdentity
	messyVEX.PayloadDigest = "  " + strings.ToUpper(canonicalVEX.PayloadDigest) + "  "
	messyProvenance := canonicalProvenance
	messyProvenance.Identity = messyIdentity
	messyProvenance.PayloadDigest = "  " + strings.ToUpper(canonicalProvenance.PayloadDigest) + "  "

	messy, err := BuildSet(identity, messySBOM, messyVEX, messyProvenance, nil)
	if err != nil {
		t.Fatal(err)
	}
	if messy.SBOM != canonical.SBOM || messy.VEX != canonical.VEX || messy.BuildProvenance != canonical.BuildProvenance {
		t.Fatalf("semantically equivalent evidence must be stored canonically: canonical=%#v messy=%#v", canonical, messy)
	}
	if messy.SetDigest != canonical.SetDigest || messy.PublicationKey != canonical.PublicationKey {
		t.Fatalf("semantic-equivalent evidence must have one content address: canonical=%s/%s messy=%s/%s", canonical.SetDigest, canonical.PublicationKey, messy.SetDigest, messy.PublicationKey)
	}
}
