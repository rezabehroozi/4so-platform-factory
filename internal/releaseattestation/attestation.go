package releaseattestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	AttestationSetAuthority       = "RELEASE_ATTESTATION_SET_AUTHORITY_V1"
	SBOMEvidenceAuthority         = "SBOM_RELEASE_EVIDENCE_V1"
	VEXEvidenceAuthority          = "VEX_RELEASE_EVIDENCE_V1"
	BuildProvenanceAuthority      = "SLSA_BUILD_PROVENANCE_BINDING_V1"
	ExactRuntimeEvidenceAuthority = "EXACT_RUNTIME_EVIDENCE_BINDING_V1"

	StatusPresent            = "PRESENT"
	StatusMissingNotInferred = "MISSING_NOT_INFERRED"
)

type EvidenceKind string

const (
	KindSBOM            EvidenceKind = "SBOM"
	KindVEX             EvidenceKind = "VEX"
	KindBuildProvenance EvidenceKind = "BUILD_PROVENANCE"
	KindExactRuntime    EvidenceKind = "EXACT_RUNTIME"
)

type CertificationLayer string

const (
	LayerSourceBuild      CertificationLayer = "SOURCE_BUILD"
	LayerExactSHAPhysical CertificationLayer = "EXACT_SHA_PHYSICAL_RUNTIME"
)

type ArtifactIdentity struct {
	SourceCommitSHA string `json:"sourceCommitSHA"`
	ReleaseSHA256   string `json:"releaseSHA256"`
	Version         string `json:"version"`
	ReleaseName     string `json:"releaseName"`
}

type EvidenceDocument struct {
	Authority     string             `json:"authority"`
	Kind          EvidenceKind       `json:"kind"`
	Identity      ArtifactIdentity   `json:"identity"`
	PayloadDigest string             `json:"payloadDigest"`
	Layer         CertificationLayer `json:"layer"`
	Present       bool               `json:"present"`
	Executed      bool               `json:"executed,omitempty"`
}

type AttestationSet struct {
	Authority                   string            `json:"authority"`
	Identity                    ArtifactIdentity  `json:"identity"`
	SBOM                        EvidenceDocument  `json:"sbom"`
	VEX                         EvidenceDocument  `json:"vex"`
	BuildProvenance             EvidenceDocument  `json:"buildProvenance"`
	ExactRuntime                *EvidenceDocument `json:"exactRuntime,omitempty"`
	SourceBuildComplete         bool              `json:"sourceBuildComplete"`
	ExactRuntimeEvidencePresent bool              `json:"exactRuntimeEvidencePresent"`
	TrustMaterialDigest         string            `json:"trustMaterialDigest,omitempty"`
	SetDigest                   string            `json:"setDigest"`
	PublicationKey              string            `json:"publicationKey"`
}

type LayerProjection struct {
	Layer       CertificationLayer `json:"layer"`
	Status      string             `json:"status"`
	ClaimedPass bool               `json:"claimedPass"`
	Evidence    []string           `json:"evidence,omitempty"`
}

type AssuranceProjection struct {
	Authority    string           `json:"authority"`
	Identity     ArtifactIdentity `json:"identity"`
	SourceBuild  LayerProjection  `json:"sourceBuild"`
	ExactRuntime LayerProjection  `json:"exactRuntime"`
}

func BuildSet(identity ArtifactIdentity, sbom, vex, provenance EvidenceDocument, runtime *EvidenceDocument) (AttestationSet, error) {
	identity = normalizeIdentity(identity)
	if err := validateIdentity(identity); err != nil {
		return AttestationSet{}, err
	}
	sbom = normalizeDocument(sbom)
	vex = normalizeDocument(vex)
	provenance = normalizeDocument(provenance)
	for _, item := range []struct {
		doc       EvidenceDocument
		authority string
		kind      EvidenceKind
		layer     CertificationLayer
	}{
		{sbom, SBOMEvidenceAuthority, KindSBOM, LayerSourceBuild},
		{vex, VEXEvidenceAuthority, KindVEX, LayerSourceBuild},
		{provenance, BuildProvenanceAuthority, KindBuildProvenance, LayerSourceBuild},
	} {
		if err := validateDocument(item.doc, identity, item.authority, item.kind, item.layer, false); err != nil {
			return AttestationSet{}, err
		}
	}

	var runtimeCopy *EvidenceDocument
	if runtime != nil {
		doc := normalizeDocument(*runtime)
		if err := validateDocument(doc, identity, ExactRuntimeEvidenceAuthority, KindExactRuntime, LayerExactSHAPhysical, true); err != nil {
			return AttestationSet{}, err
		}
		runtimeCopy = &doc
	}

	set := AttestationSet{
		Authority: AttestationSetAuthority,
		Identity: identity,
		SBOM: sbom,
		VEX: vex,
		BuildProvenance: provenance,
		ExactRuntime: runtimeCopy,
		SourceBuildComplete: true,
		ExactRuntimeEvidencePresent: runtimeCopy != nil,
	}
	return reseal(set)
}

func BindShippedTrust(set AttestationSet, trustMaterialDigest string) (AttestationSet, error) {
	trustMaterialDigest = strings.ToLower(strings.TrimSpace(trustMaterialDigest))
	if !isDigest(trustMaterialDigest) {
		return AttestationSet{}, errors.New("shipped trust material digest is required")
	}
	if set.Authority != AttestationSetAuthority || !set.SourceBuildComplete {
		return AttestationSet{}, errors.New("attestation set must be complete before trust binding")
	}
	set.TrustMaterialDigest = trustMaterialDigest
	return reseal(set)
}

func ProjectAssurance(set AttestationSet) AssuranceProjection {
	projection := AssuranceProjection{
		Authority: AttestationSetAuthority,
		Identity: set.Identity,
		SourceBuild: LayerProjection{Layer: LayerSourceBuild, Status: StatusMissingNotInferred},
		ExactRuntime: LayerProjection{Layer: LayerExactSHAPhysical, Status: StatusMissingNotInferred},
	}
	if set.SourceBuildComplete {
		projection.SourceBuild.Status = StatusPresent
		projection.SourceBuild.ClaimedPass = true
		projection.SourceBuild.Evidence = []string{set.SBOM.PayloadDigest, set.VEX.PayloadDigest, set.BuildProvenance.PayloadDigest}
	}
	if set.ExactRuntimeEvidencePresent && set.ExactRuntime != nil {
		projection.ExactRuntime.Status = StatusPresent
		projection.ExactRuntime.ClaimedPass = true
		projection.ExactRuntime.Evidence = []string{set.ExactRuntime.PayloadDigest}
	}
	return projection
}

func VerifyDisconnected(set AttestationSet, expected ArtifactIdentity, shippedTrustMaterialDigest string) error {
	expected = normalizeIdentity(expected)
	shippedTrustMaterialDigest = strings.ToLower(strings.TrimSpace(shippedTrustMaterialDigest))
	if err := validateIdentity(expected); err != nil {
		return err
	}
	if !isDigest(shippedTrustMaterialDigest) {
		return errors.New("shipped trust material digest is required for disconnected verification")
	}
	if !isDigest(set.TrustMaterialDigest) || set.TrustMaterialDigest != shippedTrustMaterialDigest {
		return errors.New("attestation set is not bound to the supplied shipped trust material")
	}
	if set.Authority != AttestationSetAuthority || !identityEqual(set.Identity, expected) {
		return errors.New("attestation set identity does not match expected release")
	}
	if !set.SourceBuildComplete {
		return errors.New("source/build attestation set is incomplete")
	}
	if err := validateDocument(set.SBOM, expected, SBOMEvidenceAuthority, KindSBOM, LayerSourceBuild, false); err != nil { return err }
	if err := validateDocument(set.VEX, expected, VEXEvidenceAuthority, KindVEX, LayerSourceBuild, false); err != nil { return err }
	if err := validateDocument(set.BuildProvenance, expected, BuildProvenanceAuthority, KindBuildProvenance, LayerSourceBuild, false); err != nil { return err }
	if set.ExactRuntimeEvidencePresent {
		if set.ExactRuntime == nil { return errors.New("exact runtime evidence flag is set without evidence") }
		if err := validateDocument(*set.ExactRuntime, expected, ExactRuntimeEvidenceAuthority, KindExactRuntime, LayerExactSHAPhysical, true); err != nil { return err }
	} else if set.ExactRuntime != nil {
		return errors.New("exact runtime evidence must not be attached while marked absent")
	}
	digest, err := attestationDigest(set)
	if err != nil { return err }
	if set.SetDigest != digest || set.PublicationKey != "sha256/"+digest[len("sha256:"):] {
		return errors.New("attestation set content address is invalid")
	}
	return nil
}

func reseal(set AttestationSet) (AttestationSet, error) {
	digest, err := attestationDigest(set)
	if err != nil { return AttestationSet{}, err }
	set.SetDigest = digest
	set.PublicationKey = "sha256/" + digest[len("sha256:"):]
	return set, nil
}

func normalizeDocument(doc EvidenceDocument) EvidenceDocument {
	doc.Identity = normalizeIdentity(doc.Identity)
	doc.PayloadDigest = strings.ToLower(strings.TrimSpace(doc.PayloadDigest))
	return doc
}

func validateDocument(doc EvidenceDocument, identity ArtifactIdentity, authority string, kind EvidenceKind, layer CertificationLayer, requireExecuted bool) error {
	doc = normalizeDocument(doc)
	if doc.Authority != authority || doc.Kind != kind || doc.Layer != layer || !doc.Present || !identityEqual(doc.Identity, identity) || !isDigest(doc.PayloadDigest) {
		return fmt.Errorf("%s evidence is missing or bound to a different release", kind)
	}
	if requireExecuted && !doc.Executed {
		return errors.New("exact runtime evidence cannot exist without direct execution")
	}
	if !requireExecuted && doc.Executed {
		return fmt.Errorf("%s source/build evidence cannot claim runtime execution", kind)
	}
	return nil
}

func validateIdentity(identity ArtifactIdentity) error {
	if !isCommitSHA(identity.SourceCommitSHA) || !isDigest(identity.ReleaseSHA256) || identity.Version == "" || identity.ReleaseName == "" {
		return errors.New("exact artifact identity is incomplete")
	}
	return nil
}

func normalizeIdentity(identity ArtifactIdentity) ArtifactIdentity {
	identity.SourceCommitSHA = strings.ToLower(strings.TrimSpace(identity.SourceCommitSHA))
	identity.ReleaseSHA256 = strings.ToLower(strings.TrimSpace(identity.ReleaseSHA256))
	identity.Version = strings.TrimSpace(identity.Version)
	identity.ReleaseName = strings.TrimSpace(identity.ReleaseName)
	return identity
}

func identityEqual(a, b ArtifactIdentity) bool {
	return normalizeIdentity(a) == normalizeIdentity(b)
}

func attestationDigest(set AttestationSet) (string, error) {
	material := struct {
		Authority                   string            `json:"authority"`
		Identity                    ArtifactIdentity  `json:"identity"`
		SBOM                        EvidenceDocument  `json:"sbom"`
		VEX                         EvidenceDocument  `json:"vex"`
		BuildProvenance             EvidenceDocument  `json:"buildProvenance"`
		ExactRuntime                *EvidenceDocument `json:"exactRuntime,omitempty"`
		SourceBuildComplete         bool              `json:"sourceBuildComplete"`
		ExactRuntimeEvidencePresent bool              `json:"exactRuntimeEvidencePresent"`
		TrustMaterialDigest         string            `json:"trustMaterialDigest,omitempty"`
	}{
		Authority: set.Authority,
		Identity: set.Identity,
		SBOM: set.SBOM,
		VEX: set.VEX,
		BuildProvenance: set.BuildProvenance,
		ExactRuntime: set.ExactRuntime,
		SourceBuildComplete: set.SourceBuildComplete,
		ExactRuntimeEvidencePresent: set.ExactRuntimeEvidencePresent,
		TrustMaterialDigest: set.TrustMaterialDigest,
	}
	raw, err := json.Marshal(material)
	if err != nil { return "", fmt.Errorf("encode release attestation set: %w", err) }
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func isCommitSHA(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 40 { return false }
	for _, r := range value { if !strings.ContainsRune("0123456789abcdef", r) { return false } }
	return true
}

func isDigest(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") { return false }
	for _, r := range value[len("sha256:"):] { if !strings.ContainsRune("0123456789abcdef", r) { return false } }
	return true
}
