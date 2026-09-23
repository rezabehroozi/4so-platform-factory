package controlplane

import (
	"testing"
	"time"
)

func TestApplicationReleaseSourceCommitProvenanceIsOptionalImmutableDigestMaterial(t *testing.T) {
	base := ApplicationRelease{
		ProjectID:              "prj-1",
		Name:                   "payments",
		Version:                "1.0.0",
		WorkloadTypeDigest:     appDigest('a'),
		TraitDigests:           []string{appDigest('b')},
		ManagedResourceDigests: []string{appDigest('c')},
		WorkspaceProfileDigest: appDigest('d'),
		SourceDigest:           appDigest('e'),
	}
	without, err := NormalizeApplicationRelease(base)
	if err != nil {
		t.Fatal(err)
	}
	committed := time.Date(2026, 9, 1, 12, 30, 0, 0, time.FixedZone("source", 2*60*60))
	base.SourceCommittedAt = &committed
	with, err := NormalizeApplicationRelease(base)
	if err != nil {
		t.Fatal(err)
	}
	if with.SourceCommittedAt == nil || with.SourceCommittedAt.Location() != time.UTC || with.Digest == without.Digest {
		t.Fatalf("source provenance did not become immutable release material: without=%s with=%#v", without.Digest, with)
	}
	zero := time.Time{}
	base.SourceCommittedAt = &zero
	if _, err := NormalizeApplicationRelease(base); err == nil {
		t.Fatal("zero source commit timestamp accepted")
	}
}
