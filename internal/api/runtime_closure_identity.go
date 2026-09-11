package api

import (
	"errors"
	"strings"

	"platform.4so.io/factory/internal/evidence"
)

// ConfigureRuntimeClosureReleaseIdentity binds newly-created runtime closure
// campaigns to the exact release artifact that installed this Platform API and
// to the inode bytes of the currently executing platform-api binary. Existing
// legacy campaigns remain readable/verifiable but cannot silently acquire this
// stronger assurance after the fact.
func (s *Server) ConfigureRuntimeClosureReleaseIdentity(releaseArtifactDigest, producerBinaryDigest string) error {
	releaseArtifactDigest = strings.TrimSpace(releaseArtifactDigest)
	producerBinaryDigest = strings.TrimSpace(producerBinaryDigest)
	if !evidence.IsSHA256Digest(releaseArtifactDigest) {
		return errors.New("runtime closure release artifact digest must be a lowercase sha256 digest")
	}
	if !evidence.IsSHA256Digest(producerBinaryDigest) {
		return errors.New("runtime closure producer binary digest must be a lowercase sha256 digest")
	}
	s.runtimeClosureReleaseDigest = releaseArtifactDigest
	s.runtimeClosureProducerDigest = producerBinaryDigest
	return nil
}
