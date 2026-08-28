package gitops

import "regexp"

var fullCommitSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$`)

// IsFullCommitSHA reports whether value is an immutable full Git object ID.
// SHA-1 repositories use 40 hexadecimal characters; SHA-256 repositories use 64.
func IsFullCommitSHA(value string) bool {
	return fullCommitSHA.MatchString(value)
}
