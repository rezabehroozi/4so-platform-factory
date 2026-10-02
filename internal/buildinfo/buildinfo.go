package buildinfo

// Version is overridden from the repository VERSION file by release/build entry points.
var Version = "devel"

// SourceCommit is the exact Git commit used to build the binary. Release builds
// must override it with a lowercase 40-character SHA. Development builds may
// leave the sentinel value when no Git authority is available.
var SourceCommit = "unknown"
