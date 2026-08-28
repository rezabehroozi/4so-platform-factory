//go:build !cgo || !linux

package pgdriver

func Name() string        { return "" }
func Available() bool     { return false }
func Description() string { return "PostgreSQL adapter unavailable: build on Linux with CGO and libpq" }
