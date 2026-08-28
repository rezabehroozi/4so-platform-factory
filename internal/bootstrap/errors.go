package bootstrap

import "errors"

// Stable conflict categories let API adapters distinguish invalid operator input
// from an otherwise-valid mutation that is fenced by durable bootstrap authority.
var (
	ErrBootstrapExecutionActive = errors.New("bootstrap execution is active")
	ErrPreflightEvidenceOwned   = errors.New("bootstrap preflight evidence is owned by an interrupted run")
)
