package api

import (
	"fmt"
	"strings"
)

type destructiveRecoveryInput struct {
	RecoveryCheckpointID string `json:"recoveryCheckpointId"`
}

func (in destructiveRecoveryInput) validate() error {
	if strings.TrimSpace(in.RecoveryCheckpointID) == "" {
		return fmt.Errorf("recoveryCheckpointId is required for destructive operations")
	}
	return nil
}
