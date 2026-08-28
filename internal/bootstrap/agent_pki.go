package bootstrap

import (
	"platform.4so.io/factory/internal/agentpki"
	"time"
)

const (
	agentCACertPath = "/var/lib/4so-platform-installer/secrets/agent-ca.crt"
	agentCAKeyPath  = "/var/lib/4so-platform-installer/secrets/agent-ca.key"
)

func ensureAgentPKI(system System) error {
	if system.Exists(agentCACertPath) && system.Exists(agentCAKeyPath) {
		return nil
	}
	cert, key, err := agentpki.GenerateCA("4SO Platform Factory Agent CA", time.Now().UTC(), 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	if err = system.WriteFile(agentCACertPath, cert, 0o644); err != nil {
		return err
	}
	return system.WriteFile(agentCAKeyPath, key, 0o600)
}
