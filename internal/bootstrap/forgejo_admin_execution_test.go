package bootstrap

import (
	"strings"
	"testing"
)

func TestForgejoAdminBootstrapNeverRunsForgejoCLIAsRoot(t *testing.T) {
	command := forgejoAdminBootstrapCommand()
	if !strings.Contains(command, "command -v su-exec") {
		t.Fatal("Forgejo admin bootstrap does not fail closed when su-exec is unavailable")
	}
	adminLines := 0
	for _, raw := range strings.Split(command, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.Contains(line, "forgejo admin user") {
			continue
		}
		adminLines++
		if !strings.Contains(line, "su-exec git forgejo admin user") {
			t.Fatalf("Forgejo admin CLI can run outside the git user boundary: %q", line)
		}
	}
	if adminLines != 3 {
		t.Fatalf("expected list/change-password/create Forgejo admin operations, got %d in %q", adminLines, command)
	}
	if !strings.Contains(command, "forgejo admin user change-password --username platform-admin") {
		t.Fatal("existing Forgejo administrator is not converged to the persisted product credential")
	}
}
