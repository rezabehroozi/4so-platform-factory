package remotebootstrap

import (
	"strings"
	"testing"
)

func TestBootstrapTokenPathIsFixedAndSecretNotCommandData(t *testing.T) {
	if bootstrapTokenRelativePath != "var/lib/4so-platform-installer/bootstrap-token" {
		t.Fatalf("unexpected bootstrap token path %q", bootstrapTokenRelativePath)
	}
	if strings.Contains(bootstrapTokenRelativePath, "..") || strings.HasPrefix(bootstrapTokenRelativePath, "/") {
		t.Fatal("bootstrap token path must remain fixed relative to live root")
	}
}
