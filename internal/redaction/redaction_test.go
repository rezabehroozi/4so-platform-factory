package redaction

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValueRedactsStructuredAndEmbeddedSecrets(t *testing.T) {
	input := map[string]any{
		"password":    "super-secret",
		"tokenDigest": "sha256:abc",
		"log":         "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"nested":      []any{map[string]any{"apiKey": "abcdefghijklmno"}},
	}
	clean, count := Value(input)
	if count < 3 {
		t.Fatalf("redactions=%d value=%#v", count, clean)
	}
	raw, _ := json.Marshal(clean)
	text := string(raw)
	if strings.Contains(text, "super-secret") || strings.Contains(text, "abcdefghijklmnopqrstuvwxyz") || strings.Contains(text, "abcdefghijklmno") {
		t.Fatalf("secret leaked: %s", text)
	}
	if !strings.Contains(text, "sha256:abc") {
		t.Fatalf("safe digest was removed: %s", text)
	}
	if findings := Detect(raw); len(findings) != 0 {
		t.Fatalf("redacted payload still contains findings: %v", findings)
	}
}
