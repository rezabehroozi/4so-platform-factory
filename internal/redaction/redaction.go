package redaction

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Finding describes a detected secret-like pattern. Names are stable contract values.
type Finding string

const Replacement = "<redacted>"

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private-key", regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----`)},
	{"bearer", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}`)},
	{"platform-token", regexp.MustCompile(`\bpft\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}\b`)},
	{"enrollment-token", regexp.MustCompile(`(?i)(enrollmentToken|enrollment_token)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{12,}`)},
	{"authorization-header", regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)["']?[A-Za-z0-9._~+/-]{12,}`)},
	{"generic-secret-assignment", regexp.MustCompile(`(?i)\b(password|passphrase|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?[^\s"']{8,}`)},
}

// Detect returns stable names for secret-like content. It is intentionally conservative;
// digests/fingerprints are not patterns and are safe to retain as evidence.
func Detect(raw []byte) []string {
	findings := []string{}
	text := string(raw)
	for _, pattern := range secretPatterns {
		if pattern.re.MatchString(text) {
			findings = append(findings, pattern.name)
		}
	}
	sort.Strings(findings)
	return findings
}

// String redacts secret-like substrings while preserving surrounding diagnostic context.
func String(value string) (string, int) {
	out := value
	count := 0
	for _, pattern := range secretPatterns {
		matches := pattern.re.FindAllStringIndex(out, -1)
		if len(matches) == 0 {
			continue
		}
		out = pattern.re.ReplaceAllString(out, "<redacted:"+pattern.name+">")
		count += len(matches)
	}
	return out, count
}

// Value recursively redacts sensitive fields and strings. The returned value is JSON-safe.
func Value(value any) (any, int) { return valueWithKey(value, "") }

func valueWithKey(value any, key string) (any, int) {
	switch current := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(current))
		count := 0
		for k, v := range current {
			if SensitiveKey(k) {
				out[k] = Replacement
				count++
				continue
			}
			clean, n := valueWithKey(v, k)
			out[k] = clean
			count += n
		}
		return out, count
	case []any:
		out := make([]any, len(current))
		count := 0
		for i, v := range current {
			clean, n := valueWithKey(v, key)
			out[i] = clean
			count += n
		}
		return out, count
	case string:
		return String(current)
	case nil, bool, float64, float32,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return current, 0
	default:
		raw, err := json.Marshal(current)
		if err != nil {
			return current, 0
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var generic any
		if err := decoder.Decode(&generic); err == nil {
			return valueWithKey(generic, key)
		}
		return current, 0
	}
}

func SensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.TrimSpace(key)))
	for _, safe := range []string{"digest", "fingerprint", "serialnumber", "tokenprefix", "credentialref", "secretref", "certificateid"} {
		if strings.Contains(normalized, safe) {
			return false
		}
	}
	for _, term := range []string{"password", "passphrase", "token", "secret", "privatekey", "authorization", "cookie", "clientsecret", "credential", "apikey", "accesskey"} {
		if strings.Contains(normalized, term) {
			return true
		}
	}
	return false
}
