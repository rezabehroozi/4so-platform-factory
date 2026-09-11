package airuntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCertifyProviderProducesSealedEvidenceAndDoesNotEgressSyntheticSecrets(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		raw, _ := json.Marshal(payload)
		if strings.Contains(string(raw), "certify-synthetic-password-7Jw9kB2mQ4xT") || strings.Contains(string(raw), "certify-synthetic-bearer-4dK8pL2qN7vR") {
			t.Fatalf("synthetic secret escaped redaction boundary: %s", raw)
		}
		instructions, _ := payload["instructions"].(string)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(instructions, "marketplace advisor") {
			_, _ = w.Write([]byte(`{"output_text":"{\"recommendations\":[{\"offerId\":\"cert-offer-a\",\"offerVersion\":\"1.0.0\",\"score\":91,\"reason\":\"Best synthetic policy fit.\"}]}","usage":{"input_tokens":30,"output_tokens":12,"input_tokens_details":{"cached_tokens":3}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"output_text":"{\"classification\":\"environment\",\"summary\":\"Synthetic certification response.\",\"owner\":\"provider-certification\",\"recommendedChecks\":[\"Inspect synthetic evidence.\"],\"recommendedFix\":\"No mutation.\",\"confidence\":88}","usage":{"input_tokens":24,"output_tokens":10,"input_tokens_details":{"cached_tokens":2}}}`))
	}))
	defer server.Close()

	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "cert-model", MaxInputBytes: 4096, MaxOutputTokens: 800})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	evidence, err := certifyProvider(context.Background(), runtime, "1.2.3", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("c", 64), now, false)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d want=2", requests)
	}
	if evidence.Authority != ExternalProviderCertificationAuthority || evidence.ProviderTransportAuthority != ProviderTransportAuthority || evidence.ReleaseVersion != "1.2.3" || evidence.CertifierBindingAuthority != "PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1" || evidence.CertifierBinaryDigest != "sha256:"+strings.Repeat("c", 64) || evidence.Provider != ProviderOpenAIResponses || evidence.Model != "cert-model" {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
	if len(evidence.Checks) != 7 || evidence.EvidenceDigest == "" {
		t.Fatalf("incomplete evidence: %+v", evidence)
	}
	if err := evidence.Verify(); err != nil {
		t.Fatalf("evidence verification failed: %v", err)
	}
	modified := evidence
	modified.Model = "tampered"
	if err := modified.Verify(); err == nil {
		t.Fatal("tampered evidence verified")
	}
}

func TestCertifyProviderRejectsInvalidReleaseDigestBeforeProviderEgress(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "cert-model"})
	if err != nil {
		t.Fatal(err)
	}
	for _, badDigest := range []string{
		"sha256:" + strings.Repeat("G", 64),
		"sha256:" + strings.Repeat("A", 64),
	} {
		_, err = certifyProvider(context.Background(), runtime, "1.2.3", badDigest, "sha256:"+strings.Repeat("c", 64), time.Now(), false)
		if err == nil || !strings.Contains(err.Error(), "release sha256 digest is invalid") {
			t.Fatalf("expected exact-release digest rejection for %q, err=%v", badDigest, err)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid exact-release binding must fail before provider egress; requests=%d", requests)
	}
}

func TestCertifyExternalProviderRequiresHTTPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "cert-model"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = CertifyExternalProvider(context.Background(), runtime, "1.2.3", "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64), time.Now())
	if err == nil || !strings.Contains(err.Error(), "requires an HTTPS endpoint") {
		t.Fatalf("expected external HTTPS requirement, err=%v", err)
	}
	runtime, err = New(Config{Provider: ProviderOpenAIResponses, Endpoint: "https://127.0.0.1/v1/responses", Model: "cert-model"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = CertifyExternalProvider(context.Background(), runtime, "1.2.3", "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64), time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not accept loopback") {
		t.Fatalf("expected external loopback rejection, err=%v", err)
	}
}

func TestProviderCertificationEvidenceRequiresCanonicalChecksAndCertifierBinding(t *testing.T) {
	evidence := ProviderCertificationEvidence{
		SchemaVersion:              providerCertificationSchemaVersion,
		Authority:                  ExternalProviderCertificationAuthority,
		RuntimeAuthority:           RuntimeAuthority,
		ProviderTransportAuthority: ProviderTransportAuthority,
		ReleaseVersion:             "1.2.3",
		ReleaseDigest:              "sha256:" + strings.Repeat("a", 64),
		CertifierBindingAuthority:  "PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1",
		CertifierBinaryDigest:      "sha256:" + strings.Repeat("b", 64),
		Provider:                   ProviderOpenAIResponses,
		Model:                      "cert-model",
		EndpointOrigin:             "https://example.invalid:443",
		GeneratedAt:                time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC),
		Checks: []ProviderCertificationCheck{
			{Name: "certifier-binary-binding", Status: "PASS", Detail: "sha256:" + strings.Repeat("b", 64)},
			{Name: "runtime-authority", Status: "PASS", Detail: RuntimeAuthority + " via " + ProviderTransportAuthority},
			{Name: "diagnosis-structured-output", Status: "PASS", Detail: "strict diagnosis schema accepted"},
			{Name: "synthetic-secret-redaction", Status: "PASS", Detail: "redactions=2"},
			{Name: "usage-integrity", Status: "PASS", Detail: "usage valid"},
			{Name: "marketplace-structured-output", Status: "PASS", Detail: "allowlistedRecommendations=1"},
			{Name: "provider-identity-stability", Status: "PASS", Detail: ProviderOpenAIResponses + "/cert-model"},
		},
		AdvisoryOnly: true,
	}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := evidence.Verify(); err != nil {
		t.Fatalf("canonical evidence rejected: %v", err)
	}

	bad := evidence
	bad.CertifierBinaryDigest = "sha256:" + strings.Repeat("c", 64)
	if err := bad.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(); err == nil {
		t.Fatal("certifier digest/check inconsistency verified")
	}

	bad = evidence
	bad.Checks = append([]ProviderCertificationCheck(nil), evidence.Checks...)
	bad.Checks[0] = bad.Checks[1]
	if err := bad.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(); err == nil {
		t.Fatal("duplicate/substituted certification check verified")
	}

	bad = evidence
	bad.Checks = append([]ProviderCertificationCheck(nil), evidence.Checks...)
	bad.Checks[0].Detail = "sha256:" + strings.Repeat("d", 64)
	if err := bad.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(); err == nil {
		t.Fatal("inconsistent certifier binary check verified")
	}

	bad = evidence
	bad.CertifierBinaryDigest = "sha256:not-a-digest"
	if err := bad.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(); err == nil {
		t.Fatal("invalid certifier binary digest verified")
	}
}

func TestGenerateRejectsInvalidProviderUsageCounters(t *testing.T) {
	for name, usage := range map[string]string{
		"negative-input":  `"input_tokens":-1,"output_tokens":1,"input_tokens_details":{"cached_tokens":0}`,
		"negative-output": `"input_tokens":2,"output_tokens":-1,"input_tokens_details":{"cached_tokens":0}`,
		"cached-overflow": `"input_tokens":2,"output_tokens":1,"input_tokens_details":{"cached_tokens":3}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"output_text":"{}","usage":{` + usage + `}}`))
			}))
			defer server.Close()
			runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "test"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"value": "safe"}})
			if err == nil || !strings.Contains(err.Error(), "usage") && !strings.Contains(err.Error(), "cached token") {
				t.Fatalf("expected usage integrity rejection, err=%v", err)
			}
		})
	}
}
