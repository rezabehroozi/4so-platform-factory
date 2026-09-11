package airuntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const ExternalProviderCertificationAuthority = "AI_EXTERNAL_PROVIDER_RUNTIME_CERTIFICATION_V2"

const providerCertificationSchemaVersion = 2

type ProviderCertificationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type ProviderCertificationEvidence struct {
	SchemaVersion              int                          `json:"schemaVersion"`
	Authority                  string                       `json:"authority"`
	RuntimeAuthority           string                       `json:"runtimeAuthority"`
	ProviderTransportAuthority string                       `json:"providerTransportAuthority"`
	ReleaseVersion             string                       `json:"releaseVersion"`
	ReleaseDigest              string                       `json:"releaseDigest"`
	CertifierBindingAuthority  string                       `json:"certifierBindingAuthority"`
	CertifierBinaryDigest      string                       `json:"certifierBinaryDigest"`
	Provider                   string                       `json:"provider"`
	Model                      string                       `json:"model"`
	EndpointOrigin             string                       `json:"endpointOrigin"`
	GeneratedAt                time.Time                    `json:"generatedAt"`
	Checks                     []ProviderCertificationCheck `json:"checks"`
	AdvisoryOnly               bool                         `json:"advisoryOnly"`
	CanDecidePass              bool                         `json:"canDecidePass"`
	CanDecidePhysicalPass      bool                         `json:"canDecidePhysicalPass"`
	EvidenceDigest             string                       `json:"evidenceDigest"`
}

func (e ProviderCertificationEvidence) canonicalBytesForDigest() ([]byte, error) {
	e.EvidenceDigest = ""
	return json.Marshal(e)
}

func (e *ProviderCertificationEvidence) Seal() error {
	if e == nil {
		return errors.New("AI provider certification evidence is required")
	}
	raw, err := e.canonicalBytesForDigest()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	e.EvidenceDigest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

func (e ProviderCertificationEvidence) Verify() error {
	if e.SchemaVersion != providerCertificationSchemaVersion || e.Authority != ExternalProviderCertificationAuthority || e.RuntimeAuthority != RuntimeAuthority || e.ProviderTransportAuthority != ProviderTransportAuthority {
		return errors.New("AI provider certification authority metadata is invalid")
	}
	if strings.TrimSpace(e.ReleaseVersion) == "" || !strings.HasPrefix(e.ReleaseDigest, "sha256:") || len(e.ReleaseDigest) != len("sha256:")+64 {
		return errors.New("AI provider certification release binding is invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(e.ReleaseDigest, "sha256:")); err != nil || strings.ToLower(e.ReleaseDigest) != e.ReleaseDigest {
		return errors.New("AI provider certification release digest is invalid")
	}
	if e.CertifierBindingAuthority != "PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1" {
		return errors.New("AI provider certification certifier binding authority is invalid")
	}
	if !strings.HasPrefix(e.CertifierBinaryDigest, "sha256:") || len(e.CertifierBinaryDigest) != len("sha256:")+64 {
		return errors.New("AI provider certification certifier binary binding is invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(e.CertifierBinaryDigest, "sha256:")); err != nil || strings.ToLower(e.CertifierBinaryDigest) != e.CertifierBinaryDigest {
		return errors.New("AI provider certification certifier binary digest is invalid")
	}
	if e.Provider == ProviderNone || strings.TrimSpace(e.Provider) == "" || strings.TrimSpace(e.Model) == "" || strings.TrimSpace(e.EndpointOrigin) == "" {
		return errors.New("AI provider certification provider identity is invalid")
	}
	requiredChecks := []string{
		"certifier-binary-binding",
		"runtime-authority",
		"diagnosis-structured-output",
		"synthetic-secret-redaction",
		"usage-integrity",
		"marketplace-structured-output",
		"provider-identity-stability",
	}
	if e.GeneratedAt.IsZero() || len(e.Checks) != len(requiredChecks) || !e.AdvisoryOnly || e.CanDecidePass || e.CanDecidePhysicalPass {
		return errors.New("AI provider certification policy metadata is invalid")
	}
	for index, check := range e.Checks {
		if check.Name != requiredChecks[index] || check.Status != "PASS" || strings.TrimSpace(check.Detail) == "" {
			return errors.New("AI provider certification contains a non-canonical, non-PASS or malformed check")
		}
	}
	if e.Checks[0].Detail != e.CertifierBinaryDigest {
		return errors.New("AI provider certification certifier binary check does not match the bound digest")
	}
	if e.Checks[1].Detail != RuntimeAuthority+" via "+ProviderTransportAuthority {
		return errors.New("AI provider certification runtime authority check is inconsistent")
	}
	if e.Checks[len(e.Checks)-1].Detail != e.Provider+"/"+e.Model {
		return errors.New("AI provider certification provider identity check is inconsistent")
	}
	expected := e.EvidenceDigest
	if !strings.HasPrefix(expected, "sha256:") || len(expected) != len("sha256:")+64 {
		return errors.New("AI provider certification evidence digest is invalid")
	}
	raw, err := e.canonicalBytesForDigest()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if actual != expected {
		return errors.New("AI provider certification evidence digest mismatch")
	}
	return nil
}

// CertifyExternalProvider performs bounded, advisory-only live model calls through
// the exact runtime/transport implementation used by the product. It produces
// provider certification evidence only for HTTPS provider endpoints. This
// evidence never implies deterministic product PASS or Physical PASS.
func CertifyExternalProvider(ctx context.Context, runtime *Runtime, releaseVersion, releaseDigest, certifierBinaryDigest string, now time.Time) (ProviderCertificationEvidence, error) {
	return certifyProvider(ctx, runtime, releaseVersion, releaseDigest, certifierBinaryDigest, now, true)
}

func certifyProvider(ctx context.Context, runtime *Runtime, releaseVersion, releaseDigest, certifierBinaryDigest string, now time.Time, requireHTTPS bool) (ProviderCertificationEvidence, error) {
	var evidence ProviderCertificationEvidence
	if runtime == nil || !runtime.Enabled() {
		return evidence, errors.New("AI provider runtime is disabled")
	}
	endpointURL, err := url.Parse(runtime.config.Endpoint)
	if err != nil || endpointURL.Host == "" {
		return evidence, errors.New("AI provider endpoint is invalid")
	}
	if requireHTTPS && !strings.EqualFold(endpointURL.Scheme, "https") {
		return evidence, errors.New("external AI provider certification requires an HTTPS endpoint")
	}
	if requireHTTPS {
		host := strings.TrimSpace(endpointURL.Hostname())
		if strings.EqualFold(host, "localhost") {
			return evidence, errors.New("external AI provider certification does not accept localhost endpoints")
		}
		if literal, parseErr := netip.ParseAddr(host); parseErr == nil && literal.Unmap().IsLoopback() {
			return evidence, errors.New("external AI provider certification does not accept loopback endpoints")
		}
	}
	releaseVersion = strings.TrimSpace(releaseVersion)
	releaseDigest = strings.TrimSpace(releaseDigest)
	certifierBinaryDigest = strings.TrimSpace(certifierBinaryDigest)
	if releaseVersion == "" || !strings.HasPrefix(releaseDigest, "sha256:") || len(releaseDigest) != len("sha256:")+64 {
		return evidence, errors.New("exact release version and sha256 digest are required for AI provider certification")
	}
	if _, digestErr := hex.DecodeString(strings.TrimPrefix(releaseDigest, "sha256:")); digestErr != nil || strings.ToLower(releaseDigest) != releaseDigest {
		return evidence, errors.New("exact release sha256 digest is invalid for AI provider certification")
	}
	if !strings.HasPrefix(certifierBinaryDigest, "sha256:") || len(certifierBinaryDigest) != len("sha256:")+64 {
		return evidence, errors.New("exact certifier platformctl sha256 digest is required for AI provider certification")
	}
	if _, digestErr := hex.DecodeString(strings.TrimPrefix(certifierBinaryDigest, "sha256:")); digestErr != nil || strings.ToLower(certifierBinaryDigest) != certifierBinaryDigest {
		return evidence, errors.New("exact certifier platformctl sha256 digest is invalid")
	}

	certRuntime := runtime
	if requireHTTPS {
		dialer := &net.Dialer{Timeout: runtime.config.Timeout, KeepAlive: 30 * time.Second}
		lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			addresses, lookupErr := net.DefaultResolver.LookupNetIP(ctx, network, host)
			if lookupErr != nil {
				return nil, lookupErr
			}
			for _, address := range addresses {
				if address.Unmap().IsLoopback() {
					return nil, fmt.Errorf("external AI provider certification target resolves to loopback address %s", address)
				}
			}
			return addresses, nil
		}
		certRuntime = &Runtime{config: runtime.config, client: newProviderHTTPClient(endpointURL, runtime.config.Timeout, lookup, dialer.DialContext)}
	}

	checks := make([]ProviderCertificationCheck, 0, 7)
	checks = append(checks,
		ProviderCertificationCheck{Name: "certifier-binary-binding", Status: "PASS", Detail: certifierBinaryDigest},
		ProviderCertificationCheck{Name: "runtime-authority", Status: "PASS", Detail: RuntimeAuthority + " via " + ProviderTransportAuthority},
	)

	syntheticPassword := "certify-synthetic-password-7Jw9kB2mQ4xT"
	syntheticBearer := "certify-synthetic-bearer-4dK8pL2qN7vR"
	diagnosisResult, err := certRuntime.Generate(ctx, Request{
		Purpose:  "external-provider-certification-diagnosis",
		PromptID: PromptOperatorDiagnosis,
		System:   DiagnosisSystem(),
		Input: map[string]any{
			"failure":       "synthetic provider-certification packet; no production mutation occurred",
			"password":      syntheticPassword,
			"authorization": "Bearer " + syntheticBearer,
			"constraints":   []string{"advisory-only", "no PASS authority", "no Physical PASS authority", "no mutation authority"},
		},
		JSONSchema: DiagnosisSchema(),
	})
	if err != nil {
		return evidence, fmt.Errorf("external provider diagnosis certification failed: %w", err)
	}
	if diagnosisResult.RedactionCount < 2 {
		return evidence, errors.New("external provider certification did not prove synthetic secret redaction")
	}
	if bytes.Contains(diagnosisResult.JSON, []byte(syntheticPassword)) || bytes.Contains(diagnosisResult.JSON, []byte(syntheticBearer)) {
		return evidence, errors.New("external provider certification output reflected synthetic secret material")
	}
	if _, err = ParseDiagnosis(diagnosisResult.JSON); err != nil {
		return evidence, fmt.Errorf("external provider diagnosis schema certification failed: %w", err)
	}
	if err = validateProviderUsage(diagnosisResult.Usage); err != nil {
		return evidence, err
	}
	checks = append(checks,
		ProviderCertificationCheck{Name: "diagnosis-structured-output", Status: "PASS", Detail: "strict diagnosis schema accepted"},
		ProviderCertificationCheck{Name: "synthetic-secret-redaction", Status: "PASS", Detail: fmt.Sprintf("redactions=%d", diagnosisResult.RedactionCount)},
		ProviderCertificationCheck{Name: "usage-integrity", Status: "PASS", Detail: "provider usage counters are non-negative and internally consistent"},
	)

	eligible := []map[string]any{
		{"id": "cert-offer-a", "version": "1.0.0", "displayName": "Synthetic Security Baseline", "description": "Synthetic certification-only offer", "category": "security", "risk": "low", "capabilities": []string{"policy"}},
		{"id": "cert-offer-b", "version": "1.0.0", "displayName": "Synthetic Operations Baseline", "description": "Synthetic certification-only offer", "category": "operations", "risk": "medium", "capabilities": []string{"observability"}},
	}
	marketResult, err := certRuntime.Generate(ctx, Request{
		Purpose:  "external-provider-certification-marketplace",
		PromptID: PromptMarketplace,
		System:   MarketplaceSystem(),
		Input: map[string]any{
			"objective":         "Select the single eligible security baseline most suitable for a synthetic certification scenario.",
			"capabilities":      []string{"policy", "observability"},
			"eligibleOffers":    eligible,
			"certificationOnly": true,
		},
		JSONSchema:      MarketplaceSchema(),
		MaxOutputTokens: 600,
	})
	if err != nil {
		return evidence, fmt.Errorf("external provider marketplace certification failed: %w", err)
	}
	var marketEnvelope struct {
		Recommendations []struct {
			OfferID      string `json:"offerId"`
			OfferVersion string `json:"offerVersion"`
			Score        int    `json:"score"`
			Reason       string `json:"reason"`
		} `json:"recommendations"`
	}
	dec := json.NewDecoder(bytes.NewReader(marketResult.JSON))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&marketEnvelope); err != nil {
		return evidence, fmt.Errorf("external provider marketplace schema certification failed: %w", err)
	}
	if len(marketEnvelope.Recommendations) == 0 || len(marketEnvelope.Recommendations) > 3 {
		return evidence, errors.New("external provider marketplace certification requires one to three valid recommendations")
	}
	allowed := map[string]struct{}{"cert-offer-a@1.0.0": {}, "cert-offer-b@1.0.0": {}}
	seen := map[string]struct{}{}
	for _, item := range marketEnvelope.Recommendations {
		key := strings.TrimSpace(item.OfferID) + "@" + strings.TrimSpace(item.OfferVersion)
		if _, ok := allowed[key]; !ok {
			return evidence, errors.New("external provider marketplace certification selected an offer outside the supplied allowlist")
		}
		if _, duplicate := seen[key]; duplicate {
			return evidence, errors.New("external provider marketplace certification returned a duplicate recommendation")
		}
		seen[key] = struct{}{}
		if item.Score < 0 || item.Score > 100 || strings.TrimSpace(item.Reason) == "" || len(item.Reason) > 500 {
			return evidence, errors.New("external provider marketplace certification returned an invalid recommendation")
		}
	}
	if err = validateProviderUsage(marketResult.Usage); err != nil {
		return evidence, err
	}
	checks = append(checks,
		ProviderCertificationCheck{Name: "marketplace-structured-output", Status: "PASS", Detail: fmt.Sprintf("allowlistedRecommendations=%d", len(marketEnvelope.Recommendations))},
		ProviderCertificationCheck{Name: "provider-identity-stability", Status: "PASS", Detail: runtime.Provider() + "/" + runtime.Model()},
	)

	origin := providerOriginKey(endpointURL)
	evidence = ProviderCertificationEvidence{
		SchemaVersion: providerCertificationSchemaVersion, Authority: ExternalProviderCertificationAuthority,
		RuntimeAuthority: RuntimeAuthority, ProviderTransportAuthority: ProviderTransportAuthority,
		ReleaseVersion: releaseVersion, ReleaseDigest: releaseDigest, CertifierBindingAuthority: "PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1", CertifierBinaryDigest: certifierBinaryDigest, Provider: runtime.Provider(), Model: runtime.Model(), EndpointOrigin: origin,
		GeneratedAt: now.UTC(), Checks: checks, AdvisoryOnly: true, CanDecidePass: false, CanDecidePhysicalPass: false,
	}
	if err = evidence.Seal(); err != nil {
		return ProviderCertificationEvidence{}, err
	}
	if err = evidence.Verify(); err != nil {
		return ProviderCertificationEvidence{}, err
	}
	return evidence, nil
}
