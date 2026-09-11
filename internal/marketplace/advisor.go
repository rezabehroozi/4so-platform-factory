package marketplace

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/airuntime"
)

type Recommendation struct {
	OfferID      string `json:"offerId"`
	OfferVersion string `json:"offerVersion"`
	Score        int    `json:"score"`
	Reason       string `json:"reason"`
	Risk         string `json:"risk"`
}

type AdvisoryInput struct {
	Objective         string   `json:"objective"`
	KubernetesVersion string   `json:"kubernetesVersion,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
}

type AdvisoryOutput struct {
	Engine          string            `json:"engine"`
	Model           string            `json:"model,omitempty"`
	Recommendations []Recommendation  `json:"recommendations"`
	AIRuntime       *airuntime.Result `json:"aiRuntime,omitempty"`
}

type Config struct {
	Provider        string
	Endpoint        string
	APIKey          string
	Model           string
	Timeout         time.Duration
	MaxInputBytes   int
	MaxOutputTokens int
}

type ControlledAdvisor struct {
	runtime   *airuntime.Runtime
	configErr error
}

func NewControlledAdvisor(config Config) *ControlledAdvisor {
	if strings.TrimSpace(config.Endpoint) == "" && strings.TrimSpace(config.Provider) == "" {
		return &ControlledAdvisor{}
	}
	provider := strings.TrimSpace(config.Provider)
	if provider == "" {
		provider = airuntime.ProviderOpenAICompatible
	}
	runtime, err := airuntime.New(airuntime.Config{Provider: provider, Endpoint: config.Endpoint, APIKey: config.APIKey, Model: config.Model, Timeout: config.Timeout, MaxInputBytes: config.MaxInputBytes, MaxOutputTokens: config.MaxOutputTokens})
	if err != nil {
		// Configuration errors are surfaced on use rather than turning invalid
		// model configuration into an implicit policy recommendation.
		return &ControlledAdvisor{configErr: err}
	}
	return &ControlledAdvisor{runtime: runtime}
}

func NewRuntimeAdvisor(runtime *airuntime.Runtime) *ControlledAdvisor {
	return &ControlledAdvisor{runtime: runtime}
}

// UsesAIRuntime reports whether the canonical advisor will issue a model call
// for a non-empty eligible offer set. API dispatch authority uses this to
// durably claim the idempotency key before external provider egress.
func (a *ControlledAdvisor) UsesAIRuntime() bool {
	return a != nil && a.configErr == nil && a.runtime != nil && a.runtime.Enabled()
}

func (a *ControlledAdvisor) Recommend(ctx context.Context, input AdvisoryInput, offers []Offer) (AdvisoryOutput, error) {
	input.Objective = strings.TrimSpace(input.Objective)
	if input.Objective == "" || len(input.Objective) > 1000 {
		return AdvisoryOutput{}, fmt.Errorf("objective must contain 1-1000 characters")
	}
	if len(offers) == 0 {
		return AdvisoryOutput{Engine: "policy", Recommendations: []Recommendation{}}, nil
	}
	if a != nil && a.configErr != nil {
		return AdvisoryOutput{}, fmt.Errorf("invalid AI advisor configuration: %w", a.configErr)
	}
	if a == nil || a.runtime == nil || !a.runtime.Enabled() {
		return policyRecommend(input, offers), nil
	}
	return a.modelRecommend(ctx, input, offers)
}

func policyRecommend(input AdvisoryInput, offers []Offer) AdvisoryOutput {
	lower := strings.ToLower(input.Objective)
	out := AdvisoryOutput{Engine: "policy", Recommendations: []Recommendation{}}
	for _, offer := range offers {
		score := 72
		if strings.Contains(lower, "security") || strings.Contains(lower, "secure") || strings.Contains(lower, "امن") {
			score = 92
		}
		out.Recommendations = append(out.Recommendations, Recommendation{OfferID: offer.ID, OfferVersion: offer.Version, Score: score, Reason: "The offer matches the admitted cluster capabilities and provides a reversible, approval-bound security baseline for the stated objective.", Risk: offer.Risk})
		if len(out.Recommendations) == 3 {
			break
		}
	}
	return out
}

func (a *ControlledAdvisor) modelRecommend(ctx context.Context, input AdvisoryInput, offers []Offer) (AdvisoryOutput, error) {
	type safeOffer struct {
		ID           string   `json:"id"`
		Version      string   `json:"version"`
		DisplayName  string   `json:"displayName"`
		Description  string   `json:"description"`
		Category     string   `json:"category"`
		Risk         string   `json:"risk"`
		Capabilities []string `json:"capabilities"`
	}
	safe := make([]safeOffer, 0, len(offers))
	for _, offer := range offers {
		safe = append(safe, safeOffer{offer.ID, offer.Version, offer.DisplayName, offer.Description, offer.Category, offer.Risk, append([]string(nil), offer.Capabilities...)})
	}
	generated, err := a.runtime.Generate(ctx, airuntime.Request{Purpose: "marketplace-recommendation", PromptID: airuntime.PromptMarketplace, System: airuntime.MarketplaceSystem(), Input: map[string]any{"objective": input.Objective, "kubernetesVersion": input.KubernetesVersion, "capabilities": input.Capabilities, "eligibleOffers": safe}, JSONSchema: airuntime.MarketplaceSchema(), MaxOutputTokens: 600})
	if err != nil {
		return AdvisoryOutput{}, fmt.Errorf("AI advisor request failed: %w", err)
	}
	recommendations, err := RecommendationsFromAIJSON(generated.JSON, offers)
	if err != nil {
		return AdvisoryOutput{}, err
	}
	return AdvisoryOutput{Engine: "model", Model: generated.Model, Recommendations: recommendations, AIRuntime: &generated}, nil
}

// RecommendationsFromAIJSON re-validates a persisted AI advisory output
// against the currently eligible allowlist. This lets interrupted API writes
// resume from durable ai_runs without spending tokens on a second model call.
func RecommendationsFromAIJSON(raw json.RawMessage, offers []Offer) ([]Recommendation, error) {
	var parsed struct {
		Recommendations []Recommendation `json:"recommendations"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("AI advisor response validation failed: %w", err)
	}
	if len(parsed.Recommendations) > 3 {
		return nil, fmt.Errorf("AI advisor returned more than three recommendations")
	}
	allowed := map[string]Offer{}
	for _, offer := range offers {
		allowed[offer.ID+"@"+offer.Version] = offer
	}
	seen := map[string]bool{}
	for i := range parsed.Recommendations {
		item := &parsed.Recommendations[i]
		item.OfferID = strings.TrimSpace(item.OfferID)
		item.OfferVersion = strings.TrimSpace(item.OfferVersion)
		item.Reason = strings.TrimSpace(item.Reason)
		key := item.OfferID + "@" + item.OfferVersion
		offer, ok := allowed[key]
		if !ok || seen[key] || item.Score < 0 || item.Score > 100 || item.Reason == "" || len(item.Reason) > 500 {
			return nil, fmt.Errorf("AI advisor selected an invalid or duplicate offer")
		}
		seen[key] = true
		item.Risk = offer.Risk
	}
	return parsed.Recommendations, nil
}
