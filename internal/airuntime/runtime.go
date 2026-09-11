package airuntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/redaction"
)

const (
	RuntimeAuthority           = "UNIFIED_AI_RUNTIME_V1"
	ProviderTransportAuthority = "AI_PROVIDER_TRANSPORT_AUTHORITY_V2"
	ProviderNone               = "none"
	ProviderOpenAIResponses    = "openai-responses"
	ProviderOpenAICompatible   = "openai-compatible-chat"
	DefaultMaxInputBytes       = 16 * 1024
	AbsoluteMaxInputBytes      = 64 * 1024
	DefaultMaxOutputTokens     = 800
	AbsoluteMaxOutputTokens    = 2000
	maxProviderResponseBytes   = 1 << 20
)

type Config struct {
	Provider        string
	Endpoint        string
	APIKey          string
	Model           string
	Timeout         time.Duration
	MaxInputBytes   int
	MaxOutputTokens int
}

type Request struct {
	Purpose         string
	PromptID        string
	System          string
	Input           any
	JSONSchema      map[string]any
	MaxOutputTokens int
}

type Usage struct {
	InputTokens  int `json:"inputTokens,omitempty"`
	CachedTokens int `json:"cachedTokens,omitempty"`
	OutputTokens int `json:"outputTokens,omitempty"`
}

type Result struct {
	Provider       string          `json:"provider"`
	Model          string          `json:"model,omitempty"`
	Purpose        string          `json:"purpose"`
	PromptID       string          `json:"promptId"`
	PromptDigest   string          `json:"promptDigest"`
	ContextDigest  string          `json:"contextDigest"`
	OutputDigest   string          `json:"outputDigest"`
	RedactionCount int             `json:"redactionCount"`
	InputBytes     int             `json:"inputBytes"`
	Usage          Usage           `json:"usage,omitempty"`
	JSON           json.RawMessage `json:"json"`
}

type Runtime struct {
	config Config
	client *http.Client
}

// ConfigFromEnv resolves the single process-wide AI provider configuration.
// It intentionally keeps credentials out of callers and gives platform-api,
// platformctl and lab automation the same provider/budget semantics.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	provider := strings.ToLower(strings.TrimSpace(getenv("PLATFORM_FACTORY_AI_PROVIDER")))
	responsesURL := strings.TrimSpace(getenv("PLATFORM_FACTORY_AI_RESPONSES_URL"))
	chatURL := strings.TrimSpace(getenv("PLATFORM_FACTORY_AI_CHAT_COMPLETIONS_URL"))
	endpoint := strings.TrimSpace(getenv("PLATFORM_FACTORY_AI_ENDPOINT"))
	if endpoint == "" {
		switch provider {
		case ProviderOpenAIResponses:
			endpoint = responsesURL
		case ProviderOpenAICompatible:
			endpoint = chatURL
		default:
			if responsesURL != "" {
				provider, endpoint = ProviderOpenAIResponses, responsesURL
			} else if chatURL != "" {
				provider, endpoint = ProviderOpenAICompatible, chatURL
			}
		}
	}
	if provider == "" && endpoint == "" {
		provider = ProviderNone
	}
	parseInt := func(name string, def, max int) (int, error) {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			return def, nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 || v > max {
			return 0, fmt.Errorf("%s must be an integer between 1 and %d", name, max)
		}
		return v, nil
	}
	maxInput, err := parseInt("PLATFORM_FACTORY_AI_MAX_INPUT_BYTES", DefaultMaxInputBytes, AbsoluteMaxInputBytes)
	if err != nil {
		return Config{}, err
	}
	maxOutput, err := parseInt("PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS", DefaultMaxOutputTokens, AbsoluteMaxOutputTokens)
	if err != nil {
		return Config{}, err
	}
	timeout := 30 * time.Second
	if raw := strings.TrimSpace(getenv("PLATFORM_FACTORY_AI_TIMEOUT")); raw != "" {
		parsed, e := time.ParseDuration(raw)
		if e != nil || parsed <= 0 || parsed > 90*time.Second {
			return Config{}, errors.New("PLATFORM_FACTORY_AI_TIMEOUT must be a duration greater than zero and at most 90s")
		}
		timeout = parsed
	}
	config := Config{Provider: provider, Endpoint: endpoint, APIKey: getenv("PLATFORM_FACTORY_AI_API_KEY"), Model: getenv("PLATFORM_FACTORY_AI_MODEL"), Timeout: timeout, MaxInputBytes: maxInput, MaxOutputTokens: maxOutput}
	// Validate here so a malformed provider configuration fails process startup
	// instead of silently falling back to deterministic recommendations.
	if _, err = New(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func New(config Config) (*Runtime, error) {
	config.Provider = strings.ToLower(strings.TrimSpace(config.Provider))
	config.Endpoint = strings.TrimSpace(config.Endpoint)
	config.APIKey = strings.TrimSpace(config.APIKey)
	config.Model = strings.TrimSpace(config.Model)
	if config.Provider == "" {
		if config.Endpoint == "" {
			config.Provider = ProviderNone
		} else if strings.Contains(config.Endpoint, "/responses") {
			config.Provider = ProviderOpenAIResponses
		} else {
			config.Provider = ProviderOpenAICompatible
		}
	}
	switch config.Provider {
	case ProviderNone:
	case ProviderOpenAIResponses, ProviderOpenAICompatible:
		if config.Endpoint == "" {
			if config.Provider == ProviderOpenAIResponses {
				config.Endpoint = "https://api.openai.com/v1/responses"
			} else {
				return nil, errors.New("OpenAI-compatible chat provider requires an endpoint")
			}
		}
		if err := validateProviderEndpoint(config.Endpoint); err != nil {
			return nil, err
		}
		if config.Model == "" {
			return nil, errors.New("AI model is required when a model provider is enabled")
		}
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", config.Provider)
	}
	if config.Timeout <= 0 || config.Timeout > 90*time.Second {
		config.Timeout = 30 * time.Second
	}
	if config.MaxInputBytes <= 0 {
		config.MaxInputBytes = DefaultMaxInputBytes
	}
	if config.MaxInputBytes > AbsoluteMaxInputBytes {
		return nil, fmt.Errorf("AI max input bytes cannot exceed %d", AbsoluteMaxInputBytes)
	}
	if config.MaxOutputTokens <= 0 {
		config.MaxOutputTokens = DefaultMaxOutputTokens
	}
	if config.MaxOutputTokens > AbsoluteMaxOutputTokens {
		return nil, fmt.Errorf("AI max output tokens cannot exceed %d", AbsoluteMaxOutputTokens)
	}
	endpointURL, err := url.Parse(config.Endpoint)
	if config.Provider != ProviderNone && err != nil {
		return nil, fmt.Errorf("parse AI provider endpoint: %w", err)
	}
	client := &http.Client{Timeout: config.Timeout}
	if config.Provider != ProviderNone {
		client = newProviderHTTPClient(endpointURL, config.Timeout, net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext)
	}
	return &Runtime{config: config, client: client}, nil
}

func (r *Runtime) Enabled() bool { return r != nil && r.config.Provider != ProviderNone }
func (r *Runtime) Provider() string {
	if r == nil || r.config.Provider == "" {
		return ProviderNone
	}
	return r.config.Provider
}
func (r *Runtime) Model() string {
	if r == nil {
		return ""
	}
	return r.config.Model
}

func (r *Runtime) Policy() map[string]any {
	if r == nil {
		return map[string]any{"runtimeAuthority": RuntimeAuthority, "providerTransportAuthority": ProviderTransportAuthority, "enabled": false, "provider": ProviderNone, "redactionRequired": true, "structuredOutputRequired": true, "rawPromptPersisted": false, "advisoryOnly": true, "canDecidePass": false, "canDecidePhysicalPass": false}
	}
	return map[string]any{"runtimeAuthority": RuntimeAuthority, "providerTransportAuthority": ProviderTransportAuthority, "enabled": r.Enabled(), "provider": r.Provider(), "model": r.Model(), "timeoutSeconds": int(r.config.Timeout / time.Second), "maxInputBytes": r.config.MaxInputBytes, "maxOutputTokens": r.config.MaxOutputTokens, "redactionRequired": true, "structuredOutputRequired": true, "rawPromptPersisted": false, "advisoryOnly": true, "canDecidePass": false, "canDecidePhysicalPass": false}
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Runtime) Generate(ctx context.Context, req Request) (Result, error) {
	if r == nil || !r.Enabled() {
		return Result{}, errors.New("AI runtime is disabled")
	}
	req.Purpose = strings.TrimSpace(req.Purpose)
	req.PromptID = strings.TrimSpace(req.PromptID)
	req.System = strings.TrimSpace(req.System)
	if req.Purpose == "" || req.PromptID == "" || req.System == "" || req.Input == nil {
		return Result{}, errors.New("AI purpose, promptId, system instruction and input are required")
	}
	clean, redactions := redaction.Value(req.Input)
	inputRaw, err := json.Marshal(clean)
	if err != nil {
		return Result{}, fmt.Errorf("encode redacted AI context: %w", err)
	}
	if findings := redaction.Detect(inputRaw); len(findings) != 0 {
		return Result{}, fmt.Errorf("AI context redaction failed: %s", strings.Join(findings, ","))
	}
	if len(inputRaw) > r.config.MaxInputBytes {
		return Result{}, fmt.Errorf("AI context exceeds %d-byte budget after redaction", r.config.MaxInputBytes)
	}
	maxTokens := req.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = r.config.MaxOutputTokens
	}
	if maxTokens > r.config.MaxOutputTokens {
		maxTokens = r.config.MaxOutputTokens
	}
	if maxTokens <= 0 || maxTokens > AbsoluteMaxOutputTokens {
		return Result{}, errors.New("invalid AI output token budget")
	}

	promptDigest := digestBytes([]byte(req.PromptID + "\n" + req.System))
	contextDigest := digestBytes(inputRaw)
	var content []byte
	var usage Usage
	switch r.config.Provider {
	case ProviderOpenAIResponses:
		content, usage, err = r.responses(ctx, req, inputRaw, maxTokens)
	case ProviderOpenAICompatible:
		content, usage, err = r.chat(ctx, req, inputRaw, maxTokens)
	default:
		err = fmt.Errorf("unsupported AI provider %q", r.config.Provider)
	}
	if err != nil {
		return Result{}, err
	}
	if err = validateProviderUsage(usage); err != nil {
		return Result{}, err
	}
	content = bytes.TrimSpace(content)
	if len(content) == 0 || len(content) > 64*1024 || bytes.Contains(content, []byte("```")) {
		return Result{}, errors.New("AI provider output is empty, oversized or markdown-wrapped")
	}
	if err = rejectDuplicateJSONKeys(content); err != nil {
		return Result{}, fmt.Errorf("AI provider output contains ambiguous JSON: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	if err = dec.Decode(&generic); err != nil {
		return Result{}, fmt.Errorf("AI provider output is not strict JSON: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return Result{}, errors.New("AI provider output contains multiple JSON values")
	}
	normalized, err := json.Marshal(generic)
	if err != nil {
		return Result{}, err
	}
	if findings := redaction.Detect(normalized); len(findings) != 0 {
		return Result{}, fmt.Errorf("AI provider output contains secret-like content: %s", strings.Join(findings, ","))
	}
	return Result{Provider: r.config.Provider, Model: r.config.Model, Purpose: req.Purpose, PromptID: req.PromptID, PromptDigest: promptDigest, ContextDigest: contextDigest, OutputDigest: digestBytes(normalized), RedactionCount: redactions, InputBytes: len(inputRaw), Usage: usage, JSON: normalized}, nil
}

func validateProviderUsage(usage Usage) error {
	if usage.InputTokens < 0 || usage.CachedTokens < 0 || usage.OutputTokens < 0 {
		return errors.New("AI provider usage counters must not be negative")
	}
	if usage.CachedTokens > usage.InputTokens {
		return errors.New("AI provider cached token count cannot exceed input token count")
	}
	return nil
}

func (r *Runtime) request(ctx context.Context, payload map[string]any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if r.config.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+r.config.APIKey)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("AI provider request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxProviderResponseBytes {
		return nil, errors.New("AI provider response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("AI provider returned HTTP %d", response.StatusCode)
	}
	return body, nil
}

func (r *Runtime) responses(ctx context.Context, req Request, inputRaw []byte, maxTokens int) ([]byte, Usage, error) {
	text := map[string]any{"verbosity": "low"}
	if req.JSONSchema != nil {
		text["format"] = map[string]any{"type": "json_schema", "name": safeSchemaName(req.PromptID), "strict": true, "schema": req.JSONSchema}
	}
	body, err := r.request(ctx, map[string]any{"model": r.config.Model, "instructions": req.System, "input": string(inputRaw), "max_output_tokens": maxTokens, "store": false, "text": text})
	if err != nil {
		return nil, Usage{}, err
	}
	if err = rejectDuplicateJSONKeys(body); err != nil {
		return nil, Usage{}, fmt.Errorf("Responses API envelope contains ambiguous JSON: %w", err)
	}
	var envelope struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage struct {
			InputTokens        int `json:"input_tokens"`
			OutputTokens       int `json:"output_tokens"`
			InputTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil {
		return nil, Usage{}, fmt.Errorf("decode Responses API envelope: %w", err)
	}
	content := envelope.OutputText
	if strings.TrimSpace(content) == "" {
		var b strings.Builder
		for _, item := range envelope.Output {
			for _, part := range item.Content {
				if part.Type == "output_text" {
					b.WriteString(part.Text)
				}
			}
		}
		content = b.String()
	}
	if strings.TrimSpace(content) == "" {
		return nil, Usage{}, errors.New("Responses API returned no output_text")
	}
	return []byte(content), Usage{InputTokens: envelope.Usage.InputTokens, CachedTokens: envelope.Usage.InputTokensDetails.CachedTokens, OutputTokens: envelope.Usage.OutputTokens}, nil
}

func (r *Runtime) chat(ctx context.Context, req Request, inputRaw []byte, maxTokens int) ([]byte, Usage, error) {
	payload := map[string]any{"model": r.config.Model, "temperature": 0, "max_tokens": maxTokens, "messages": []map[string]string{{"role": "system", "content": req.System}, {"role": "user", "content": string(inputRaw)}}}
	if req.JSONSchema != nil {
		payload["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": safeSchemaName(req.PromptID), "strict": true, "schema": req.JSONSchema}}
	}
	body, err := r.request(ctx, payload)
	if err != nil {
		return nil, Usage{}, err
	}
	if err = rejectDuplicateJSONKeys(body); err != nil {
		return nil, Usage{}, fmt.Errorf("chat provider envelope contains ambiguous JSON: %w", err)
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens        int `json:"prompt_tokens"`
			CompletionTokens    int `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil || len(envelope.Choices) == 0 {
		return nil, Usage{}, errors.New("AI provider response is not an OpenAI-compatible chat response")
	}
	return []byte(envelope.Choices[0].Message.Content), Usage{InputTokens: envelope.Usage.PromptTokens, CachedTokens: envelope.Usage.PromptTokensDetails.CachedTokens, OutputTokens: envelope.Usage.CompletionTokens}, nil
}

type providerLookupFunc func(context.Context, string, string) ([]netip.Addr, error)
type providerDialFunc func(context.Context, string, string) (net.Conn, error)

func newProviderHTTPClient(endpointURL *url.URL, timeout time.Duration, lookup providerLookupFunc, dial providerDialFunc) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Provider egress is an explicit authority boundary. Environment proxies are
	// not implicitly trusted, and the socket is opened only to an address from
	// the exact resolution set that was validated immediately beforehand. This
	// removes the DNS validation/connect TOCTOU window while preserving TLS SNI
	// and hostname verification from the original request URL.
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid AI provider target %q: %w", address, err)
		}
		addresses, err := resolveProviderHost(ctx, host, lookup)
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			if providerAddressBlocked(addr) {
				return nil, fmt.Errorf("AI provider target resolves to an unsafe address: %s", addr)
			}
		}
		var lastErr error
		for _, addr := range addresses {
			if network == "tcp4" && !addr.Is4() {
				continue
			}
			if network == "tcp6" && addr.Is4() {
				continue
			}
			conn, dialErr := dial(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("AI provider target has no address compatible with %s", network)
		}
		return nil, lastErr
	}
	origin := providerOriginKey(endpointURL)
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("AI provider redirect limit exceeded")
			}
			if err := validateProviderEndpoint(req.URL.String()); err != nil {
				return fmt.Errorf("AI provider redirect rejected: %w", err)
			}
			if providerOriginKey(req.URL) != origin {
				return errors.New("AI provider redirect to a different origin is not allowed")
			}
			return nil
		},
	}
}

func resolveProviderHost(ctx context.Context, host string, lookup providerLookupFunc) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	values, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve AI provider target %q: %w", host, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("AI provider target %q resolved to no addresses", host)
	}
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		out = append(out, value.Unmap())
	}
	return out, nil
}

func providerAddressBlocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		v := addr.As4()
		return v[0] == 0
	}
	return false
}

func providerOriginKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + host + ":" + port
}

func validateProviderEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return errors.New("AI provider endpoint must be an absolute HTTP(S) URL with a host")
	}
	if u.User != nil || u.Fragment != "" {
		return errors.New("AI provider endpoint must not contain URL credentials or a fragment")
	}
	if ip, parseErr := netip.ParseAddr(strings.TrimSpace(u.Hostname())); parseErr == nil && providerAddressBlocked(ip) {
		return errors.New("AI provider endpoint must not target an unspecified, multicast or link-local address")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.TrimSpace(u.Hostname())
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.New("AI provider endpoint must use HTTPS; plain HTTP is allowed only for loopback test endpoints")
	default:
		return errors.New("AI provider endpoint must use HTTP or HTTPS")
	}
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func safeSchemaName(promptID string) string {
	value := strings.NewReplacer(".", "_", "-", "_").Replace(promptID)
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
