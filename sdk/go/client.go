// Package factorysdk provides the dependency-light transport foundation for
// clients that consume the canonical 4SO Platform Factory Product API.
//
// It intentionally contains no lifecycle policy, mutation retry loop, RBAC
// bypass, approval shortcut, or provider-specific business logic. Higher-level
// clients such as Terraform and Crossplane must continue to use the Product API
// and its durable-operation contracts.
package factorysdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxResponseBytes = 1 << 20

type Route struct {
	Method              string   `json:"method"`
	Path                string   `json:"path"`
	Family              string   `json:"family"`
	PathParams          []string `json:"pathParams,omitempty"`
	Mutation            bool     `json:"mutation"`
	ResourceScope       string   `json:"resourceScope"`
	ResourceScopeStatus string   `json:"resourceScopeStatus"`
}

type Client struct {
	BaseURL     string
	HTTPClient  *http.Client
	BearerToken string
}

type APIError struct {
	StatusCode int
	Body       []byte
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("4SO Product API returned HTTP %d", e.StatusCode)
}

func AsAPIError(err error, target **APIError) bool { return errors.As(err, target) }

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid Product API base URL")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: baseURL, HTTPClient: httpClient}, nil
}

func expandRoutePath(route Route, values map[string]string) (string, error) {
	path := route.Path
	if !strings.HasPrefix(path, "/api/v1/") {
		return "", fmt.Errorf("route is outside the stable Product API")
	}
	for _, name := range route.PathParams {
		value := strings.TrimSpace(values[name])
		if value == "" {
			return "", fmt.Errorf("path parameter %s is required", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
	}
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return "", fmt.Errorf("route contains unresolved path parameters")
	}
	return path, nil
}

// Do executes exactly one Product API request. It never retries a mutation (or
// any other request) automatically. This is deliberate: retry/idempotency and
// ambiguous external outcomes remain owned by the server-side durable workflow.
func (c *Client) Do(ctx context.Context, route Route, pathParams map[string]string, query url.Values, body any, headers http.Header, out any) (*http.Response, error) {
	if c == nil || c.HTTPClient == nil {
		return nil, fmt.Errorf("Product API client is not initialized")
	}
	method := strings.ToUpper(strings.TrimSpace(route.Method))
	if method == "" {
		return nil, fmt.Errorf("route method is required")
	}
	path, err := expandRoutePath(route, pathParams)
	if err != nil {
		return nil, err
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode Product API request: %w", err)
		}
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token := strings.TrimSpace(c.BearerToken); token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if readErr != nil {
		return resp, readErr
	}
	if len(raw) > maxResponseBytes {
		return resp, fmt.Errorf("Product API response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, &APIError{StatusCode: resp.StatusCode, Body: append([]byte(nil), raw...)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, fmt.Errorf("decode Product API response: %w", err)
		}
	}
	return resp, nil
}
