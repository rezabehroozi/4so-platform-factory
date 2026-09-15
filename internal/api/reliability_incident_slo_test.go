package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/auth"
)

func reliabilityRequest(t *testing.T, handler http.HandlerFunc, principal auth.Principal, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) > 4 && parts[2] == "reliability" && parts[3] == "incidents" {
		req.SetPathValue("id", parts[4])
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}
